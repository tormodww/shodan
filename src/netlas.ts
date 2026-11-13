// Netlas.io: klient + oversetter fra søkebyggerens (Shodan-baserte) filtre til Netlas' spørrespråk.
// Alle kall går via /netlas (proxy i nginx/Vite) som legger på "Authorization: Bearer NETLAS_API_KEY".
// Docs: https://docs.netlas.io/automation/ og https://docs.netlas.io/knowledge-base/field-reference/responses/

import type { FilterRow, QueryState } from './query';
import type { FacetBucket, Match } from './shodan';

// --- Oversetting ------------------------------------------------------------------

type Translator = (value: string) => string | null;

const q = (v: string) => (/[\s:/"()]/.test(v) ? `"${v.replace(/"/g, '')}"` : v);
const orList = (field: string) => (v: string) => {
  const parts = v.split(',').map((s) => s.trim()).filter(Boolean);
  return parts.length > 1 ? `${field}:(${parts.map(q).join(' OR ')})` : `${field}:${q(parts[0] ?? v)}`;
};

const ICS = 'protocol:(modbus OR s7 OR bacnet OR dnp3 OR fox OR ethernetip OR iec104 OR opcua)';
const CAMERAS = '(protocol:rtsp OR tag.name:(hikvision OR dahua OR axis OR reolink OR foscam OR uniview))';
const CAMERAS_BASIC =
  '(protocol:rtsp OR http.title:(camera OR webcam OR "network camera" OR "ip camera" OR hikvision OR dahua OR dvr OR nvr))';

// --- Planer -------------------------------------------------------------------------
// Fra netlas.io/pricing og docs.netlas.io/faq: CVE- og tag-søk krever Business,
// SSL-sertifikater krever Freelancer. Community: 50 forespørsler/dag.

export type NetlasPlan = 'community' | 'freelancer' | 'business';
export const PLANS: { key: NetlasPlan; label: string; daily: number }[] = [
  { key: 'community', label: 'Community (gratis)', daily: 50 },
  { key: 'freelancer', label: 'Freelancer', daily: 1000 },
  { key: 'business', label: 'Business+', daily: 10000 },
];
const RANK: Record<NetlasPlan, number> = { community: 0, freelancer: 1, business: 2 };

/** Returnerer navnet på planen som trengs hvis uttrykket bruker felt planen ikke har. */
function requiredPlan(expr: string, plan: NetlasPlan): string | null {
  if (RANK[plan] < 2 && /(^|[\s(!])(tag|cve)\./.test(expr)) return 'Business';
  if (RANK[plan] < 1 && /(^|[\s(!])certificate\./.test(expr)) return 'Freelancer';
  return null;
}

/** Erstatninger med felt som finnes i lavere planer. */
const BASIC_FALLBACK: Record<string, Translator> = {
  product: (v) => `http.headers.server:${q(v.replace(/ httpd$/i, ''))}`,
  'screenshot.label': (v) => (/webcam|camera/i.test(v) ? CAMERAS_BASIC : null),
};

/** Shodan-filter -> Netlas-uttrykk. null = ikke støttet i Netlas. */
const FILTER_MAP: Record<string, Translator> = {
  country: orList('geo.country'),
  city: orList('geo.city'),
  port: orList('port'),
  org: (v) => `whois.asn.name:${q(v)}`,
  isp: (v) => `isp:${q(v)}`,
  asn: (v) => `whois.asn.number:${v.replace(/^AS/i, '')}`,
  net: (v) => `ip:"${v}"`,
  ip: (v) => `ip:${q(v)}`,
  hostname: (v) => `host:${q(v.includes('*') ? v : `*${v}`)}`,
  product: (v) => `tag.name:${q(v.toLowerCase().replace(/ httpd$/, '').replace(/\s+/g, '_'))}`,
  version: () => null, // håndteres sammen med product, se translate()
  os: (v) => `tag.name:${q(v.toLowerCase())}`,
  vuln: orList('cve.name'),
  has_vuln: (v) => (v === 'false' ? '!cve.name:*' : 'cve.name:*'),
  tag: (v) => {
    const t = v.toLowerCase();
    if (t === 'ics') return ICS;
    if (t === 'self-signed') return 'certificate.self_signed:true';
    return `tag.name:${q(t)}`;
  },
  'http.title': (v) => `http.title:${q(v)}`,
  'http.status': (v) => `http.status_code:${v}`,
  'http.component': (v) => `tag.name:${q(v.toLowerCase())}`,
  'ssl.cert.subject.cn': (v) => `certificate.subject.common_name:${q(v)}`,
  'ssl.cert.expired': (v) => (v === 'false' ? 'certificate.validity.end:>now' : 'certificate.validity.end:<now'),
  'screenshot.label': (v) => (/webcam|camera/i.test(v) ? CAMERAS : null),
  after: (v) => `scan_date:>=${v}`,
  before: (v) => `scan_date:<=${v}`,
};

/** Shodan-fasett -> Netlas-felt. */
export const FACET_MAP: Record<string, string> = {
  country: 'geo.country',
  city: 'geo.city',
  org: 'whois.asn.name',
  isp: 'isp',
  asn: 'whois.asn.number',
  port: 'port',
  product: 'tag.name',
  vuln: 'cve.name',
  tag: 'tag.category',
  'http.component': 'tag.name',
  domain: 'host',
};

/** Netlas-felt -> filter-nøkkel i søkebyggeren (for drill-down fra fasetter). */
export const NETLAS_FIELD_TO_FILTER: Record<string, string> = {
  'geo.country': 'country',
  'geo.city': 'city',
  'whois.asn.name': 'org',
  isp: 'isp',
  'whois.asn.number': 'asn',
  port: 'port',
  'tag.name': 'product',
  'cve.name': 'vuln',
  'tag.category': 'tag',
  host: 'hostname',
};

export interface Translated {
  query: string;
  warnings: string[];
}

export function translate(state: Pick<QueryState, 'text' | 'filters'>, plan: NetlasPlan = 'business'): Translated {
  const parts: string[] = [];
  const warnings: string[] = [];
  const active = state.filters.filter((f) => f.value.trim());
  const product = active.find((f) => f.key === 'product' && !f.negate);

  if (state.text.trim()) parts.push(`(${state.text.trim()})`);
  for (const f of active as FilterRow[]) {
    let expr: string | null;
    if (f.key === 'version') {
      expr = product
        ? `tag.${product.value.toLowerCase().replace(/ httpd$/, '').replace(/\s+/g, '_')}.version:${q(f.value)}`
        : null;
      if (!expr) warnings.push('version krever et produkt-filter i Netlas');
    } else {
      expr = FILTER_MAP[f.key]?.(f.value.trim()) ?? null;
      if (!expr) warnings.push(`${f.key}:${f.value} støttes ikke i Netlas og ble hoppet over`);
    }
    const needs = expr ? requiredPlan(expr, plan) : null;
    if (expr && needs) {
      const fb = BASIC_FALLBACK[f.key]?.(f.value.trim()) ?? null;
      if (fb && !requiredPlan(fb, plan)) {
        expr = fb;
        warnings.push(`${f.key}:${f.value} krever ${needs} – bruker forenklet variant`);
      } else {
        expr = null;
        warnings.push(`${f.key}:${f.value} krever Netlas ${needs} og ble hoppet over`);
      }
    }
    if (expr) parts.push(f.negate ? `!${expr.startsWith('(') || !expr.includes(' ') ? expr : `(${expr})`}` : expr);
  }
  return { query: parts.join(' AND '), warnings };
}

export function netlasFacets(facets: string[], plan: NetlasPlan = 'business'): { fields: string[]; skipped: string[] } {
  const fields: string[] = [];
  const skipped: string[] = [];
  for (const f of facets) {
    let n: string | undefined = FACET_MAP[f];
    if (n && requiredPlan(`${n}:x`, plan)) n = f === 'product' ? 'protocol' : undefined;
    if (n && !fields.includes(n)) fields.push(n);
    else if (!n) skipped.push(f);
  }
  return { fields, skipped };
}

// --- Klient -----------------------------------------------------------------------

export class NetlasError extends Error {
  status: number;
  constructor(message: string, status: number) {
    super(message);
    this.status = status;
  }
}

const USAGE_KEY = 'shodan-sok.netlas-usage';
export function usageToday(): number {
  try {
    const u = JSON.parse(localStorage.getItem(USAGE_KEY) ?? '{}') as { date?: string; n?: number };
    return u.date === new Date().toISOString().slice(0, 10) ? (u.n ?? 0) : 0;
  } catch {
    return 0;
  }
}
function countRequest() {
  try {
    localStorage.setItem(USAGE_KEY, JSON.stringify({ date: new Date().toISOString().slice(0, 10), n: usageToday() + 1 }));
  } catch {
    /* ignorer */
  }
}

async function get<T>(path: string, params: Record<string, string | number | undefined>): Promise<T> {
  const qs = new URLSearchParams();
  for (const [k, v] of Object.entries(params)) if (v !== undefined && v !== '') qs.set(k, String(v));
  countRequest();
  const res = await fetch(`netlas/api/${path}/?${qs}`);
  const text = await res.text();
  let body: unknown;
  try {
    body = JSON.parse(text);
  } catch {
    throw new NetlasError(text.slice(0, 300) || res.statusText, res.status);
  }
  if (!res.ok) {
    const b = body as { detail?: string; error?: string; message?: string };
    let msg = b.detail ?? b.error ?? b.message ?? res.statusText;
    if (res.status === 429) msg = `Netlas: rate-limit/dagskvote nådd (${msg})`;
    if (/not available for this plan/i.test(msg)) msg = `Netlas: et av feltene i søket krever høyere plan (${msg}). Sjekk planvalget.`;
    else if (res.status === 401 || res.status === 403) msg = `Netlas avviste forespørselen (${msg}) – sjekk NETLAS_API_KEY`;
    if (res.status === 402) msg = `Netlas: krever høyere plan (${msg})`;
    throw new NetlasError(msg, res.status);
  }
  return body as T;
}

interface NetlasItem {
  data: Record<string, unknown> & {
    ip?: string;
    port?: number;
    protocol?: string;
    prot4?: string;
    host?: string;
    uri?: string;
    isp?: string;
    scan_date?: string;
    '@timestamp'?: string;
    geo?: { country?: string; city?: string };
    whois?: { asn?: { name?: string; number?: (string | number)[] | string | number }; net?: { organization?: string; name?: string } };
    http?: { title?: string; status_code?: number; headers?: { server?: string[] | string } };
    tag?: { name?: string; fullname?: string; version?: string }[];
    cve?: { name: string; base_score?: number; description?: string }[];
  };
}

function toMatch(item: NetlasItem): Match {
  const d = item.data;
  const asnNum = d.whois?.asn?.number;
  const asn = Array.isArray(asnNum) ? asnNum[0] : asnNum;
  const isIpHost = d.host && /^[\d.:]+$/.test(d.host);
  const tags = d.tag ?? [];
  const firstTag = tags.find((t) => t.version) ?? tags[0];
  return {
    ip_str: d.ip ?? '',
    port: d.port ?? 0,
    transport: d.protocol ?? d.prot4,
    org: d.whois?.asn?.name ?? d.whois?.net?.organization,
    isp: d.isp,
    asn: asn !== undefined ? `AS${asn}` : undefined,
    hostnames: d.host && !isIpHost ? [d.host] : [],
    location: { country_code: d.geo?.country, country_name: d.geo?.country, city: d.geo?.city },
    product: firstTag?.fullname ?? firstTag?.name,
    version: firstTag?.version,
    timestamp: d.scan_date ?? d['@timestamp'],
    data: JSON.stringify(d, null, 2).slice(0, 8000),
    vulns: d.cve?.length
      ? Object.fromEntries(d.cve.map((c) => [c.name, { cvss: c.base_score, summary: c.description }]))
      : undefined,
    http: d.http ? { title: d.http.title, status: d.http.status_code } : undefined,
    tags: tags.map((t) => t.name ?? '').filter(Boolean),
  };
}

export const PAGE_SIZE = 20;

export const netlas = {
  count: async (query: string) => (await get<{ count: number }>('responses_count', { q: query })).count,
  facet: async (query: string, field: string, size: number): Promise<FacetBucket[]> => {
    const r = await get<{ aggregations?: { key: (string | number)[] | string; doc_count: number }[] }>(
      'responses_facet',
      { q: query, facets: field, size },
    );
    return (r.aggregations ?? []).map((a) => ({
      value: Array.isArray(a.key) ? a.key.join(' / ') : String(a.key),
      count: a.doc_count,
    }));
  },
  search: async (query: string, start: number): Promise<Match[]> => {
    const r = await get<{ items?: NetlasItem[] }>('responses', { q: query, start });
    return (r.items ?? []).map(toMatch);
  },
};
