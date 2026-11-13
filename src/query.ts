// Modell for søkebyggeren: fritekst + en liste filtre som blir til en Shodan-spørring.

export interface FilterDef {
  key: string;
  label: string;
  placeholder: string;
}

export const FILTERS: FilterDef[] = [
  { key: 'country', label: 'Land (kode)', placeholder: 'NO' },
  { key: 'city', label: 'By', placeholder: 'Oslo' },
  { key: 'port', label: 'Port', placeholder: '22,80,443' },
  { key: 'org', label: 'Organisasjon', placeholder: 'Telenor Norge AS' },
  { key: 'isp', label: 'ISP', placeholder: 'Telia' },
  { key: 'asn', label: 'ASN', placeholder: 'AS2119' },
  { key: 'net', label: 'Nett (CIDR)', placeholder: '193.0.0.0/16' },
  { key: 'ip', label: 'IP', placeholder: '1.2.3.4' },
  { key: 'hostname', label: 'Vertsnavn', placeholder: 'example.no' },
  { key: 'product', label: 'Produkt', placeholder: 'nginx' },
  { key: 'version', label: 'Versjon', placeholder: '1.18.0' },
  { key: 'os', label: 'OS', placeholder: 'Windows' },
  { key: 'vuln', label: 'Sårbarhet (CVE)', placeholder: 'CVE-2024-3400' },
  { key: 'has_vuln', label: 'Har sårbarhet', placeholder: 'true' },
  { key: 'tag', label: 'Tag', placeholder: 'ics, self-signed, cloud' },
  { key: 'http.title', label: 'HTTP-tittel', placeholder: 'Login' },
  { key: 'http.status', label: 'HTTP-status', placeholder: '200' },
  { key: 'http.component', label: 'Web-komponent', placeholder: 'WordPress' },
  { key: 'ssl.cert.subject.cn', label: 'SSL CN', placeholder: '*.example.no' },
  { key: 'ssl.cert.expired', label: 'SSL utløpt', placeholder: 'true' },
  { key: 'screenshot.label', label: 'Skjermbilde-label', placeholder: 'webcam' },
  { key: 'after', label: 'Sett etter', placeholder: '2026-01-01' },
  { key: 'before', label: 'Sett før', placeholder: '2026-06-30' },
];

export interface FacetDef {
  key: string;
  label: string;
}

export const FACETS: FacetDef[] = [
  { key: 'country', label: 'Land' },
  { key: 'city', label: 'By' },
  { key: 'org', label: 'Organisasjon' },
  { key: 'isp', label: 'ISP' },
  { key: 'asn', label: 'ASN' },
  { key: 'port', label: 'Port' },
  { key: 'product', label: 'Produkt' },
  { key: 'version', label: 'Versjon' },
  { key: 'os', label: 'OS' },
  { key: 'vuln', label: 'Sårbarhet' },
  { key: 'tag', label: 'Tag' },
  { key: 'domain', label: 'Domene' },
  { key: 'http.title', label: 'HTTP-tittel' },
  { key: 'http.component', label: 'Web-komponent' },
  { key: 'ssl.version', label: 'SSL-versjon' },
];

/** Fasett-nøkkel -> filter-nøkkel når man klikker en verdi for å filtrere. */
export const FACET_TO_FILTER: Record<string, string> = {
  domain: 'hostname',
  'ssl.version': 'ssl.version',
};

export interface FilterRow {
  id: string;
  key: string;
  value: string;
  negate: boolean;
}

export interface QueryState {
  text: string;
  filters: FilterRow[];
  facets: string[];
  facetSize: number;
}

export const emptyQuery = (): QueryState => ({
  text: '',
  filters: [],
  facets: ['country', 'org', 'port', 'product'],
  facetSize: 10,
});

export const newId = () => Math.random().toString(36).slice(2, 10);

function quote(value: string): string {
  const v = value.trim();
  if (v.startsWith('"') && v.endsWith('"')) return v;
  // Komma-lister (port:22,80) skal ikke quotes; mellomrom eller kolon må quotes.
  return /[\s:]/.test(v) ? `"${v.replace(/"/g, '')}"` : v;
}

export function buildQuery(q: Pick<QueryState, 'text' | 'filters'>): string {
  const parts: string[] = [];
  if (q.text.trim()) parts.push(q.text.trim());
  for (const f of q.filters) {
    if (!f.value.trim()) continue;
    parts.push(`${f.negate ? '-' : ''}${f.key}:${quote(f.value)}`);
  }
  return parts.join(' ');
}

export function buildFacets(q: Pick<QueryState, 'facets' | 'facetSize'>): string {
  return q.facets.map((f) => `${f}:${q.facetSize}`).join(',');
}

/** Om et søk koster query credits (Shodan: filtre eller side > 1). */
export function costsCredits(q: QueryState, page: number): boolean {
  return page > 1 || q.filters.some((f) => f.value.trim()) || /\w+:/.test(q.text);
}

// --- URL-hash for delbare lenker -------------------------------------------

export function toHash(q: QueryState): string {
  const p = new URLSearchParams();
  if (q.text) p.set('q', q.text);
  q.filters
    .filter((f) => f.value.trim())
    .forEach((f) => p.append('f', `${f.negate ? '-' : ''}${f.key}=${f.value}`));
  p.set('facets', q.facets.join(','));
  p.set('n', String(q.facetSize));
  return p.toString();
}

export function fromHash(hash: string): QueryState | null {
  const raw = hash.replace(/^#/, '');
  if (!raw) return null;
  const p = new URLSearchParams(raw);
  const filters: FilterRow[] = p.getAll('f').map((s) => {
    const negate = s.startsWith('-');
    const body = negate ? s.slice(1) : s;
    const i = body.indexOf('=');
    return { id: newId(), key: body.slice(0, i), value: body.slice(i + 1), negate };
  });
  const facetStr = p.get('facets');
  return {
    text: p.get('q') ?? '',
    filters,
    facets: facetStr ? facetStr.split(',').filter(Boolean) : emptyQuery().facets,
    facetSize: Number(p.get('n')) || 10,
  };
}
