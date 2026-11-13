// Tynn klient mot Shodan REST API. Alle kall går via /api, som proxyes til
// https://api.shodan.io. Proxyen (nginx i Docker, eller Vite i dev) legger på
// API-nøkkelen, så den havner aldri i nettleseren.

export interface FacetBucket {
  value: string | number;
  count: number;
}

export interface Match {
  ip_str: string;
  port: number;
  transport?: string;
  org?: string;
  isp?: string;
  asn?: string;
  hostnames?: string[];
  domains?: string[];
  location?: { country_code?: string; country_name?: string; city?: string };
  product?: string;
  version?: string;
  os?: string | null;
  timestamp?: string;
  data?: string;
  vulns?: Record<string, { cvss?: number; summary?: string }>;
  http?: { title?: string | null; status?: number; server?: string };
  ssl?: { cert?: { subject?: { CN?: string }; expires?: string } };
  tags?: string[];
  _shodan?: { module?: string };
}

export interface SearchResult {
  total: number;
  matches: Match[];
  facets?: Record<string, FacetBucket[]>;
}

export interface HostResult {
  ip_str: string;
  ports: number[];
  hostnames?: string[];
  org?: string;
  isp?: string;
  asn?: string;
  os?: string | null;
  country_name?: string;
  city?: string;
  last_update?: string;
  vulns?: string[];
  tags?: string[];
  data: Match[];
}

export interface ApiInfo {
  plan: string;
  query_credits: number;
  scan_credits: number;
  usage_limits?: { query_credits: number; scan_credits: number };
}

export class ShodanError extends Error {
  status: number;
  constructor(message: string, status: number) {
    super(message);
    this.status = status;
  }
}

async function get<T>(path: string, params: Record<string, string | number | undefined> = {}): Promise<T> {
  const qs = new URLSearchParams();
  for (const [k, v] of Object.entries(params)) {
    if (v !== undefined && v !== '') qs.set(k, String(v));
  }
  // Minst én parameter, så proxyen alltid kan bruke "&key=".
  if ([...qs.keys()].length === 0) qs.set('_', '1');
  const res = await fetch(`api${path}?${qs.toString()}`);
  const text = await res.text();
  let body: unknown;
  try {
    body = JSON.parse(text);
  } catch {
    throw new ShodanError(text.slice(0, 300) || res.statusText, res.status);
  }
  if (!res.ok || (body && typeof body === 'object' && 'error' in body)) {
    const msg = (body as { error?: string }).error ?? res.statusText;
    throw new ShodanError(msg, res.status);
  }
  return body as T;
}

export const shodan = {
  /** Gratis: koster ingen query credits. Gir total + fasetter. */
  count: (query: string, facets: string) =>
    get<SearchResult>('/shodan/host/count', { query, facets }),
  /** Koster 1 credit per side hvis søket har filtre eller side > 1. */
  search: (query: string, facets: string, page: number) =>
    get<SearchResult>('/shodan/host/search', { query, facets, page }),
  host: (ip: string) => get<HostResult>(`/shodan/host/${encodeURIComponent(ip)}`),
  apiInfo: () => get<ApiInfo>('/api-info'),
};
