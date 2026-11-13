// Shodan InternetDB: gratis, ingen nøkkel. Ett oppslag per IP.
// Går via /internetdb (proxy i nginx/Vite) for å unngå CORS-problemer.

export interface IdbHost {
  ip: string;
  ports: number[];
  cpes: string[];
  hostnames: string[];
  tags: string[];
  vulns: string[];
  /** Domenet brukeren skrev inn, hvis IP-en kom fra et DNS-oppslag. */
  source?: string;
}

export interface IdbProgress {
  done: number;
  total: number;
  found: number;
}

const MAX_IPS = 1024;

function ipToInt(ip: string): number {
  return ip.split('.').reduce((a, o) => (a << 8) + Number(o), 0) >>> 0;
}
function intToIp(n: number): string {
  return [24, 16, 8, 0].map((s) => (n >>> s) & 255).join('.');
}
const IPV4 = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/;
const isIp = (s: string) => IPV4.test(s) && s.split('.').every((o) => Number(o) <= 255);

export function expandCidr(cidr: string): string[] {
  const [ip, bitsStr] = cidr.split('/');
  const bits = Number(bitsStr);
  if (!isIp(ip) || !(bits >= 0 && bits <= 32)) throw new Error(`Ugyldig CIDR: ${cidr}`);
  const size = 2 ** (32 - bits);
  if (size > MAX_IPS) throw new Error(`${cidr} er for stort (maks /22 = ${MAX_IPS} adresser)`);
  const base = ipToInt(ip) & (bits === 0 ? 0 : (~0 << (32 - bits)) >>> 0);
  return Array.from({ length: size }, (_, i) => intToIp((base + i) >>> 0));
}

/** DNS-over-HTTPS (Cloudflare) for å gjøre domener om til IPv4-adresser. */
async function resolve(name: string): Promise<string[]> {
  const res = await fetch(`https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(name)}&type=A`, {
    headers: { accept: 'application/dns-json' },
  });
  if (!res.ok) throw new Error(`DNS-oppslag feilet for ${name}`);
  const body = (await res.json()) as { Answer?: { type: number; data: string }[] };
  return (body.Answer ?? []).filter((a) => a.type === 1).map((a) => a.data);
}

/** Tolker fritekst (IP-er, CIDR, domener, separert med mellomrom/komma/linjeskift). */
export async function parseTargets(input: string): Promise<{ ip: string; source?: string }[]> {
  const tokens = input
    .split(/[\s,;]+/)
    .map((t) => t.trim().replace(/^https?:\/\//, '').replace(/\/$/, ''))
    .filter(Boolean);
  const out = new Map<string, string | undefined>();
  for (const t of tokens) {
    if (t.includes('/') && isIp(t.split('/')[0])) expandCidr(t).forEach((ip) => out.set(ip, undefined));
    else if (isIp(t)) out.set(t, undefined);
    else if (/^[a-z0-9.-]+\.[a-z]{2,}$/i.test(t)) (await resolve(t)).forEach((ip) => out.set(ip, out.get(ip) ?? t));
    else throw new Error(`Forstår ikke «${t}» – bruk IP, CIDR eller domene`);
    if (out.size > MAX_IPS) throw new Error(`For mange adresser (maks ${MAX_IPS})`);
  }
  return [...out.entries()].map(([ip, source]) => ({ ip, source }));
}

async function lookupOne(ip: string, signal: AbortSignal): Promise<IdbHost | null> {
  for (let attempt = 0; attempt < 4; attempt++) {
    const res = await fetch(`internetdb/${ip}`, { signal });
    if (res.status === 404) return null; // ingen data om IP-en
    if (res.status === 429) {
      await new Promise((r) => setTimeout(r, 1000 * 2 ** attempt));
      continue;
    }
    if (!res.ok) throw new Error(`InternetDB svarte ${res.status} for ${ip}`);
    return (await res.json()) as IdbHost;
  }
  throw new Error(`InternetDB rate-limit for ${ip} – prøv igjen litt senere`);
}

export async function lookupMany(
  targets: { ip: string; source?: string }[],
  onProgress: (p: IdbProgress, hosts: IdbHost[]) => void,
  signal: AbortSignal,
  concurrency = 4,
): Promise<IdbHost[]> {
  const hosts: IdbHost[] = [];
  let next = 0;
  let done = 0;
  const worker = async () => {
    while (next < targets.length && !signal.aborted) {
      const t = targets[next++];
      const h = await lookupOne(t.ip, signal);
      if (h) hosts.push({ ...h, source: t.source });
      done++;
      onProgress({ done, total: targets.length, found: hosts.length }, [...hosts]);
    }
  };
  await Promise.all(Array.from({ length: Math.min(concurrency, targets.length) }, worker));
  return hosts;
}

/** Klient-side grupperinger, i samme format som Shodan-fasetter. */
export const IDB_FACETS: { key: string; label: string; get: (h: IdbHost) => string[] }[] = [
  { key: 'port', label: 'Port', get: (h) => h.ports.map(String) },
  { key: 'vuln', label: 'Sårbarhet', get: (h) => h.vulns },
  { key: 'tag', label: 'Tag', get: (h) => h.tags },
  { key: 'cpe', label: 'Programvare (CPE)', get: (h) => h.cpes.map((c) => c.replace(/^cpe:\/[aho]:/, '')) },
  { key: 'domain', label: 'Domene', get: (h) => [...new Set(h.hostnames.map((n) => n.split('.').slice(-2).join('.')))] },
  { key: 'source', label: 'Inndata', get: (h) => [h.source ?? '(IP/CIDR)'] },
];
