import { useState } from 'react';
import type { FacetBucket, HostResult, Match } from './shodan';
import { shodan } from './shodan';
import { FACETS, FILTERS, newId, type FilterRow, type QueryState } from './query';

// --- Søkebygger ---------------------------------------------------------------

export function QueryBuilder({
  state,
  onChange,
}: {
  state: QueryState;
  onChange: (s: QueryState) => void;
}) {
  const setFilter = (id: string, patch: Partial<FilterRow>) =>
    onChange({ ...state, filters: state.filters.map((f) => (f.id === id ? { ...f, ...patch } : f)) });
  const removeFilter = (id: string) =>
    onChange({ ...state, filters: state.filters.filter((f) => f.id !== id) });
  const addFilter = (key = 'country') =>
    onChange({ ...state, filters: [...state.filters, { id: newId(), key, value: '', negate: false }] });

  return (
    <div className="builder">
      <label className="field">
        <span>Fritekst / rå spørring</span>
        <input
          value={state.text}
          placeholder='f.eks. "Server: Apache" eller webcam'
          onChange={(e) => onChange({ ...state, text: e.target.value })}
        />
      </label>

      <div className="filters">
        {state.filters.map((f) => {
          const def = FILTERS.find((d) => d.key === f.key);
          return (
            <div className="filter-row" key={f.id}>
              <button
                className={`neg ${f.negate ? 'on' : ''}`}
                title={f.negate ? 'Ekskluderer (klikk for å inkludere)' : 'Inkluderer (klikk for å ekskludere)'}
                onClick={() => setFilter(f.id, { negate: !f.negate })}
              >
                {f.negate ? '−' : '+'}
              </button>
              <select value={f.key} onChange={(e) => setFilter(f.id, { key: e.target.value })}>
                {FILTERS.map((d) => (
                  <option key={d.key} value={d.key}>
                    {d.label} ({d.key})
                  </option>
                ))}
                {!def && <option value={f.key}>{f.key}</option>}
              </select>
              <input
                value={f.value}
                placeholder={def?.placeholder}
                onChange={(e) => setFilter(f.id, { value: e.target.value })}
              />
              <button className="ghost" title="Fjern" onClick={() => removeFilter(f.id)}>
                ✕
              </button>
            </div>
          );
        })}
      </div>

      <div className="quick">
        <button onClick={() => addFilter()}>+ Filter</button>
        {['country', 'port', 'org', 'product', 'vuln', 'net'].map((k) => (
          <button key={k} className="chip" onClick={() => addFilter(k)}>
            {k}
          </button>
        ))}
      </div>

      <details className="facet-picker">
        <summary>
          Grupperinger (fasetter): {state.facets.length ? state.facets.join(', ') : 'ingen'}
        </summary>
        <div className="facet-grid">
          {FACETS.map((f) => (
            <label key={f.key} className="check">
              <input
                type="checkbox"
                checked={state.facets.includes(f.key)}
                onChange={(e) =>
                  onChange({
                    ...state,
                    facets: e.target.checked
                      ? [...state.facets, f.key]
                      : state.facets.filter((x) => x !== f.key),
                  })
                }
              />
              {f.label}
            </label>
          ))}
        </div>
        <label className="field inline">
          <span>Antall verdier per gruppe</span>
          <select
            value={state.facetSize}
            onChange={(e) => onChange({ ...state, facetSize: Number(e.target.value) })}
          >
            {[5, 10, 20, 50, 100].map((n) => (
              <option key={n}>{n}</option>
            ))}
          </select>
        </label>
      </details>
    </div>
  );
}

// --- Fasetter -----------------------------------------------------------------

export function FacetPanel({
  facets,
  total,
  onPick,
}: {
  facets: Record<string, FacetBucket[]>;
  total: number;
  onPick: (facet: string, value: string, negate: boolean) => void;
}) {
  const keys = Object.keys(facets);
  if (!keys.length) return null;
  return (
    <div className="facets">
      {keys.map((k) => {
        const buckets = facets[k];
        const max = Math.max(1, ...buckets.map((b) => b.count));
        const label = FACETS.find((f) => f.key === k)?.label ?? k;
        return (
          <section className="facet card" key={k}>
            <header>
              <h3>{label}</h3>
              <button
                className="ghost small"
                title="Kopier som CSV"
                onClick={() =>
                  navigator.clipboard?.writeText(
                    [`${k},count`, ...buckets.map((b) => `"${b.value}",${b.count}`)].join('\n'),
                  )
                }
              >
                CSV
              </button>
            </header>
            {buckets.length === 0 && <p className="muted">Ingen verdier</p>}
            <ul>
              {buckets.map((b) => (
                <li key={String(b.value)}>
                  <div className="bar" style={{ width: `${(b.count / max) * 100}%` }} />
                  <span className="val" title={String(b.value)}>
                    {String(b.value) || '(tom)'}
                  </span>
                  <span className="num">
                    {b.count.toLocaleString('nb-NO')}
                    <small>{total ? ` ${((b.count / total) * 100).toFixed(1)}%` : ''}</small>
                  </span>
                  <span className="acts">
                    <button title="Filtrer på denne" onClick={() => onPick(k, String(b.value), false)}>
                      +
                    </button>
                    <button title="Ekskluder denne" onClick={() => onPick(k, String(b.value), true)}>
                      −
                    </button>
                  </span>
                </li>
              ))}
            </ul>
          </section>
        );
      })}
    </div>
  );
}

// --- Resultater -----------------------------------------------------------------

export const GROUP_BY: { key: string; label: string; get: (m: Match) => string[] }[] = [
  { key: '', label: 'Ingen gruppering', get: () => [] },
  { key: 'ip', label: 'IP (vert)', get: (m) => [m.ip_str] },
  { key: 'org', label: 'Organisasjon', get: (m) => [m.org ?? '(ukjent)'] },
  { key: 'country', label: 'Land', get: (m) => [m.location?.country_name ?? '(ukjent)'] },
  { key: 'port', label: 'Port', get: (m) => [String(m.port)] },
  { key: 'product', label: 'Produkt', get: (m) => [m.product ?? '(ukjent)'] },
  { key: 'asn', label: 'ASN', get: (m) => [m.asn ?? '(ukjent)'] },
  {
    key: 'vuln',
    label: 'Sårbarhet',
    get: (m) => (m.vulns && Object.keys(m.vulns).length ? Object.keys(m.vulns) : ['(ingen)']),
  },
];

function Row({ m, onOpen }: { m: Match; onOpen: (m: Match) => void }) {
  const vulns = m.vulns ? Object.keys(m.vulns) : [];
  return (
    <tr onClick={() => onOpen(m)}>
      <td className="mono">{m.ip_str}</td>
      <td className="mono">
        {m.port}
        <small className="muted">/{m.transport ?? 'tcp'}</small>
      </td>
      <td>{m.org}</td>
      <td>
        {m.location?.country_code} <small className="muted">{m.location?.city}</small>
      </td>
      <td>
        {m.product} <small className="muted">{m.version}</small>
      </td>
      <td className="ellipsis">{m.hostnames?.[0] ?? m.http?.title ?? ''}</td>
      <td>{vulns.length ? <span className="badge danger">{vulns.length}</span> : ''}</td>
      <td className="muted small">{m.timestamp?.slice(0, 10)}</td>
    </tr>
  );
}

export function ResultsTable({
  matches,
  groupBy,
  onOpen,
}: {
  matches: Match[];
  groupBy: string;
  onOpen: (m: Match) => void;
}) {
  const [collapsed, setCollapsed] = useState<Record<string, boolean>>({});
  const head = (
    <thead>
      <tr>
        <th>IP</th>
        <th>Port</th>
        <th>Organisasjon</th>
        <th>Land</th>
        <th>Produkt</th>
        <th>Vert / tittel</th>
        <th>CVE</th>
        <th>Sett</th>
      </tr>
    </thead>
  );

  const g = GROUP_BY.find((x) => x.key === groupBy);
  if (!g || !g.key) {
    return (
      <div className="table-wrap">
        <table>
          {head}
          <tbody>
            {matches.map((m, i) => (
              <Row key={`${m.ip_str}:${m.port}:${i}`} m={m} onOpen={onOpen} />
            ))}
          </tbody>
        </table>
      </div>
    );
  }

  const groups = new Map<string, Match[]>();
  for (const m of matches) for (const k of g.get(m)) groups.set(k, [...(groups.get(k) ?? []), m]);
  const sorted = [...groups.entries()].sort((a, b) => b[1].length - a[1].length);

  return (
    <div className="table-wrap">
      <table>
        {head}
        {sorted.map(([k, ms]) => (
          <tbody key={k}>
            <tr className="group" onClick={() => setCollapsed({ ...collapsed, [k]: !collapsed[k] })}>
              <td colSpan={8}>
                <span className="caret">{collapsed[k] ? '▸' : '▾'}</span> {k}{' '}
                <span className="badge">{ms.length}</span>
              </td>
            </tr>
            {!collapsed[k] &&
              ms.map((m, i) => <Row key={`${m.ip_str}:${m.port}:${i}`} m={m} onOpen={onOpen} />)}
          </tbody>
        ))}
      </table>
    </div>
  );
}

// --- Detaljpanel ----------------------------------------------------------------

export function DetailDrawer({
  match,
  onClose,
  onFilter,
}: {
  match: Match;
  onClose: () => void;
  onFilter: (key: string, value: string) => void;
}) {
  const [host, setHost] = useState<HostResult | null>(null);
  const [loading, setLoading] = useState(false);
  const [err, setErr] = useState('');
  const vulns = match.vulns ? Object.entries(match.vulns) : [];

  const lookup = async () => {
    setLoading(true);
    setErr('');
    try {
      setHost(await shodan.host(match.ip_str));
    } catch (e) {
      setErr((e as Error).message);
    } finally {
      setLoading(false);
    }
  };

  return (
    <aside className="drawer">
      <header>
        <h2 className="mono">
          {match.ip_str}:{match.port}
        </h2>
        <button className="ghost" onClick={onClose}>
          ✕
        </button>
      </header>
      <div className="drawer-body">
        <dl>
          <dt>Organisasjon</dt>
          <dd>
            {match.org}{' '}
            {match.org && (
              <button className="link" onClick={() => onFilter('org', match.org!)}>
                filtrer
              </button>
            )}
          </dd>
          <dt>ISP / ASN</dt>
          <dd>
            {match.isp} {match.asn}
          </dd>
          <dt>Sted</dt>
          <dd>
            {match.location?.city} {match.location?.country_name}
          </dd>
          <dt>Produkt</dt>
          <dd>
            {match.product} {match.version}{' '}
            {match.product && (
              <button className="link" onClick={() => onFilter('product', match.product!)}>
                filtrer
              </button>
            )}
          </dd>
          <dt>OS</dt>
          <dd>{match.os ?? '–'}</dd>
          <dt>Vertsnavn</dt>
          <dd>{match.hostnames?.join(', ') || '–'}</dd>
          {match.http?.title && (
            <>
              <dt>HTTP-tittel</dt>
              <dd>{match.http.title}</dd>
            </>
          )}
          {match.ssl?.cert?.subject?.CN && (
            <>
              <dt>SSL CN</dt>
              <dd>{match.ssl.cert.subject.CN}</dd>
            </>
          )}
          {match.tags?.length ? (
            <>
              <dt>Tags</dt>
              <dd>{match.tags.join(', ')}</dd>
            </>
          ) : null}
          <dt>Sist sett</dt>
          <dd>{match.timestamp}</dd>
        </dl>

        {vulns.length > 0 && (
          <>
            <h3>Sårbarheter ({vulns.length})</h3>
            <ul className="vulns">
              {vulns
                .sort((a, b) => (b[1].cvss ?? 0) - (a[1].cvss ?? 0))
                .map(([cve, v]) => (
                  <li key={cve}>
                    <a href={`https://nvd.nist.gov/vuln/detail/${cve}`} target="_blank" rel="noreferrer">
                      {cve}
                    </a>{' '}
                    {v.cvss !== undefined && (
                      <span className={`badge ${v.cvss >= 7 ? 'danger' : ''}`}>{v.cvss}</span>
                    )}
                    {v.summary && <p className="muted small">{v.summary.slice(0, 220)}</p>}
                  </li>
                ))}
            </ul>
          </>
        )}

        <h3>Banner</h3>
        <pre>{match.data}</pre>

        <div className="row">
          <button onClick={lookup} disabled={loading}>
            {loading ? 'Henter…' : 'Slå opp hele verten'}
          </button>
          <a className="button ghost" href={`https://www.shodan.io/host/${match.ip_str}`} target="_blank" rel="noreferrer">
            Åpne på shodan.io ↗
          </a>
        </div>
        {err && <p className="error">{err}</p>}
        {host && (
          <div className="host">
            <h3>Alle tjenester på verten</h3>
            <p className="muted small">
              Porter: {host.ports.sort((a, b) => a - b).join(', ')} · oppdatert {host.last_update}
            </p>
            {host.vulns?.length ? <p className="small">CVE-er: {host.vulns.join(', ')}</p> : null}
            {host.data.map((d, i) => (
              <details key={i}>
                <summary className="mono">
                  {d.port}/{d.transport} {d.product ?? d._shodan?.module ?? ''} {d.version ?? ''}
                </summary>
                <pre>{d.data}</pre>
              </details>
            ))}
          </div>
        )}
      </div>
    </aside>
  );
}
