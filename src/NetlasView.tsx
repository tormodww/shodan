import { useMemo, useState } from 'react';
import { DetailDrawer, FacetPanel, GROUP_BY, QueryBuilder, ResultsTable } from './components';
import { NETLAS_FIELD_TO_FILTER, PAGE_SIZE, netlas, netlasFacets, translate, usageToday } from './netlas';
import { SHODAN_PRESETS } from './presets';
import { FACETS, emptyQuery, newId, type QueryState } from './query';
import type { FacetBucket, Match } from './shodan';
import { downloadFile } from './storage';

const STATE_KEY = 'shodan-sok.netlas-state';
const DAILY_LIMIT = 50; // Community-planen
const PRESET_GROUPS = [...new Set(SHODAN_PRESETS.map((p) => p.group))];
const LABELS = Object.fromEntries(
  Object.entries(NETLAS_FIELD_TO_FILTER).map(([field, key]) => [
    field,
    FACETS.find((f) => f.key === key)?.label ?? field,
  ]),
);
LABELS['tag.name'] = 'Produkt / teknologi';

function loadState(): QueryState {
  try {
    const s = localStorage.getItem(STATE_KEY);
    return s ? (JSON.parse(s) as QueryState) : { ...emptyQuery(), facets: ['country', 'org', 'port'] };
  } catch {
    return emptyQuery();
  }
}

export default function NetlasView() {
  const [state, setStateRaw] = useState<QueryState>(loadState);
  const [total, setTotal] = useState<number | null>(null);
  const [facets, setFacets] = useState<Record<string, FacetBucket[]>>({});
  const [matches, setMatches] = useState<Match[]>([]);
  const [page, setPage] = useState(0);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [groupBy, setGroupBy] = useState('');
  const [open, setOpen] = useState<Match | null>(null);
  const [used, setUsed] = useState(usageToday);

  const setState = (s: QueryState) => {
    setStateRaw(s);
    try {
      localStorage.setItem(STATE_KEY, JSON.stringify(s));
    } catch {
      /* ignorer */
    }
  };

  const { query, warnings } = useMemo(() => translate(state), [state]);
  const { fields, skipped } = useMemo(() => netlasFacets(state.facets), [state.facets]);

  const guard = async (fn: () => Promise<void>) => {
    setLoading(true);
    setError('');
    try {
      await fn();
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setLoading(false);
      setUsed(usageToday());
    }
  };

  const group = (s: QueryState = state) =>
    guard(async () => {
      const t = translate(s);
      if (!t.query) throw new Error('Skriv inn fritekst eller legg til minst ett filter.');
      const f = netlasFacets(s.facets).fields;
      const [count, ...buckets] = await Promise.all([
        netlas.count(t.query),
        ...f.map((field) => netlas.facet(t.query, field, s.facetSize)),
      ]);
      setTotal(count as number);
      setFacets(Object.fromEntries(f.map((field, i) => [field, buckets[i] as FacetBucket[]])));
      setMatches([]);
    });

  const search = (p = 0) =>
    guard(async () => {
      if (!query) throw new Error('Skriv inn fritekst eller legg til minst ett filter.');
      setMatches(await netlas.search(query, p * PAGE_SIZE));
      setPage(p);
    });

  const pick = (field: string, value: string, negate: boolean) => {
    const key = NETLAS_FIELD_TO_FILTER[field] ?? field;
    const v = value.split(' / ')[0];
    const kept = negate ? state.filters : state.filters.filter((f) => f.key !== key || f.negate);
    const next = { ...state, filters: [...kept, { id: newId(), key, value: v, negate }] };
    setState(next);
    setOpen(null);
    group(next);
  };

  const exportCsv = () => {
    const esc = (v: unknown) => `"${String(v ?? '').replace(/"/g, '""')}"`;
    const rows = matches.map((m) =>
      [m.ip_str, m.port, m.transport, m.org, m.isp, m.asn, m.location?.country_code, m.location?.city, m.product,
        m.version, (m.hostnames ?? []).join(' '), m.http?.title, Object.keys(m.vulns ?? {}).join(' '), m.timestamp]
        .map(esc).join(','),
    );
    downloadFile('netlas.csv', ['ip,port,protocol,org,isp,asn,country,city,product,version,host,http_title,vulns,scan_date', ...rows].join('\n'), 'text/csv');
  };

  const groupCost = 1 + fields.length;

  return (
    <div className="layout">
      <aside className="side">
        <section className="card">
          <header>
            <h2>Forslag</h2>
          </header>
          {PRESET_GROUPS.map((g, i) => (
            <details key={g} className="preset-group" open={i === 0}>
              <summary>{g}</summary>
              <ul className="list">
                {SHODAN_PRESETS.filter((p) => p.group === g && p.netlas !== false).map((p) => (
                  <li key={p.name}>
                    <button
                      className="link"
                      title={`${p.description}\n${translate(p.state).query}`}
                      onClick={() => {
                        setState(p.state);
                        setTotal(null);
                        setFacets({});
                        setMatches([]);
                      }}
                    >
                      {p.name}
                    </button>
                  </li>
                ))}
              </ul>
            </details>
          ))}
          <p className="muted small">Forslag lastes inn uten å kjøre, så du sparer forespørsler.</p>
        </section>
        <section className="card">
          <header>
            <h2>Forbruk i dag</h2>
          </header>
          <div className="meter">
            <div style={{ width: `${Math.min(100, (used / DAILY_LIMIT) * 100)}%` }} />
          </div>
          <p className="muted small">
            {used} av ~{DAILY_LIMIT} forespørsler (telt i denne nettleseren, Community-planen)
          </p>
        </section>
      </aside>

      <main>
        <section className="card">
          <QueryBuilder state={state} onChange={setState} />
          <div className="query-preview">
            <code>{query || <span className="muted">(tom spørring)</span>}</code>
            <button className="ghost small" onClick={() => navigator.clipboard?.writeText(query)} disabled={!query}>
              Kopier
            </button>
            <a className="button ghost small" href={`https://app.netlas.io/responses/?q=${encodeURIComponent(query)}`} target="_blank" rel="noreferrer">
              netlas.io ↗
            </a>
          </div>
          {(warnings.length > 0 || skipped.length > 0) && (
            <ul className="warnings">
              {warnings.map((w) => <li key={w}>{w}</li>)}
              {skipped.length > 0 && <li>Grupperinger som ikke finnes i Netlas: {skipped.join(', ')}</li>}
            </ul>
          )}
          <div className="row">
            <button className="primary" disabled={loading} onClick={() => group()}>
              Tell og grupper <small>({groupCost} forespørsler)</small>
            </button>
            <button disabled={loading} onClick={() => search(0)}>
              Hent treff <small>(1 forespørsel, {PAGE_SIZE} treff)</small>
            </button>
            <button className="ghost" onClick={() => { setState(emptyQuery()); setTotal(null); setFacets({}); setMatches([]); }}>
              Nullstill
            </button>
            {loading && <span className="spinner" />}
          </div>
          {error && <p className="error">{error}</p>}
        </section>

        {total !== null && (
          <>
            <div className="summary">
              <strong>{total.toLocaleString('nb-NO')}</strong> treff i Netlas
              {total >= 1000 && <span className="muted"> (estimat ±3 %)</span>}
            </div>
            <FacetPanel facets={facets} total={total} labels={LABELS} onPick={pick} />
          </>
        )}

        {matches.length > 0 && (
          <section className="card">
            <header>
              <h2>Treff</h2>
              <div className="row">
                <label className="field inline">
                  <span>Grupper etter</span>
                  <select value={groupBy} onChange={(e) => setGroupBy(e.target.value)}>
                    {GROUP_BY.map((g) => (
                      <option key={g.key} value={g.key}>{g.label}</option>
                    ))}
                  </select>
                </label>
                <button className="ghost small" onClick={exportCsv}>Eksporter CSV</button>
              </div>
            </header>
            <ResultsTable matches={matches} groupBy={groupBy} onOpen={setOpen} />
            <div className="pager">
              <button disabled={page === 0 || loading} onClick={() => search(page - 1)}>← Forrige</button>
              <span>Side {page + 1}</span>
              <button disabled={matches.length < PAGE_SIZE || loading} onClick={() => search(page + 1)}>
                Neste → <small>(1 forespørsel)</small>
              </button>
            </div>
          </section>
        )}
        {total !== null && matches.length === 0 && !loading && (
          <p className="muted small">Trykk «Hent treff» for å se de enkelte tjenestene.</p>
        )}
      </main>

      {open && <DetailDrawer match={open} onClose={() => setOpen(null)} onFilter={(k, v) => {
        const next = { ...state, filters: [...state.filters.filter((f) => f.key !== k || f.negate), { id: newId(), key: k, value: v, negate: false }] };
        setState(next);
        setOpen(null);
      }} />}
    </div>
  );
}
