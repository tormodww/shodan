import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { DetailDrawer, FacetPanel, GROUP_BY, QueryBuilder, ResultsTable } from './components';
import {
  FACET_TO_FILTER,
  buildFacets,
  buildQuery,
  costsCredits,
  emptyQuery,
  fromHash,
  newId,
  toHash,
  type QueryState,
} from './query';
import InternetDbView from './InternetDbView';
import { SHODAN_PRESETS } from './presets';
import { shodan, type ApiInfo, type Match, type SearchResult } from './shodan';
import {
  downloadFile,
  loadHistory,
  loadSaved,
  storeHistory,
  storeSaved,
  type HistoryEntry,
  type SavedSearch,
} from './storage';

type Mode = 'count' | 'search';
type View = 'idb' | 'shodan';
const VIEW_KEY = 'shodan-sok.view';

function friendlyError(e: Error & { status?: number }): string {
  if (e.status === 401 || e.status === 403 || /membership|upgrade|access denied|requires/i.test(e.message)) {
    return `${e.message} – søket krever sannsynligvis betalt Shodan-nivå. Bruk «Tell og grupper» uten filtre, eller InternetDB-fanen.`;
  }
  return e.message;
}

const PRESET_GROUPS = [...new Set(SHODAN_PRESETS.map((p) => p.group))];

export default function App() {
  const [state, setState] = useState<QueryState>(() => fromHash(location.hash) ?? emptyQuery());
  const [result, setResult] = useState<SearchResult | null>(null);
  const [mode, setMode] = useState<Mode>('count');
  const [page, setPage] = useState(1);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [info, setInfo] = useState<ApiInfo | null>(null);
  const [saved, setSaved] = useState<SavedSearch[]>(loadSaved);
  const [history, setHistory] = useState<HistoryEntry[]>(loadHistory);
  const [groupBy, setGroupBy] = useState('');
  const [view, setView] = useState<View>(() => {
    try {
      return (localStorage.getItem(VIEW_KEY) as View) || (location.hash.length > 1 ? 'shodan' : 'idb');
    } catch {
      return 'idb';
    }
  });
  const switchView = (v: View) => {
    setView(v);
    try {
      localStorage.setItem(VIEW_KEY, v);
    } catch {
      /* ignorer */
    }
  };
  const [open, setOpen] = useState<Match | null>(null);
  const importRef = useRef<HTMLInputElement>(null);

  const query = useMemo(() => buildQuery(state), [state]);
  const willCost = costsCredits(state, page);

  useEffect(() => {
    window.history.replaceState(null, '', `#${toHash(state)}`);
  }, [state]);

  const refreshInfo = useCallback(() => {
    shodan.apiInfo().then(setInfo).catch(() => setInfo(null));
  }, []);
  useEffect(refreshInfo, [refreshInfo]);

  const run = async (m: Mode, p = 1, s: QueryState = state) => {
    const q = buildQuery(s);
    if (!q) {
      setError('Skriv inn fritekst eller legg til minst ett filter.');
      return;
    }
    setLoading(true);
    setError('');
    setMode(m);
    setPage(p);
    try {
      const r = m === 'count' ? await shodan.count(q, buildFacets(s)) : await shodan.search(q, buildFacets(s), p);
      setResult(r);
      const h = [{ query: q, state: s, total: r.total, at: new Date().toISOString() }, ...history.filter((x) => x.query !== q)];
      setHistory(h);
      storeHistory(h);
      if (m === 'search') refreshInfo();
    } catch (e) {
      setError(friendlyError(e as Error & { status?: number }));
    } finally {
      setLoading(false);
    }
  };

  const addFilter = (key: string, value: string, negate: boolean) => {
    const fk = FACET_TO_FILTER[key] ?? key;
    // Drill-down: et positivt valg erstatter eksisterende positivt filter på samme felt.
    const kept = negate ? state.filters : state.filters.filter((f) => f.key !== fk || f.negate);
    const next = { ...state, filters: [...kept, { id: newId(), key: fk, value, negate }] };
    setState(next);
    setOpen(null);
    run(mode === 'search' ? 'search' : 'count', 1, next);
  };

  const save = () => {
    const name = prompt('Navn på lagret søk', query.slice(0, 60));
    if (!name) return;
    const s = [{ id: newId(), name, state, createdAt: new Date().toISOString() }, ...saved];
    setSaved(s);
    storeSaved(s);
  };
  const removeSaved = (id: string) => {
    const s = saved.filter((x) => x.id !== id);
    setSaved(s);
    storeSaved(s);
  };
  const importSaved = async (file: File) => {
    try {
      const data = JSON.parse(await file.text()) as SavedSearch[];
      const known = new Set(saved.map((s) => s.id));
      const s = [...saved, ...data.filter((d) => d.state && !known.has(d.id))];
      setSaved(s);
      storeSaved(s);
    } catch {
      setError('Kunne ikke lese fila – forventer JSON eksportert herfra.');
    }
  };

  const exportCsv = () => {
    if (!result?.matches.length) return;
    const esc = (v: unknown) => `"${String(v ?? '').replace(/"/g, '""')}"`;
    const rows = result.matches.map((m) =>
      [m.ip_str, m.port, m.transport, m.org, m.isp, m.asn, m.location?.country_code, m.location?.city,
        m.product, m.version, m.os, (m.hostnames ?? []).join(' '), m.http?.title,
        Object.keys(m.vulns ?? {}).join(' '), m.timestamp].map(esc).join(','),
    );
    const header = 'ip,port,transport,org,isp,asn,country,city,product,version,os,hostnames,http_title,vulns,timestamp';
    downloadFile(`shodan-${new Date().toISOString().slice(0, 10)}.csv`, [header, ...rows].join('\n'), 'text/csv');
  };

  const totalPages = result ? Math.ceil(result.total / 100) : 0;

  return (
    <div className="app">
      <header className="top">
        <h1>
          Shodan<span>søk</span>
        </h1>
        <nav className="tabs">
          <button className={view === 'idb' ? 'active' : ''} onClick={() => switchView('idb')}>
            InternetDB <small>gratis</small>
          </button>
          <button className={view === 'shodan' ? 'active' : ''} onClick={() => switchView('shodan')}>
            Shodan-søk <small>API-nøkkel</small>
          </button>
        </nav>
        <div className="credits">
          {info ? (
            <>
              <span title="Query credits igjen">🔎 {info.query_credits}</span>
              <span title="Scan credits igjen">📡 {info.scan_credits}</span>
              <span className="muted">{info.plan}</span>
            </>
          ) : (
            <span className="muted">API-info utilgjengelig – sjekk SHODAN_API_KEY</span>
          )}
        </div>
      </header>

      {view === 'idb' ? (
        <div className="layout single">
          <InternetDbView />
        </div>
      ) : (
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
                  {SHODAN_PRESETS.filter((p) => p.group === g).map((p) => (
                    <li key={p.name}>
                      <button
                        className="link"
                        title={`${p.description}\n${buildQuery(p.state)}`}
                        onClick={() => { setState(p.state); run('count', 1, p.state); }}
                      >
                        {p.name}
                      </button>
                    </li>
                  ))}
                </ul>
              </details>
            ))}
          </section>

          <section className="card">
            <header>
              <h2>Lagrede søk</h2>
              <button className="small" onClick={save} disabled={!query}>
                Lagre nåværende
              </button>
            </header>
            {saved.length === 0 && <p className="muted small">Ingen lagrede søk ennå.</p>}
            <ul className="list">
              {saved.map((s) => (
                <li key={s.id}>
                  <button className="link" title={buildQuery(s.state)} onClick={() => { setState(s.state); run('count', 1, s.state); }}>
                    {s.name}
                  </button>
                  <button className="ghost small" title="Slett" onClick={() => removeSaved(s.id)}>
                    ✕
                  </button>
                </li>
              ))}
            </ul>
            <div className="row small">
              <button className="ghost small" onClick={() => downloadFile('shodan-lagrede-sok.json', JSON.stringify(saved, null, 2), 'application/json')}>
                Eksporter
              </button>
              <button className="ghost small" onClick={() => importRef.current?.click()}>
                Importer
              </button>
              <input ref={importRef} type="file" accept=".json" hidden onChange={(e) => e.target.files?.[0] && importSaved(e.target.files[0])} />
            </div>
          </section>

          <section className="card">
            <header>
              <h2>Historikk</h2>
              {history.length > 0 && (
                <button className="ghost small" onClick={() => { setHistory([]); storeHistory([]); }}>
                  Tøm
                </button>
              )}
            </header>
            <ul className="list">
              {history.map((h) => (
                <li key={h.at}>
                  <button className="link mono small" title={h.at} onClick={() => setState(h.state)}>
                    {h.query}
                  </button>
                  <span className="muted small">{h.total.toLocaleString('nb-NO')}</span>
                </li>
              ))}
            </ul>
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
            </div>
            <div className="row">
              <button className="primary" disabled={loading} onClick={() => run('count')}>
                Tell og grupper <small>(gratis)</small>
              </button>
              <button disabled={loading} onClick={() => run('search')}>
                Hent treff {willCost && <small>(1 credit)</small>}
              </button>
              <button className="ghost" onClick={() => { setState(emptyQuery()); setResult(null); }}>
                Nullstill
              </button>
              {loading && <span className="spinner" />}
            </div>
            {error && <p className="error">{error}</p>}
          </section>

          {result && (
            <>
              <div className="summary">
                <strong>{result.total.toLocaleString('nb-NO')}</strong> treff
                {mode === 'search' && result.matches.length > 0 && (
                  <span className="muted"> · viser {result.matches.length} på side {page} av {totalPages}</span>
                )}
              </div>

              {result.facets && (
                <FacetPanel facets={result.facets} total={result.total} onPick={addFilter} />
              )}

              {mode === 'search' && result.matches.length > 0 && (
                <section className="card">
                  <header>
                    <h2>Treff</h2>
                    <div className="row">
                      <label className="field inline">
                        <span>Grupper etter</span>
                        <select value={groupBy} onChange={(e) => setGroupBy(e.target.value)}>
                          {GROUP_BY.map((g) => (
                            <option key={g.key} value={g.key}>
                              {g.label}
                            </option>
                          ))}
                        </select>
                      </label>
                      <button className="ghost small" onClick={exportCsv}>
                        Eksporter CSV
                      </button>
                    </div>
                  </header>
                  <ResultsTable matches={result.matches} groupBy={groupBy} onOpen={setOpen} />
                  {totalPages > 1 && (
                    <div className="pager">
                      <button disabled={page <= 1 || loading} onClick={() => run('search', page - 1)}>
                        ← Forrige
                      </button>
                      <span>
                        Side {page} / {totalPages}
                      </span>
                      <button disabled={page >= totalPages || loading} onClick={() => run('search', page + 1)}>
                        Neste → <small>(1 credit)</small>
                      </button>
                    </div>
                  )}
                </section>
              )}
            </>
          )}
        </main>
      </div>
      )}

      {open && <DetailDrawer match={open} onClose={() => setOpen(null)} onFilter={(k, v) => addFilter(k, v, false)} />}
    </div>
  );
}
