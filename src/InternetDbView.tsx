import { Fragment, useMemo, useRef, useState } from 'react';
import { FacetPanel } from './components';
import { IDB_FACETS, cameraSignals, lookupMany, parseTargets, type IdbHost, type IdbProgress } from './internetdb';
import { IDB_PRESETS } from './presets';
import type { FacetBucket } from './shodan';
import { downloadFile } from './storage';

interface ClientFilter {
  key: string;
  value: string;
  negate: boolean;
}

const LABELS = Object.fromEntries(IDB_FACETS.map((f) => [f.key, f.label]));
const INPUT_KEY = 'shodan-sok.idb-input';

export default function InternetDbView() {
  const [input, setInput] = useState(() => {
    try {
      return localStorage.getItem(INPUT_KEY) ?? '';
    } catch {
      return '';
    }
  });
  const [hosts, setHosts] = useState<IdbHost[]>([]);
  const [progress, setProgress] = useState<IdbProgress | null>(null);
  const [running, setRunning] = useState(false);
  const [error, setError] = useState('');
  const [filters, setFilters] = useState<ClientFilter[]>([]);
  const [expanded, setExpanded] = useState<string | null>(null);
  const [camOnly, setCamOnly] = useState(false);
  const abort = useRef<AbortController | null>(null);

  const run = async (text = input) => {
    setError('');
    setFilters([]);
    setHosts([]);
    try {
      localStorage.setItem(INPUT_KEY, text);
    } catch {
      /* ignorer */
    }
    let targets;
    try {
      targets = await parseTargets(text);
    } catch (e) {
      setError((e as Error).message);
      return;
    }
    if (!targets.length) {
      setError('Skriv inn minst én IP, CIDR eller domene.');
      return;
    }
    abort.current = new AbortController();
    setRunning(true);
    setProgress({ done: 0, total: targets.length, found: 0 });
    try {
      await lookupMany(targets, (p, h) => { setProgress(p); setHosts(h); }, abort.current.signal);
    } catch (e) {
      if ((e as Error).name !== 'AbortError') setError((e as Error).message);
    } finally {
      setRunning(false);
    }
  };

  const myIp = async () => {
    try {
      const { ip } = (await (await fetch('https://api.ipify.org?format=json')).json()) as { ip: string };
      const text = input.trim() ? `${input.trim()}\n${ip}` : ip;
      setInput(text);
    } catch {
      setError('Klarte ikke å finne din offentlige IP.');
    }
  };

  const visible = useMemo(
    () =>
      hosts
        .filter((h) => !camOnly || cameraSignals(h).length > 0)
        .filter((h) =>
          filters.every((f) => {
            const vals = IDB_FACETS.find((x) => x.key === f.key)!.get(h);
            return vals.includes(f.value) !== f.negate;
          }),
        )
        .sort((a, b) => b.vulns.length - a.vulns.length || b.ports.length - a.ports.length),
    [hosts, filters, camOnly],
  );

  const facets = useMemo(() => {
    const out: Record<string, FacetBucket[]> = {};
    for (const f of IDB_FACETS) {
      const counts = new Map<string, number>();
      for (const h of visible) for (const v of f.get(h)) counts.set(v, (counts.get(v) ?? 0) + 1);
      if (f.key === 'source' && counts.size < 2) continue;
      if (f.key === 'camera' && counts.size === 0) continue;
      out[f.key] = [...counts.entries()]
        .map(([value, count]) => ({ value, count }))
        .sort((a, b) => b.count - a.count)
        .slice(0, 15);
    }
    return out;
  }, [visible]);

  const exportCsv = () => {
    const esc = (v: unknown) => `"${String(v ?? '').replace(/"/g, '""')}"`;
    const rows = visible.map((h) =>
      [h.ip, h.source, h.hostnames.join(' '), h.ports.join(' '), h.vulns.join(' '), h.tags.join(' '), h.cpes.join(' ')]
        .map(esc)
        .join(','),
    );
    downloadFile('internetdb.csv', ['ip,input,hostnames,ports,vulns,tags,cpes', ...rows].join('\n'), 'text/csv');
  };

  return (
    <main>
      <section className="card">
        <header>
          <h2>InternetDB-oppslag</h2>
          <span className="muted small">Gratis · ingen API-nøkkel · data per IP</span>
        </header>
        <label className="field">
          <span>IP-er, CIDR (maks /22) eller domener – skilt med mellomrom, komma eller linjeskift</span>
          <textarea
            rows={4}
            value={input}
            placeholder={'1.1.1.1\n193.90.0.0/28\nvg.no nrk.no'}
            onChange={(e) => setInput(e.target.value)}
            onKeyDown={(e) => e.key === 'Enter' && (e.metaKey || e.ctrlKey) && run()}
          />
        </label>
        <div className="quick" style={{ marginTop: 8 }}>
          <span className="muted small">Forslag:</span>
          {IDB_PRESETS.map((p) => (
            <button key={p.name} className="chip" title={`${p.description}: ${p.input}`} onClick={() => { setInput(p.input); run(p.input); }}>
              {p.name}
            </button>
          ))}
          <button className="chip" onClick={myIp} title="Legg til din offentlige IP">
            + min IP
          </button>
        </div>
        <div className="row">
          {running ? (
            <button onClick={() => abort.current?.abort()}>Stopp</button>
          ) : (
            <button className="primary" onClick={() => run()}>
              Slå opp <small>(Ctrl+Enter)</small>
            </button>
          )}
          {progress && (
            <span className="muted small">
              {progress.done}/{progress.total} sjekket · {progress.found} med data
            </span>
          )}
          {running && <span className="spinner" />}
        </div>
        {error && <p className="error">{error}</p>}
      </section>

      {hosts.length > 0 && (
        <>
          <div className="quick">
            <button className={`chip ${camOnly ? 'active-chip' : ''}`} onClick={() => setCamOnly(!camOnly)} title="Vis bare verter med kamera-porter (RTSP, Dahua, DVR, Hikvision), kamera-CPE eller webcam-tag">
              📷 Kamera-sjekk {camOnly ? 'på' : 'av'} ({hosts.filter((h) => cameraSignals(h).length).length})
            </button>
          {filters.length > 0 && (
            <>
              <span className="muted small">Filtre:</span>
              {filters.map((f, i) => (
                <button key={i} className={`chip ${f.negate ? 'neg-chip' : ''}`} title="Fjern" onClick={() => setFilters(filters.filter((_, j) => j !== i))}>
                  {f.negate ? '−' : ''}{f.key}:{f.value} ✕
                </button>
              ))}
              <button className="ghost small" onClick={() => setFilters([])}>Fjern alle</button>
            </>
          )}
          </div>
          <div className="summary">
            <strong>{visible.length}</strong> verter med data
            <span className="muted"> · {visible.reduce((a, h) => a + h.vulns.length, 0)} CVE-funn</span>
          </div>
          <FacetPanel
            facets={facets}
            total={visible.length}
            labels={LABELS}
            onPick={(key, value, negate) => setFilters([...filters, { key, value, negate }])}
          />
          <section className="card">
            <header>
              <h2>Verter</h2>
              <button className="ghost small" onClick={exportCsv}>Eksporter CSV</button>
            </header>
            <div className="table-wrap">
              <table>
                <thead>
                  <tr>
                    <th>IP</th>
                    <th>Vertsnavn</th>
                    <th>Porter</th>
                    <th>CVE</th>
                    <th>Tags</th>
                  </tr>
                </thead>
                <tbody>
                  {visible.map((h) => (
                    <Fragment key={h.ip}>
                      <tr onClick={() => setExpanded(expanded === h.ip ? null : h.ip)}>
                        <td className="mono">
                          {h.ip}
                          {cameraSignals(h).length > 0 && <span title={cameraSignals(h).join(', ')}> 📷</span>}
                          {h.source && <div className="muted small">{h.source}</div>}
                        </td>
                        <td className="ellipsis">{h.hostnames.slice(0, 2).join(', ')}{h.hostnames.length > 2 ? ` +${h.hostnames.length - 2}` : ''}</td>
                        <td className="mono small">{h.ports.join(', ')}</td>
                        <td>{h.vulns.length ? <span className="badge danger">{h.vulns.length}</span> : ''}</td>
                        <td className="small">{h.tags.join(', ')}</td>
                      </tr>
                      {expanded === h.ip && (
                        <tr className="expanded">
                          <td colSpan={5}>
                            <dl>
                              <dt>Vertsnavn</dt>
                              <dd>{h.hostnames.join(', ') || '–'}</dd>
                              <dt>Programvare</dt>
                              <dd className="mono small">{h.cpes.join(', ') || '–'}</dd>
                              {cameraSignals(h).length > 0 && (
                                <>
                                  <dt>Kamera-signal</dt>
                                  <dd>{cameraSignals(h).join(', ')}</dd>
                                </>
                              )}
                              <dt>CVE-er</dt>
                              <dd>
                                {h.vulns.length
                                  ? h.vulns.map((v) => (
                                      <a key={v} className="cve" href={`https://nvd.nist.gov/vuln/detail/${v}`} target="_blank" rel="noreferrer">
                                        {v}
                                      </a>
                                    ))
                                  : '–'}
                              </dd>
                            </dl>
                            <a className="button ghost" href={`https://www.shodan.io/host/${h.ip}`} target="_blank" rel="noreferrer">
                              Åpne på shodan.io ↗
                            </a>
                          </td>
                        </tr>
                      )}
                    </Fragment>
                  ))}
                </tbody>
              </table>
            </div>
          </section>
        </>
      )}
      {!running && progress && hosts.length === 0 && !error && (
        <p className="muted">Ingen av adressene finnes i InternetDB.</p>
      )}
    </main>
  );
}
