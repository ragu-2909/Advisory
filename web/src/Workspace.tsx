import { useEffect, useState, type FormEvent } from 'react';
import { Activity, Bell, Database, Download, FileWarning, LayoutDashboard, Play, Server, ShieldCheck } from 'lucide-react';
import type { Overview } from './types';

type Row = Record<string, string | number | boolean | null | undefined>;
type Run = {
  id: string; cveId: string; done: boolean;
  steps: Array<{ name: string; status: string; detail?: string }>;
  assets: Row[];
  products?: Row[];
};
const views = [
  ['Assessment', Play], ['Overview', LayoutDashboard], ['Findings', FileWarning],
  ['Affected assets', Server], ['Alert delivery', Bell], ['Intelligence feeds', Activity], ['Data sources', Database]
] as const;
type View = typeof views[number][0];

async function api<T>(path: string, init?: RequestInit): Promise<T> {
  const response = await fetch(`/api/v1/${path}`, { ...init, cache: 'no-store', signal: AbortSignal.timeout(25_000) });
  const json = await response.json().catch(() => undefined);
  if (!response.ok || !json) throw new Error(json?.message ?? `API unavailable (HTTP ${response.status}).`);
  return json as T;
}

function usePolling<T>(path: string | undefined, interval: number) {
  const [state, setState] = useState<{ path?: string; data?: T; error?: string; updated?: Date }>({});
  useEffect(() => {
    if (!path) return;
    let stopped = false;
    let timer: number;
    async function refresh() {
      try {
        const data = await api<T>(path!);
        if (!stopped) setState({ path, data, updated: new Date() });
      } catch (error) {
        if (!stopped) setState(previous => ({ ...(previous.path === path ? previous : {}), path, error: (error as Error).message }));
      }
      if (!stopped) timer = window.setTimeout(refresh, interval);
    }
    void refresh();
    return () => { stopped = true; window.clearTimeout(timer); };
  }, [path, interval]);
  return state.path === path ? state : {};
}

function exportCsv(name: string, columns: string[], rows: Row[]) {
  const cell = (value: Row[string]) => {
    const raw = String(value ?? '');
    const safe = typeof value === 'string' && /^(?:\s*[=+\-@]|[\t\r\n])/.test(raw) ? "'" + raw : raw;
    return '"' + safe.replaceAll('"', '""') + '"';
  };
  const csv = [columns.map(cell).join(','), ...rows.map(row => columns.map(key => cell(row[key])).join(','))].join('\r\n');
  const url = URL.createObjectURL(new Blob(['\uFEFF', csv], { type: 'text/csv;charset=utf-8' }));
  const anchor = document.createElement('a');
  anchor.href = url;
  anchor.download = name + '.csv';
  anchor.click();
  window.setTimeout(() => URL.revokeObjectURL(url), 1000);
}

function Records({ title, rows, columns, onSelectCve, empty = 'No records to display.' }: {
  title: string; rows?: Row[]; columns: string[]; empty?: string; onSelectCve?: (id: string) => void;
}) {
  return <section className="panel">
    <div className="panel-header"><h2>{title}</h2>
      {Boolean(rows?.length) && <button className="button secondary" onClick={() => exportCsv(title.toLowerCase().replaceAll(/[^a-z0-9-]+/g, '-'), columns, rows!)}><Download size={16} /> Export CSV</button>}
    </div>
    {rows?.length ? <div className="table-wrap"><table><thead><tr>{columns.map(key => <th scope="col" key={key}>{key}</th>)}</tr></thead>
      <tbody>{rows.map((row, index) => <tr key={index}>{columns.map(key => <td key={key}>{
        key === 'cveId' && onSelectCve && typeof row[key] === 'string'
          ? <button className="record-link" onClick={() => onSelectCve(String(row[key]))}>{row[key]}</button>
          : key === 'source' && typeof row[key] === 'string' && row[key].startsWith('https://')
            ? <a className="record-link" href={row[key]} target="_blank" rel="noreferrer">View evidence</a>
            : row[key] == null ? '—' : String(row[key])
      }</td>)}</tr>)}</tbody>
    </table></div> : <p className="workspace-empty">{rows ? empty : 'Waiting for data…'}</p>}
  </section>;
}

export default function Workspace() {
  const [view, setView] = useState<View>('Assessment');
  const [input, setInput] = useState('CVE-2026-111497');
  const [initial, setInitial] = useState<Run>();
  const [starting, setStarting] = useState(false);
  const [failure, setFailure] = useState('');
  const [query, setQuery] = useState('');
  const [filter, setFilter] = useState('All');
  const [falconCheck, setFalconCheck] = useState<{ running: boolean; message?: string; failed?: boolean }>({ running: false });
  const assessment = usePolling<Run>(initial?.done ? undefined : initial && `assessments/${initial.id}`, 1000);
  const run = assessment.data ?? initial;
  useEffect(() => {
    if (assessment.data?.done) setInitial(assessment.data);
  }, [assessment.data]);
  const status = usePolling<{ crowdStrike: { configured: boolean; region: string } }>('connectors', 10000);
  const overview = usePolling<Overview>(['Overview', 'Findings', 'Intelligence feeds'].includes(view) ? 'dashboard/overview' : undefined, 5000);
  const feed = usePolling<{ cursor: string; records: Array<{ cveId: string; change: string }> }>('cve-feed', 15000);
  const collection = usePolling<Row[]>(view === 'Affected assets' ? 'dashboard/assets' : view === 'Alert delivery' ? 'dashboard/deliveries' : undefined, 5000);

  async function assess(event: FormEvent) {
    event.preventDefault();
    setStarting(true);
    setFailure('');
    try {
      setInitial(await api<Run>('assessments', {
        method: 'POST', headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ cveId: input })
      }));
    } catch (error) { setFailure((error as Error).message); }
    finally { setStarting(false); }
  }

  async function checkFalcon() {
    setFalconCheck({ running: true });
    try {
      const result = await api<{ status: string; baseUrl: string }>('connectors/crowdstrike/check', { method: 'POST' });
      setFalconCheck({ running: false, message: `${result.status} with ${result.baseUrl}. Run an assessment to check inventory access.` });
    } catch (error) {
      setFalconCheck({ running: false, failed: true, message: (error as Error).message });
    }
  }

  const findings = overview.data?.findings.filter(item =>
    `${item.cveId} ${item.subject}`.toLowerCase().includes(query.toLowerCase()) &&
    (filter === 'All' || (filter === 'KEV' ? item.kev : item.priority === filter)));
  const error = view === 'Assessment' ? failure || assessment.error : view === 'Intelligence feeds' ? feed.error || overview.error : overview.error || collection.error || status.error;
  function selectCve(id: string) {
    setInput(id);
    setView('Assessment');
  }
  return <div className="operations">
    <aside className="operations-nav">
      <div className="operations-brand"><ShieldCheck size={23} /> Vulnerability advisory</div>
      <nav aria-label="Workspace">{views.map(([name, Icon]) =>
        <button key={name} type="button" aria-current={view === name ? 'page' : undefined} onClick={() => setView(name)}><Icon size={18} />{name}</button>)}
      </nav>
    </aside>
    <main className="operations-main">
      <header className="operations-top"><span>Security operations</span><span role="status">{status.error ? 'API disconnected' : status.updated ? `API connected · ${status.updated.toLocaleTimeString()}` : 'Connecting to API…'}</span></header>
      <div className="operations-content">
        <h1>{view === 'Assessment' ? 'CVE assessment' : view}</h1>
        {error && <p className="action-toast error" role="alert">{error}</p>}
        {view === 'Assessment' && <>
          <section className="panel assessment-form">
            <form onSubmit={assess}>
              <label htmlFor="cve">CVE ID</label>
              <div><input id="cve" required value={input} onChange={event => setInput(event.target.value)} />
                <button className="button primary" disabled={starting || Boolean(run && !run.done && !assessment.error)}><Play size={16} />{starting || (run && !run.done && !assessment.error) ? 'Assessing…' : 'Run assessment'}</button></div>
            </form>
            <p>Checks public feeds and CrowdStrike inventory. Produces an alert preview.</p>
          </section>
          {run && <>
            <section className="panel">
              <div className="panel-header"><h2>{run.cveId}</h2><span role="status">{run.done ? 'Run finished' : 'In progress'}</span></div>
              <ol className="workflow">{run.steps.map((step, index) =>
                <li key={index}><span className={`step-status ${step.status.toLowerCase()}`}>{step.status}</span><div><strong>{step.name}</strong>{step.detail && <p>{step.detail}</p>}</div></li>)}</ol>
            </section>
            <Records title="Products and bundled dependencies" rows={run.products} columns={['product', 'relationship', 'versions', 'inventory', 'source']} empty="No product evidence yet. See the research steps above." />
            <Records title="Inventory evidence" rows={run.assets} columns={['product', 'version', 'host', 'result', 'exposure']} empty={run.done ? 'No inventory evidence returned. See the CrowdStrike step for coverage and errors.' : 'Waiting for CrowdStrike evidence…'} />
          </>}
        </>}
        {view === 'Overview' && <>
          <div className="operations-metrics">{['Open findings', 'P1 critical', 'P2 high', 'Unique CVEs'].map((label, index) =>
            <article className="panel" key={label}><span>{label}</span><strong>{overview.data ? Object.values(overview.data.counts)[index] : '—'}</strong></article>)}</div>
          <Records title="Feed health" rows={overview.data?.feeds.map(item => ({ ...item }))} columns={['feed', 'status', 'completedAt', 'recordsProcessed', 'errorSummary']} />
        </>}
        {view === 'Findings' && <>
          <div className="operations-filters"><input aria-label="Search findings" placeholder="Search by CVE or subject" value={query} onChange={event => setQuery(event.target.value)} />
            <select aria-label="Filter findings" value={filter} onChange={event => setFilter(event.target.value)}>{['All', 'P1', 'P2', 'KEV'].map(option => <option key={option}>{option}</option>)}</select></div>
          <Records title="Open findings" rows={findings?.map(item => ({ ...item }))} onSelectCve={selectCve} columns={['cveId', 'priority', 'subject', 'kev', 'cvssScore', 'cvssVersion', 'cvssSource', 'epss', 'epssDate', 'affectedHosts', 'dueDate']} />
        </>}
        {view === 'Affected assets' && <Records title="Recent inventory matches" rows={collection.data} columns={['cveId', 'product', 'version', 'host', 'observedAt']} />}
        {view === 'Alert delivery' && <Records title="Recent deliveries" rows={collection.data} columns={['cveId', 'consumer', 'status', 'attempts', 'createdAt']} />}
        {view === 'Intelligence feeds' && <>
          <p className="section-note">{feed.data ? `Upstream batch: ${feed.data.cursor} · checked ${feed.updated?.toLocaleTimeString()}` : 'Checking CVE List V5…'}</p>
          <Records title="CVE List V5 changes" rows={feed.data?.records} onSelectCve={selectCve} columns={['cveId', 'change']} empty="The current upstream batch has no changes." />
          <Records title="Processing status" rows={overview.data?.feeds.map(item => ({ ...item }))} columns={['feed', 'status', 'completedAt', 'recordsProcessed', 'errorSummary']} />
        </>}
        {view === 'Data sources' && <><div><button className="button primary" onClick={checkFalcon} disabled={falconCheck.running}>{falconCheck.running ? 'Checking…' : 'Check CrowdStrike authentication'}</button></div>
          {falconCheck.message && <p className={`action-toast ${falconCheck.failed ? 'error' : 'success'}`} role="status">{falconCheck.message}</p>}
          <Records title="Connector configuration" rows={status.data && [
          { source: 'CrowdStrike Falcon', region: status.data.crowdStrike.region, configuration: status.data.crowdStrike.configured ? 'Credentials loaded · run an assessment to check access' : 'Client ID or secret missing' },
          { source: 'CVE List V5', configuration: feed.error ? 'Upstream unavailable' : feed.data ? 'Upstream reachable' : 'Checking upstream' }
        ]} columns={['source', 'region', 'configuration']} /></>}
      </div>
    </main>
  </div>;
}
