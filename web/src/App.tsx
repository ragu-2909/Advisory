import { useEffect, useMemo, useState } from 'react';
import {
  Activity, AlertTriangle, Bell, ChevronDown, CircleHelp, Database, FileWarning,
  Gauge, LayoutDashboard, Menu, Search, Server, Settings, ShieldCheck, SlidersHorizontal,
  X, Zap
} from 'lucide-react';
import { demoOverview } from './demo';
import type { Finding, Overview } from './types';

type LoadState = 'loading' | 'live' | 'demo' | 'error';
type RiskFilter = 'all' | 'p1' | 'kev';

export default function App() {
  const [overview, setOverview] = useState<Overview>();
  const [loadState, setLoadState] = useState<LoadState>('loading');
  const [query, setQuery] = useState('');
  const [sidebarOpen, setSidebarOpen] = useState(false);
  const [selected, setSelected] = useState<Finding>();
  const [riskFilter, setRiskFilter] = useState<RiskFilter>('all');
  const [assessmentState, setAssessmentState] = useState<'idle' | 'running' | 'done' | 'failed'>('idle');

  useEffect(() => {
    const demo = new URLSearchParams(window.location.search).get('demo') === '1';
    if (demo) { setOverview(demoOverview); setLoadState('demo'); return; }
    fetch('/api/v1/dashboard/overview')
      .then((response) => { if (!response.ok) throw new Error('API unavailable'); return response.json(); })
      .then((data: Overview) => { setOverview(data); setLoadState('live'); })
      .catch(() => setLoadState('error'));
  }, []);

  const findings = useMemo(() => overview?.findings.filter((finding) => {
    const searchMatch = `${finding.cveId} ${finding.subject}`.toLowerCase().includes(query.toLowerCase());
    const riskMatch = riskFilter === 'all' || (riskFilter === 'p1' && finding.priority === 'P1') || (riskFilter === 'kev' && finding.kev);
    return searchMatch && riskMatch;
  }) ?? [], [overview, query, riskFilter]);

  const runAssessment = async () => {
    setAssessmentState('running');
    const endpoints = ['/api/v1/feeds/cisa-kev/sync', '/api/v1/feeds/epss/refresh', '/api/v1/feeds/cve-list/sync'];
    const results = await Promise.allSettled(endpoints.map(async (endpoint) => {
      const response = await fetch(endpoint, { method: 'POST' });
      if (!response.ok) throw new Error(endpoint);
      return response.json();
    }));
    setAssessmentState(results.some((result) => result.status === 'fulfilled') ? 'done' : 'failed');
    if (results.some((result) => result.status === 'fulfilled')) {
      fetch('/api/v1/dashboard/overview').then((response) => response.json()).then(setOverview).catch(() => undefined);
    }
    window.setTimeout(() => setAssessmentState('idle'), 4500);
  };

  const cycleFilter = () => setRiskFilter((current) => current === 'all' ? 'p1' : current === 'p1' ? 'kev' : 'all');

  return <div className="shell">
    <Sidebar open={sidebarOpen} onClose={() => setSidebarOpen(false)} />
    <main className="main">
      <Header query={query} setQuery={setQuery} openMenu={() => setSidebarOpen(true)} />
      <div className="content">
        <div className="page-heading">
          <div>
            <div className="eyebrow"><span className="live-dot" /> Intelligence operations</div>
            <h1>Vulnerability posture</h1>
            <p>Prioritized advisories matched against your environment.</p>
          </div>
          <div className="heading-actions">
            <button className={`button secondary ${riskFilter !== 'all' ? 'selected' : ''}`} onClick={cycleFilter}><SlidersHorizontal size={17} /> {riskFilter === 'all' ? 'Filter' : riskFilter.toUpperCase()}</button>
            <button className="button primary" onClick={runAssessment} disabled={assessmentState === 'running'}><Zap size={17} /> {assessmentState === 'running' ? 'Running…' : 'Run assessment'}</button>
          </div>
        </div>

        {loadState === 'error' && <SetupBanner />}
        {loadState === 'demo' && <div className="demo-banner">Preview data is displayed. Connect PostgreSQL to view live findings.</div>}
        {assessmentState === 'done' && <div className="action-toast success">Assessment completed. Available feed results were refreshed.</div>}
        {assessmentState === 'failed' && <div className="action-toast error">Assessment could not run. Check the API, database, and connector configuration.</div>}
        {loadState === 'loading' && <LoadingState />}
        {overview && <>
          <MetricGrid overview={overview} />
          <div className="dashboard-grid">
            <section className="panel findings-panel">
              <div className="panel-header">
                <div><h2>Priority queue</h2><p>Open findings requiring attention</p></div>
                <button className="text-button">View all</button>
              </div>
              <FindingsTable findings={findings} onSelect={setSelected} />
            </section>
            <aside className="right-column">
              <RiskPanel overview={overview} />
              <FeedPanel overview={overview} />
            </aside>
          </div>
        </>}
      </div>
    </main>
    {selected && <FindingDrawer finding={selected} onClose={() => setSelected(undefined)} />}
  </div>;
}

function Sidebar({ open, onClose }: { open: boolean; onClose: () => void }) {
  const items = [
    { icon: LayoutDashboard, label: 'Overview', active: true },
    { icon: FileWarning, label: 'Findings', count: 24 },
    { icon: Server, label: 'Affected assets' },
    { icon: Bell, label: 'Alert delivery' },
    { icon: Activity, label: 'Intelligence feeds' },
    { icon: Database, label: 'Data sources' }
  ];
  return <aside className={`sidebar ${open ? 'open' : ''}`}>
    <div className="brand"><div className="brand-mark"><ShieldCheck size={23} /></div><div><strong>Sentinel</strong><span>ADVISORY</span></div><button className="sidebar-close" onClick={onClose}><X size={20} /></button></div>
    <div className="tenant"><div className="tenant-icon">AC</div><div><strong>Acme Security</strong><span>Production</span></div><ChevronDown size={15} /></div>
    <nav>{items.map(({ icon: Icon, label, active, count }) => <button key={label} className={active ? 'active' : ''}><Icon size={19} /><span>{label}</span>{count && <em>{count}</em>}</button>)}</nav>
    <div className="sidebar-spacer" />
    <nav className="bottom-nav"><button><CircleHelp size={19} /><span>Support</span></button><button><Settings size={19} /><span>Settings</span></button></nav>
    <div className="profile"><div className="avatar">RS</div><div><strong>Security Admin</strong><span>Administrator</span></div><ChevronDown size={15} /></div>
  </aside>;
}

function Header({ query, setQuery, openMenu }: { query: string; setQuery: (value: string) => void; openMenu: () => void }) {
  return <header className="topbar">
    <button className="menu-button" onClick={openMenu}><Menu size={21} /></button>
    <div className="search"><Search size={18} /><input aria-label="Search findings" placeholder="Search CVEs, products, or hosts" value={query} onChange={(event) => setQuery(event.target.value)} /><kbd>⌘ K</kbd></div>
    <div className="topbar-actions"><span className="updated">Updated 4 min ago</span><button className="icon-button"><Bell size={19} /><i /></button><button className="avatar small">RS</button></div>
  </header>;
}

function MetricGrid({ overview }: { overview: Overview }) {
  const metrics = [
    { label: 'Open findings', value: overview.counts.open, detail: `${overview.counts.cves} unique CVEs`, icon: FileWarning, tone: 'navy' },
    { label: 'Critical priority', value: overview.counts.p1, detail: 'Requires immediate action', icon: AlertTriangle, tone: 'red' },
    { label: 'CISA KEV', value: overview.findings.filter((item) => item.kev).length, detail: 'Known exploited', icon: Zap, tone: 'amber' },
    { label: 'Affected hosts', value: overview.findings.reduce((sum, item) => sum + Number(item.affectedHosts), 0), detail: 'Confirmed matches', icon: Server, tone: 'teal' }
  ];
  return <div className="metric-grid">{metrics.map(({ label, value, detail, icon: Icon, tone }) => <article className="metric-card" key={label}>
    <div className={`metric-icon ${tone}`}><Icon size={20} /></div><div className="metric-label">{label}</div><strong>{value}</strong><span>{detail}</span>
  </article>)}</div>;
}

function FindingsTable({ findings, onSelect }: { findings: Finding[]; onSelect: (finding: Finding) => void }) {
  if (!findings.length) return <div className="empty-state"><ShieldCheck size={30} /><strong>No matching findings</strong><span>Try a different search or refresh the intelligence feeds.</span></div>;
  return <div className="table-wrap"><table><thead><tr><th>Finding</th><th>Signals</th><th>Score</th><th>Affected</th><th>Due</th></tr></thead><tbody>
    {findings.map((finding) => <tr key={finding.id} onClick={() => onSelect(finding)}>
      <td><div className="finding-title"><span className={`priority ${finding.priority.toLowerCase()}`}>{finding.priority}</span><div><strong>{finding.cveId}</strong><span>{finding.subject}</span></div></div></td>
      <td><div className="signal-list">{finding.kev && <span className="tag kev">KEV</span>}<span className="tag">EPSS {percent(finding.epss)}</span></div></td>
      <td><strong className="score">{finding.cvssScore?.toFixed(1) ?? '—'}</strong><span className="cell-sub">CVSS {finding.cvssVersion ?? 'unknown'}</span></td>
      <td><strong>{finding.affectedHosts}</strong><span className="cell-sub">hosts</span></td>
      <td><strong>{finding.dueDate ? shortDate(finding.dueDate) : '—'}</strong><span className="cell-sub">{finding.kev ? 'CISA due' : 'No deadline'}</span></td>
    </tr>)}
  </tbody></table></div>;
}

function RiskPanel({ overview }: { overview: Overview }) {
  const total = Math.max(overview.counts.open, 1);
  const rows = [{ label: 'P1 Critical', value: overview.counts.p1, color: 'red' }, { label: 'P2 High', value: overview.counts.p2, color: 'amber' }, { label: 'Review', value: Math.max(overview.counts.open - overview.counts.p1 - overview.counts.p2, 0), color: 'blue' }];
  return <section className="panel risk-panel"><div className="panel-header"><div><h2>Risk distribution</h2><p>Current open queue</p></div><Gauge size={20} /></div><div className="risk-total"><strong>{overview.counts.open}</strong><span>Total findings</span></div><div className="risk-bars">{rows.map((row) => <div key={row.label}><div><span>{row.label}</span><strong>{row.value}</strong></div><div className="bar"><i className={row.color} style={{ width: `${Math.max((row.value / total) * 100, 3)}%` }} /></div></div>)}</div></section>;
}

function FeedPanel({ overview }: { overview: Overview }) {
  return <section className="panel feed-panel"><div className="panel-header"><div><h2>Feed health</h2><p>Connector status</p></div><button className="text-button">Manage</button></div><div className="feed-list">{overview.feeds.map((feed) => <div className="feed" key={feed.feed}><span className={`health-dot ${feed.status === 'SUCCESS' ? '' : 'error'}`} /><div><strong>{feed.feed.replaceAll('_', ' ')}</strong><span>{feed.completedAt ? relative(feed.completedAt) : 'Not synchronized'}</span></div><em>{feed.status === 'SUCCESS' ? 'Healthy' : feed.status}</em></div>)}</div></section>;
}

function FindingDrawer({ finding, onClose }: { finding: Finding; onClose: () => void }) {
  return <div className="drawer-backdrop" onClick={onClose}><aside className="drawer" onClick={(event) => event.stopPropagation()}>
    <div className="drawer-head"><div><span className={`priority ${finding.priority.toLowerCase()}`}>{finding.priority}</span><h2>{finding.cveId}</h2></div><button className="icon-button" onClick={onClose}><X size={20} /></button></div>
    {finding.kev && <div className="kev-callout"><Zap size={21} /><div><strong>Known exploited vulnerability</strong><span>CISA has observed active exploitation. Prioritize remediation.</span></div></div>}
    <h3>Executive summary</h3><p className="summary">{finding.subject} affects {finding.affectedHosts} confirmed hosts in your environment. The selected score is {finding.cvssScore ?? 'unknown'} (CVSS {finding.cvssVersion ?? 'unknown'}, {finding.cvssSource ?? 'unattributed'}) and the current EPSS probability is {percent(finding.epss)}.</p>
    <div className="detail-grid"><div><span>CVSS score</span><strong>{finding.cvssScore?.toFixed(1) ?? 'Unknown'}</strong></div><div><span>EPSS probability</span><strong>{percent(finding.epss)}</strong></div><div><span>Affected hosts</span><strong>{finding.affectedHosts}</strong></div><div><span>Remediation due</span><strong>{finding.dueDate ? shortDate(finding.dueDate) : 'Not set'}</strong></div></div>
    <h3>Score provenance</h3><div className="provenance"><ShieldCheck size={19} /><div><strong>{finding.cvssSource ?? 'No score selected'}</strong><span>CVSS {finding.cvssVersion ?? 'unknown'} takes precedence under policy 1.0.0</span></div></div>
    <div className="drawer-actions"><button className="button secondary">Open full record</button><button className="button primary">Create response task</button></div>
  </aside></div>;
}

function SetupBanner() { return <div className="setup-banner"><Database size={21} /><div><strong>Backend setup required</strong><span>Run the PostgreSQL migration and start the API, or add <code>?demo=1</code> to preview the dashboard.</span></div></div>; }
function LoadingState() { return <div className="loading"><span /><span /><span /></div>; }
function percent(value?: number) { return value == null ? 'Unknown' : `${(Number(value) * 100).toFixed(1)}%`; }
function shortDate(value: string) { return new Intl.DateTimeFormat('en', { month: 'short', day: 'numeric' }).format(new Date(`${value}T00:00:00`)); }
function relative(value: string) { const minutes = Math.max(1, Math.round((Date.now() - new Date(value).getTime()) / 60_000)); return minutes < 60 ? `${minutes} min ago` : `${Math.round(minutes / 60)} hr ago`; }
