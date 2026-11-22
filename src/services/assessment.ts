import { randomUUID } from 'node:crypto';
import { fetchCve } from '../connectors/cve-feed.js';
import { parseCveRecord } from '../connectors/cve-record.js';
import { CisaKevConnector } from '../connectors/cisa-kev.js';
import { EpssConnector } from '../connectors/epss.js';
import { HttpError } from '../connectors/http.js';
import type { NvdConnector } from '../connectors/nvd.js';
import type { CrowdStrikeConnector } from '../connectors/crowdstrike.js';
import { selectCvss } from '../domain/cvss-selector.js';
import { evaluateRisk } from '../domain/risk-policy.js';
import { discoverProducts, matchTarget } from './product-discovery.js';

type Step = { name: string; status: 'Running' | 'Complete' | 'Unavailable'; detail?: string };
type Run = {
  id: string; cveId: string; done: boolean; steps: Step[];
  assets: Array<{ product: string; version?: string; host: string; result: string; exposure: boolean | null; hostLookup: string }>;
  products: Array<{ product: string; relationship: string; source: string; versions: string; inventory: string }>;
  incomplete: boolean;
};

export class AssessmentService {
  private readonly runs = new Map<string, Run>();
  private readonly kev = new CisaKevConnector();
  private readonly epss = new EpssConnector();

  constructor(private readonly crowdStrike: CrowdStrikeConnector, private readonly nvd: NvdConnector) {}

  get(id: string) { return this.runs.get(id); }

  start(cveId: string) {
    if ([...this.runs.values()].some(run => !run.done)) return;
    if (this.runs.size >= 20) this.runs.delete(this.runs.keys().next().value!);
    const run: Run = { id: randomUUID(), cveId, done: false, steps: [], assets: [], products: [], incomplete: false };
    this.runs.set(run.id, run);
    void this.execute(run).catch(() => {
      run.incomplete = true;
      run.steps.push({ name: 'Assessment', status: 'Unavailable', detail: 'The assessment stopped unexpectedly.' });
    }).finally(() => { run.done = true; });
    return run;
  }

  private async execute(run: Run) {
    async function step<T>(name: string, work: () => Promise<T>, describe: (data: T) => string) {
      const state: Step = { name, status: 'Running' };
      run.steps.push(state);
      try {
        const data = await work();
        state.detail = describe(data);
        state.status = 'Complete';
        return data;
      } catch (error) {
        state.status = 'Unavailable';
        state.detail = error instanceof HttpError
          ? (name === 'CVE List V5' && error.status === 404 ? 'This CVE was not found in the public repository.' : error.message)
          : error instanceof Error ? error.message : 'Request failed';
        run.incomplete = true;
      }
    }

    const record = await step('CVE List V5', async () => parseCveRecord(await fetchCve(run.cveId)),
      data => `${data.state} · ${data.title ?? data.cveId}`);
    if (!record || record.state !== 'PUBLISHED') return;
    const [nvd, epss, kev] = await Promise.all([
      step('NVD', () => this.nvd.getCve(run.cveId), data => `${data.metrics.length} CVSS metrics returned`),
      step('FIRST EPSS', async () => (await this.epss.getScores([run.cveId]))[0],
        data => data ? `${(data.epss * 100).toFixed(2)}% on ${data.scoreDate}` : 'No score published'),
      step('CISA KEV', async () => (await this.kev.fetchCatalog()).vulnerabilities.find(item => item.cveID === run.cveId) ?? null,
        data => data ? `Listed · action due ${data.dueDate}` : 'No entry in the current catalog')
    ]);
    const selected = selectCvss([...record.metrics, ...(nvd?.metrics ?? [])]);
    await step('CVSS selection', async () => selected,
      data => data ? `${data.baseScore} · CVSS ${data.version} · ${data.provider ?? data.source}` : 'No usable CVSS 4.0 or 3.1 score');
    const discovery = await step('Product and dependency research', () => discoverProducts(record, nvd?.raw),
      data => `${data.targets.length} product records. ${data.warnings.join(' ')}`);
    if (!discovery?.targets.length) {
      run.steps.push({ name: 'CrowdStrike', status: 'Unavailable', detail: 'The CVE has no searchable product entries.' });
      return;
    }
    run.incomplete ||= discovery.warnings.length > 0 || discovery.targets.length > 20;
    run.products = discovery.targets.map(target => {
      const { product } = target;
      const label = [product.vendor, product.product].filter(Boolean).join(' ');
      const versions = product.versions.map(v => [v.version, v.lessThan && `< ${v.lessThan}`, v.lessThanOrEqual && `≤ ${v.lessThanOrEqual}`, v.status].filter(Boolean).join(' ')).join(', ');
      return { product: label, relationship: target.relationship, source: target.source, versions: versions || 'Unverified', inventory: 'Pending' };
    });
    const auth = await step('CrowdStrike authentication', () => this.crowdStrike.checkAuthentication(), result => result.baseUrl);
    const searches = new Map<string, ReturnType<CrowdStrikeConnector['searchApplications']>>();
    for (const [index, target] of discovery.targets.entries()) {
      const row = run.products[index]!;
      if (!auth || index >= 20) {
        row.inventory = auth ? 'Lookup limit reached' : 'Authentication unavailable';
        continue;
      }
      const matches = await step(`CrowdStrike · ${row.product}`, async () => {
        const lookup = searches.get(target.searchName) ?? this.crowdStrike.searchApplications({ name: target.searchName });
        searches.set(target.searchName, lookup);
        const applications = await lookup;
        for (const app of applications) {
          run.assets.push({
            product: app.name, version: app.version, host: String(app.host?.hostname ?? app.hostId),
            result: matchTarget(target, app), exposure: app.exposure,
            hostLookup: app.hostResolutionIssue ?? 'Resolved'
          });
        }
        return applications;
      }, apps => {
        const issues = [...new Set(apps.flatMap(app => app.hostResolutionIssue ? [app.hostResolutionIssue] : []))];
        if (issues.length) run.incomplete = true;
        const resolved = new Set(apps.filter(app => app.host).map(app => app.hostId)).size;
        return [`${apps.length} application inventory entries · ${resolved} host records resolved`, ...issues].join(' · ');
      });
      row.inventory = matches
        ? `${matches.length} entries${matches.some(app => app.hostResolutionIssue) ? ' · partial host details' : ''}`
        : 'Lookup unavailable';
    }
    await step('Alert preview', async () => {
      const affected = run.assets.filter(asset => asset.result === 'AFFECTED');
      return evaluateRisk({
        cveId: run.cveId, selectedCvss: selected, epss, kev: Boolean(kev),
        confirmedAffectedAssets: new Set(affected.map(asset => asset.host)).size,
        internetExposure: affected.some(asset => asset.exposure === true) ? true : affected.every(asset => asset.exposure === false) ? false : null
      });
    }, decision => `${run.incomplete || record.affected.length > 10 || run.assets.some(asset => asset.result === 'REVIEW') ? 'Partial evidence · ' : ''}${decision.decision.replaceAll('_', ' ')} · ${decision.reasons.join(', ')}. This run does not queue email.`);
  }
}
