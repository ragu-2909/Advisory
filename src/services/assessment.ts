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
import { matchVersion } from '../domain/version-match.js';

type Step = { name: string; status: 'Running' | 'Complete' | 'Unavailable'; detail?: string };
type Run = {
  id: string; cveId: string; done: boolean; steps: Step[];
  assets: Array<{ product: string; version?: string; host: string; result: string; exposure: boolean | null }>;
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
    const run: Run = { id: randomUUID(), cveId, done: false, steps: [], assets: [], incomplete: false };
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
    if (!record.affected.length) {
      run.steps.push({ name: 'CrowdStrike', status: 'Unavailable', detail: 'The CVE has no searchable product entries.' });
      return;
    }
    for (const product of record.affected.slice(0, 10)) {
      const label = [product.vendor, product.product].filter(Boolean).join(' ');
      await step(`Published versions · ${label}`, async () => product.versions, versions =>
        versions.map(v => [v.version, v.lessThan && `< ${v.lessThan}`, v.lessThanOrEqual && `≤ ${v.lessThanOrEqual}`, v.status].filter(Boolean).join(' ')).join(', ') || 'Unspecified');
      await step(`CrowdStrike · ${label}`, async () => {
        if (!this.crowdStrike.configured) throw new Error('Set both CrowdStrike credential fields and restart the API.');
        const applications = await this.crowdStrike.searchApplications({ name: product.product });
        for (const app of applications) {
          const exact = app.name.trim().toLowerCase() === product.product.trim().toLowerCase()
            && (!product.vendor || app.vendor?.trim().toLowerCase() === product.vendor.trim().toLowerCase());
          run.assets.push({
            product: app.name, version: app.version, host: String(app.host?.hostname ?? app.hostId),
            result: exact ? matchVersion(product, app.version) : 'REVIEW', exposure: app.exposure
          });
        }
        return applications;
      }, apps => `${apps.length} application inventory entries · ${apps.filter(app => app.host).length} host records resolved`);
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
