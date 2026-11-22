import { createHash } from 'node:crypto';
import type { DatabasePool } from '../db/pool.js';
import type { AppConfig } from '../config.js';
import type { CrowdStrikeConnector } from '../connectors/crowdstrike.js';
import type { AffectedProduct, ParsedCveRecord } from '../connectors/cve-record.js';
import { evaluateRisk } from '../domain/risk-policy.js';
import type { CvssMetric } from '../domain/types.js';

export class CorrelationService {
  constructor(private readonly db: DatabasePool, private readonly crowdStrike: CrowdStrikeConnector, private readonly config: AppConfig) {}

  async evaluate(record: ParsedCveRecord, selectedCvss?: CvssMetric): Promise<{ matches: number; alert?: string }> {
    if (!this.crowdStrike.configured) return { matches: 0 };
    const kevResult = await this.db.query<{ due_date?: string; required_action?: string; known_ransomware_campaign_use?: string }>('SELECT * FROM kev_entries WHERE cve_id=$1', [record.cveId]);
    const kev = kevResult.rows[0];
    if (!kev && (selectedCvss?.baseScore ?? 0) < 9) return { matches: 0 };

    const allMatches = [];
    for (const affected of distinctProducts(record.affected)) {
      const matches = await this.crowdStrike.searchApplications({ name: affected.product, vendor: usableVendor(affected.vendor) });
      allMatches.push(...matches.map((match) => ({ ...match, affected })));
    }

    for (const match of allMatches) {
      await this.db.query(
        `INSERT INTO application_matches(cve_id,source,external_application_id,host_id,application_name,vendor,installed_version,architecture,installation_paths,match_confidence,match_state,evidence)
         VALUES($1,'CROWDSTRIKE',$2,$3,$4,$5,$6,$7,$8,'PROBABLE','AFFECTED',$9)
         ON CONFLICT(cve_id,source,external_application_id,host_id) DO UPDATE SET
           installed_version=EXCLUDED.installed_version, architecture=EXCLUDED.architecture,
           installation_paths=EXCLUDED.installation_paths, evidence=EXCLUDED.evidence, observed_at=now()`,
        [record.cveId, match.applicationId, match.hostId, match.name, match.vendor, match.version, match.architecture, JSON.stringify(match.installationPaths), { application: match.application, affected: match.affected }]
      );
      if (match.host) {
        await this.db.query(
          `INSERT INTO hosts(source,host_id,hostname,local_ip,external_ip,platform_name,os_version,architecture,internet_exposure,exposure_source,last_seen_at,details,expires_at)
           VALUES('CROWDSTRIKE',$1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,now()+interval '15 minutes')
           ON CONFLICT(source,host_id) DO UPDATE SET hostname=EXCLUDED.hostname,local_ip=EXCLUDED.local_ip,external_ip=EXCLUDED.external_ip,
             platform_name=EXCLUDED.platform_name,os_version=EXCLUDED.os_version,architecture=EXCLUDED.architecture,
             internet_exposure=EXCLUDED.internet_exposure,exposure_source=EXCLUDED.exposure_source,last_seen_at=EXCLUDED.last_seen_at,
             details=EXCLUDED.details,fetched_at=now(),expires_at=EXCLUDED.expires_at`,
          [match.hostId, value(match.host.hostname), value(match.host.local_ip) ?? value(match.host.local_ip_address), value(match.host.external_ip),
            value(match.host.platform_name), value(match.host.os_version), match.architecture, match.exposure, match.exposure === null ? null : 'CROWDSTRIKE', value(match.host.last_seen), match.host]
        );
      }
    }

    if (!allMatches.length) return { matches: 0 };
    const exposures = allMatches.map((match) => match.exposure);
    const internetExposure = exposures.includes(true) ? true : exposures.every((item) => item === false) ? false : null;
    const decision = evaluateRisk({
      cveId: record.cveId, selectedCvss, kev: Boolean(kev),
      ransomwareUseKnown: kev?.known_ransomware_campaign_use?.toLowerCase() === 'known',
      confirmedAffectedAssets: new Set(allMatches.map((match) => match.hostId)).size,
      internetExposure
    });
    if (!decision.decision.startsWith('ALERT')) return { matches: allMatches.length };

    const hostCount = new Set(allMatches.map((match) => match.hostId)).size;
    const subject = `${kev ? '[KEV]' : ''}[${decision.priority}] ${record.cveId} affects ${hostCount} host${hostCount === 1 ? '' : 's'}`;
    const executive = `${kev ? 'KNOWN EXPLOITED (CISA KEV): YES. ' : ''}${record.cveId} affects ${hostCount} confirmed CrowdStrike host${hostCount === 1 ? '' : 's'}. Selected severity: ${selectedCvss ? `${selectedCvss.baseScore} (CVSS ${selectedCvss.version}, ${selectedCvss.source})` : 'unknown'}.`;
    const fingerprint = createHash('sha256').update(`${record.cveId}:${decision.priority}:${hostCount}:${selectedCvss?.version}:${selectedCvss?.baseScore}:${Boolean(kev)}`).digest('hex');
    const alert = await this.db.query<{ id: string }>(
      `INSERT INTO alerts(cve_id,priority,subject,executive_summary,mail_body,decision_trace,policy_version,fingerprint)
       VALUES($1,$2,$3,$4,$5,$6,$7,$8)
       ON CONFLICT(fingerprint) DO UPDATE SET updated_at=now() RETURNING id`,
      [record.cveId, decision.priority, subject, executive, {
        contentType: 'html', executiveSummary: executive, html: renderHtml(executive, allMatches),
        affectedHosts: allMatches.map((match) => ({ hostId: match.hostId, hostname: match.host?.hostname, ipAddresses: [match.host?.local_ip, match.host?.external_ip].filter(Boolean), architecture: match.architecture, installedProduct: match.name, installedVersion: match.version, internetFacing: match.exposure, matchConfidence: 'PROBABLE' }))
      }, decision, decision.policyVersion, fingerprint]
    );
    await this.db.query(
      `INSERT INTO alert_deliveries(alert_id,consumer_id) VALUES($1,$2)
       ON CONFLICT(alert_id,consumer_id) DO NOTHING`,
      [alert.rows[0]!.id, this.config.DEFAULT_ALERT_CONSUMER]
    );
    return { matches: allMatches.length, alert: alert.rows[0]!.id };
  }
}

function distinctProducts(products: AffectedProduct[]): AffectedProduct[] { const seen = new Set<string>(); return products.filter((item) => { const key = `${item.vendor}:${item.product}`.toLowerCase(); if (seen.has(key)) return false; seen.add(key); return true; }); }
function usableVendor(vendor?: string): string | undefined { return vendor && !['n/a', 'unknown', '*'].includes(vendor.toLowerCase()) ? vendor : undefined; }
function value(input: unknown): string | undefined { return typeof input === 'string' ? input : undefined; }
function escapeHtml(input: unknown): string { return String(input ?? '').replace(/[&<>"']/g, (char) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[char]!); }
function renderHtml(summary: string, matches: Array<{ hostId: string; name: string; version?: string; architecture?: string; host?: Record<string, unknown> }>): string {
  const rows = matches.map((item) => `<tr><td>${escapeHtml(item.host?.hostname ?? item.hostId)}</td><td>${escapeHtml(item.host?.local_ip ?? '')}</td><td>${escapeHtml(item.name)}</td><td>${escapeHtml(item.version ?? 'Unknown')}</td><td>${escapeHtml(item.architecture ?? 'Unknown')}</td></tr>`).join('');
  return `<p><strong>${escapeHtml(summary)}</strong></p><table><thead><tr><th>Host</th><th>IP</th><th>Application</th><th>Version</th><th>Architecture</th></tr></thead><tbody>${rows}</tbody></table>`;
}
