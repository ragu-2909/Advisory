import type { DatabasePool } from '../db/pool.js';
import { CisaKevConnector } from '../connectors/cisa-kev.js';
import { EpssConnector } from '../connectors/epss.js';
import { parseCveRecord } from '../connectors/cve-record.js';
import { selectCvss } from '../domain/cvss-selector.js';
import type { CorrelationService } from './correlation-service.js';

export class FeedService {
  constructor(
    private readonly db: DatabasePool,
    private readonly correlation?: CorrelationService,
    private readonly kev = new CisaKevConnector(),
    private readonly epss = new EpssConnector()
  ) {}

  async syncKev(): Promise<{ processed: number; version: string }> {
    const run = await this.startRun('CISA_KEV');
    try {
      const catalog = await this.kev.fetchCatalog();
      const existing = await this.db.query<{ cve_id: string }>('SELECT cve_id FROM kev_entries WHERE cve_id=ANY($1::text[])', [catalog.vulnerabilities.map((entry) => entry.cveID)]);
      const existingIds = new Set(existing.rows.map((row) => row.cve_id));
      const client = await this.db.connect();
      try {
        await client.query('BEGIN');
        for (const entry of catalog.vulnerabilities) {
          await client.query(
            `INSERT INTO vulnerabilities (cve_id, title, description, updated_at)
             VALUES ($1, $2, $3, now())
             ON CONFLICT (cve_id) DO UPDATE SET
               title = COALESCE(vulnerabilities.title, EXCLUDED.title),
               description = COALESCE(vulnerabilities.description, EXCLUDED.description),
               updated_at = now()`,
            [entry.cveID, entry.vulnerabilityName, entry.shortDescription]
          );
          await client.query(
            `INSERT INTO kev_entries (
               cve_id, vendor_project, product, vulnerability_name, date_added,
               short_description, required_action, due_date,
               known_ransomware_campaign_use, notes, raw_record, fetched_at
             ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,now())
             ON CONFLICT (cve_id) DO UPDATE SET
               vendor_project=EXCLUDED.vendor_project, product=EXCLUDED.product,
               vulnerability_name=EXCLUDED.vulnerability_name, date_added=EXCLUDED.date_added,
               short_description=EXCLUDED.short_description, required_action=EXCLUDED.required_action,
               due_date=EXCLUDED.due_date, known_ransomware_campaign_use=EXCLUDED.known_ransomware_campaign_use,
               notes=EXCLUDED.notes, raw_record=EXCLUDED.raw_record, fetched_at=now()`,
            [entry.cveID, entry.vendorProject, entry.product, entry.vulnerabilityName, entry.dateAdded,
              entry.shortDescription, entry.requiredAction, entry.dueDate,
              entry.knownRansomwareCampaignUse, entry.notes, entry]
          );
        }
        await client.query('COMMIT');
      } catch (error) {
        await client.query('ROLLBACK');
        throw error;
      } finally {
        client.release();
      }
      if (this.correlation) {
        for (const entry of catalog.vulnerabilities.filter((item) => !existingIds.has(item.cveID))) {
          const result = await this.db.query<{ raw_record?: Record<string, unknown> }>('SELECT raw_record FROM vulnerabilities WHERE cve_id=$1', [entry.cveID]);
          if (!result.rows[0]?.raw_record) continue;
          const record = parseCveRecord(result.rows[0].raw_record);
          await this.correlation.evaluate(record, selectCvss(record.metrics));
        }
      }
      await this.finishRun(run, 'SUCCESS', catalog.vulnerabilities.length, catalog.catalogVersion);
      return { processed: catalog.vulnerabilities.length, version: catalog.catalogVersion };
    } catch (error) {
      await this.failRun(run, error);
      throw error;
    }
  }

  async refreshEpss(): Promise<{ processed: number; scoreDate?: string }> {
    const run = await this.startRun('FIRST_EPSS');
    try {
      const ids = await this.db.query<{ cve_id: string }>(
        `SELECT DISTINCT v.cve_id FROM vulnerabilities v
         LEFT JOIN alerts a ON a.cve_id = v.cve_id AND a.state = 'OPEN'
         LEFT JOIN kev_entries k ON k.cve_id = v.cve_id
         WHERE a.id IS NOT NULL OR k.cve_id IS NOT NULL OR v.selected_cvss_score >= 8`
      );
      const scores = await this.epss.getScores(ids.rows.map((row) => row.cve_id));
      for (const score of scores) {
        await this.db.query(
          `INSERT INTO epss_history(cve_id, score_date, epss, percentile)
           VALUES ($1,$2,$3,$4)
           ON CONFLICT(cve_id, score_date) DO UPDATE SET
             epss=EXCLUDED.epss, percentile=EXCLUDED.percentile, fetched_at=now()`,
          [score.cve, score.scoreDate, score.epss, score.percentile]
        );
      }
      const scoreDate = scores[0]?.scoreDate;
      await this.finishRun(run, 'SUCCESS', scores.length, scoreDate);
      return { processed: scores.length, scoreDate };
    } catch (error) {
      await this.failRun(run, error);
      throw error;
    }
  }

  private async startRun(feed: string): Promise<string> {
    const result = await this.db.query<{ id: string }>('INSERT INTO feed_runs(feed,status) VALUES ($1,$2) RETURNING id', [feed, 'RUNNING']);
    return result.rows[0]!.id;
  }
  private async finishRun(id: string, status: string, count: number, cursor?: string) {
    await this.db.query('UPDATE feed_runs SET status=$2, completed_at=now(), records_processed=$3, cursor=$4 WHERE id=$1', [id, status, count, cursor]);
  }
  private async failRun(id: string, error: unknown) {
    await this.db.query('UPDATE feed_runs SET status=$2, completed_at=now(), error_summary=$3 WHERE id=$1', [id, 'FAILED', error instanceof Error ? error.message.slice(0, 1000) : 'Unknown error']);
  }
}
