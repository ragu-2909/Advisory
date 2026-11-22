import type { DatabasePool } from '../db/pool.js';

export class DashboardService {
  constructor(private readonly db: DatabasePool) {}

  async overview() {
    const [counts, findings, feeds] = await Promise.all([
      this.db.query(`
        SELECT
          count(*) FILTER (WHERE state='OPEN')::int AS open,
          count(*) FILTER (WHERE state='OPEN' AND priority='P1')::int AS p1,
          count(*) FILTER (WHERE state='OPEN' AND priority='P2')::int AS p2,
          count(DISTINCT cve_id) FILTER (WHERE state='OPEN')::int AS cves
        FROM alerts`),
      this.db.query(`
        SELECT a.id, a.cve_id AS "cveId", a.priority, a.subject,
               a.created_at AS "createdAt", v.selected_cvss_score AS "cvssScore",
               v.selected_cvss_version AS "cvssVersion", v.selected_cvss_source AS "cvssSource",
               (k.cve_id IS NOT NULL) AS kev, k.due_date AS "dueDate",
               e.epss, e.percentile, e.score_date AS "epssDate",
               (SELECT count(*)::int FROM application_matches m WHERE m.cve_id=a.cve_id) AS "affectedHosts"
        FROM alerts a
        JOIN vulnerabilities v ON v.cve_id=a.cve_id
        LEFT JOIN kev_entries k ON k.cve_id=a.cve_id
        LEFT JOIN LATERAL (
          SELECT epss, percentile, score_date FROM epss_history
          WHERE cve_id=a.cve_id ORDER BY score_date DESC LIMIT 1
        ) e ON true
        WHERE a.state='OPEN'
        ORDER BY CASE a.priority WHEN 'P1' THEN 1 WHEN 'P2' THEN 2 ELSE 3 END, a.created_at DESC
        LIMIT 20`),
      this.db.query(`
        SELECT DISTINCT ON (feed) feed, status, completed_at AS "completedAt",
               records_processed AS "recordsProcessed", error_summary AS "errorSummary"
        FROM feed_runs ORDER BY feed, started_at DESC`)
    ]);

    const row = counts.rows[0] ?? { open: 0, p1: 0, p2: 0, cves: 0 };
    return { counts: row, findings: findings.rows, feeds: feeds.rows };
  }
}
