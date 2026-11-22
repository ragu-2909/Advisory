import type { FastifyInstance } from 'fastify';
import { z } from 'zod';
import { inventories, importInventory, sourceName } from '../services/workspace-settings.js';
import type { DatabasePool } from '../db/pool.js';
import type { CrowdStrikeConnector } from '../connectors/crowdstrike.js';
import type { FeedService } from '../services/feed-service.js';
import { DashboardService } from '../services/dashboard-service.js';
import type { CveIngestionService } from '../services/cve-ingestion-service.js';
import type { AssessmentService } from '../services/assessment.js';
import { cveIdPattern, fetchCveDelta } from '../connectors/cve-feed.js';

const crowdStrikeSearchSchema = z.object({
  name: z.string().min(1).max(200),
  vendor: z.string().max(200).optional(),
  versions: z.array(z.string().max(100)).max(100).optional(),
  architectures: z.array(z.string().max(50)).max(20).optional(),
  limit: z.number().int().min(1).max(10_000).optional()
});

const claimSchema = z.object({
  consumerId: z.string().min(1).max(100),
  maxItems: z.number().int().min(1).max(100).default(50),
  leaseSeconds: z.number().int().min(30).max(3600).default(300)
});

export async function registerApiRoutes(
  app: FastifyInstance,
  dependencies: { db: DatabasePool; crowdStrike: CrowdStrikeConnector; feeds: FeedService; cves: CveIngestionService; assessments: AssessmentService }
) {
  const dashboard = new DashboardService(dependencies.db);
  app.addContentTypeParser('application/octet-stream', { parseAs:'buffer', bodyLimit: 4*1024*1024 }, (_req, body, done) => done(null, body));
  app.get('/api/v1/inventories', async () => (await inventories()).map(f => ({ name:f.name, updated:f.updated, rows:f.rows.length })));
  app.put<{ Params:{name:string} }>('/api/v1/inventories/:name', async (req, reply) => {
    if (!sourceName.safeParse(req.params.name).success || !Buffer.isBuffer(req.body)) return reply.code(400).send({message:'Supply an inventory name and an XLSX workbook.'});
    try { return await importInventory(req.params.name,req.body); }
    catch { return reply.code(400).send({message:'Could not import XLSX. Check the first sheet, required columns, and row limit.'}); }
  });
  app.get<{Params:{id:string}}>('/api/v1/assessments/:id/email', async (req, reply) => {
    const run = dependencies.assessments.get(req.params.id);
    if (!run) return reply.code(404).send({message:'Assessment expired or unknown.'});
    if (!run.done) return reply.code(202).send({status:'Running'});
    return run.email;
  });
  app.get<{Params:{id:string}}>('/api/v1/alerts/:id/email', async (req, reply) => {
    if (!z.string().uuid().safeParse(req.params.id).success) return reply.code(400).send({message:'Invalid alert ID'});
    const result = await dependencies.db.query('SELECT subject,mail_body AS body FROM alerts WHERE id=$1',[req.params.id]);
    return result.rows[0] ?? reply.code(404).send({message:'Unknown alert'});
  });

  for (const path of ['/health', '/api/v1/health']) app.get(path, async () => {
    await dependencies.db.query('SELECT 1');
    return { status: 'ok', time: new Date().toISOString() };
  });

  app.get('/api/v1/dashboard/overview', async () => dashboard.overview());
  app.get('/api/v1/cve-feed', async () => fetchCveDelta());
  app.get('/api/v1/dashboard/assets', async () => (await dependencies.db.query(
    `SELECT m.cve_id AS "cveId", m.application_name AS product, m.installed_version AS version,
       COALESCE(h.hostname,m.host_id) AS host, m.observed_at AS "observedAt"
     FROM application_matches m LEFT JOIN hosts h ON h.source=m.source AND h.host_id=m.host_id
     ORDER BY m.observed_at DESC LIMIT 100`)).rows);
  app.get('/api/v1/dashboard/deliveries', async () => (await dependencies.db.query(
    `SELECT a.cve_id AS "cveId", d.consumer_id AS consumer, d.status, d.attempts, d.created_at AS "createdAt"
     FROM alert_deliveries d JOIN alerts a ON a.id=d.alert_id ORDER BY d.created_at DESC LIMIT 100`)).rows);
  app.post('/api/v1/assessments', async (request, reply) => {
    const input = z.object({ cveId: z.string().trim().toUpperCase().regex(cveIdPattern) }).safeParse(request.body);
    if (!input.success) return reply.code(400).send({ message: 'Enter a valid CVE ID.' });
    const run = dependencies.assessments.start(input.data.cveId);
    if (!run) return reply.code(409).send({ message: 'An assessment is already running.' });
    return reply.code(202).send(run);
  });
  app.get<{ Params: { id: string } }>('/api/v1/assessments/:id', async (request, reply) => {
    const run = dependencies.assessments.get(request.params.id);
    return run ?? reply.code(404).send({ message: 'Assessment expired or the service restarted.' });
  });

  app.get('/api/v1/connectors', async () => ({
    crowdStrike: {
      configured: dependencies.crowdStrike.configured,
      region: new URL(dependencies.crowdStrike.baseUrl).hostname,
      baseUrl: dependencies.crowdStrike.baseUrl,
      strategy: 'TARGETED_APPLICATION_LOOKUP'
    },
    postgresql: { configured: true },
    cisaKev: { configured: true },
    epss: { configured: true }
  }));
  app.post('/api/v1/connectors/crowdstrike/check', async (_request, reply) => {
    try { return await dependencies.crowdStrike.checkAuthentication(); }
    catch (error) {
      return reply.code(502).send({ message: error instanceof Error ? error.message : 'Falcon authentication check failed.' });
    }
  });

  app.post('/api/v1/crowdstrike/applications/search', async (request, reply) => {
    const parsed = crowdStrikeSearchSchema.safeParse(request.body);
    if (!parsed.success) return reply.code(400).send({ error: 'VALIDATION_ERROR', details: parsed.error.flatten() });
    if (!dependencies.crowdStrike.configured) return reply.code(503).send({ error: 'CROWDSTRIKE_NOT_CONFIGURED' });
    const results = await dependencies.crowdStrike.searchApplications(parsed.data);
    return { state: results.length ? 'MATCHED' : 'NOT_FOUND_IN_CROWDSTRIKE', count: results.length, results };
  });

  app.post('/api/v1/feeds/cisa-kev/sync', async () => dependencies.feeds.syncKev());
  app.post('/api/v1/feeds/epss/refresh', async () => dependencies.feeds.refreshEpss());
  app.post('/api/v1/feeds/cve-list/sync', async () => dependencies.cves.sync());

  app.post('/api/v1/alert-deliveries/claim', async (request, reply) => {
    const parsed = claimSchema.safeParse(request.body);
    if (!parsed.success) return reply.code(400).send({ error: 'VALIDATION_ERROR', details: parsed.error.flatten() });
    const { consumerId, maxItems, leaseSeconds } = parsed.data;
    const client = await dependencies.db.connect();
    try {
      await client.query('BEGIN');
      const deliveries = await client.query(
        `SELECT d.id, d.alert_id FROM alert_deliveries d
         WHERE d.consumer_id=$1
           AND (d.status='AVAILABLE' OR (d.status='LEASED' AND d.leased_until < now()))
         ORDER BY d.created_at
         FOR UPDATE SKIP LOCKED LIMIT $2`, [consumerId, maxItems]
      );
      if (!deliveries.rowCount) {
        await client.query('COMMIT');
        return { generatedAt: new Date().toISOString(), items: [] };
      }
      const ids = deliveries.rows.map((row) => row.id);
      const leased = await client.query(
        `UPDATE alert_deliveries d SET status='LEASED', lease_token=gen_random_uuid(),
           leased_until=now()+($2 || ' seconds')::interval, attempts=attempts+1
         FROM alerts a WHERE d.id=ANY($1::uuid[]) AND a.id=d.alert_id
         RETURNING d.id AS "deliveryId", d.lease_token AS "leaseToken", d.leased_until AS "leasedUntil",
           a.id AS "alertId", a.subject, a.executive_summary AS "executiveSummary", a.mail_body AS body,
           a.priority, a.cve_id AS "cveId", a.decision_trace AS "decisionTrace"`, [ids, leaseSeconds]
      );
      await client.query('COMMIT');
      return { generatedAt: new Date().toISOString(), items: leased.rows };
    } catch (error) {
      await client.query('ROLLBACK');
      throw error;
    } finally {
      client.release();
    }
  });

  app.post('/api/v1/alert-deliveries/:deliveryId/ack', async (request, reply) => {
    const params = z.object({ deliveryId: z.string().uuid() }).safeParse(request.params);
    const body = z.object({ leaseToken: z.string().uuid() }).safeParse(request.body);
    if (!params.success || !body.success) return reply.code(400).send({ error: 'VALIDATION_ERROR' });
    const result = await dependencies.db.query(
      `UPDATE alert_deliveries SET status='ACKNOWLEDGED', acknowledged_at=now()
       WHERE id=$1 AND lease_token=$2 AND status='LEASED' RETURNING id`,
      [params.data.deliveryId, body.data.leaseToken]
    );
    if (!result.rowCount) return reply.code(409).send({ error: 'LEASE_NOT_ACTIVE' });
    return { acknowledged: true };
  });
}
