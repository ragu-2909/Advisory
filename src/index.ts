import Fastify from 'fastify';
import cors from '@fastify/cors';
import fastifyStatic from '@fastify/static';
import cron from 'node-cron';
import { z } from 'zod';
import { readSetting, saveSetting } from './services/workspace-settings.js';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { loadConfig } from './config.js';
import { createPool } from './db/pool.js';
import { CrowdStrikeConnector } from './connectors/crowdstrike.js';
import { FeedService } from './services/feed-service.js';
import { registerApiRoutes } from './routes/api.js';
import { CorrelationService } from './services/correlation-service.js';
import { CveIngestionService } from './services/cve-ingestion-service.js';
import { NvdConnector } from './connectors/nvd.js';
import { AssessmentService } from './services/assessment.js';

const config = loadConfig();
const app = Fastify({ logger: { level: config.LOG_LEVEL, redact: ['req.headers.authorization', 'client_secret', 'CROWDSTRIKE_CLIENT_SECRET'] } });
const db = createPool(config.DATABASE_URL);
const crowdStrike = new CrowdStrikeConnector(config);
const correlation = new CorrelationService(db, crowdStrike, config);
const feeds = new FeedService(db, correlation);
const nvd = new NvdConnector(config);
const cves = new CveIngestionService(db, config, correlation, nvd);

await app.register(cors, { origin: config.NODE_ENV === 'development' ? true : false });
await registerApiRoutes(app, { db, crowdStrike, feeds, cves, assessments: new AssessmentService(crowdStrike, nvd) });

if (config.NODE_ENV === 'production') {
  const publicDirectory = join(fileURLToPath(new URL('.', import.meta.url)), '../../public');
  await app.register(fastifyStatic, { root: publicDirectory, wildcard: false });
  app.get('/*', async (_request, reply) => reply.sendFile('index.html'));
}

const jobs = { cve: () => cves.sync(), kev: () => feeds.syncKev(), epss: () => feeds.refreshEpss() };
const schedule = z.object({ enabled:z.boolean(), expression:z.string().refine(value => cron.validate(value)) });
const schema = z.object({ cve:schedule, kev:schedule, epss:schedule });
let schedules = schema.parse(await readSetting('schedules', Object.fromEntries(
  Object.entries({cve:config.CVE_CRON, kev:config.KEV_CRON, epss:config.EPSS_CRON}).map(([key,expression]) => [key,{enabled:config.ENABLE_SCHEDULERS,expression}]))));
let tasks: ReturnType<typeof cron.schedule>[] = [];
function applySchedules() {
  for (const task of tasks) task.destroy();
  tasks = [];
  for (const key of Object.keys(jobs) as (keyof typeof jobs)[]) {
    const rule = schedules[key];
    if (rule.enabled) tasks.push(cron.schedule(rule.expression, async () => {
      try { await jobs[key](); } catch (error) { app.log.error(error, key + ' sync failed'); }
    }, {noOverlap:true}));
  }
}
applySchedules();
app.get('/api/v1/settings/schedules', async () => schedules);
app.put('/api/v1/settings/schedules', async (req,reply) => {
  const parsed = schema.safeParse(req.body);
  if (!parsed.success) return reply.code(400).send({message:'Enter valid cron expressions for each feed.'});
  await saveSetting('schedules',parsed.data);
  schedules = parsed.data;
  applySchedules();
  return schedules;
});

const close = async () => { await app.close(); await db.end(); };
process.on('SIGINT', () => void close());
process.on('SIGTERM', () => void close());

await app.listen({ host: config.HOST, port: config.PORT });
