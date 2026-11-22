import Fastify from 'fastify';
import cors from '@fastify/cors';
import fastifyStatic from '@fastify/static';
import cron from 'node-cron';
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

const config = loadConfig();
const app = Fastify({ logger: { level: config.LOG_LEVEL, redact: ['req.headers.authorization', 'client_secret', 'CROWDSTRIKE_CLIENT_SECRET'] } });
const db = createPool(config.DATABASE_URL);
const crowdStrike = new CrowdStrikeConnector(config);
const correlation = new CorrelationService(db, crowdStrike, config);
const feeds = new FeedService(db, correlation);
const nvd = new NvdConnector(config);
const cves = new CveIngestionService(db, config, correlation, nvd);

await app.register(cors, { origin: config.NODE_ENV === 'development' ? true : false });
await registerApiRoutes(app, { db, crowdStrike, feeds, cves });

if (config.NODE_ENV === 'production') {
  const publicDirectory = join(fileURLToPath(new URL('.', import.meta.url)), '../../public');
  await app.register(fastifyStatic, { root: publicDirectory, wildcard: false });
  app.get('/*', async (_request, reply) => reply.sendFile('index.html'));
}

if (config.ENABLE_SCHEDULERS) {
  cron.schedule(config.KEV_CRON, () => void feeds.syncKev().catch((error) => app.log.error(error, 'CISA KEV sync failed')));
  cron.schedule(config.EPSS_CRON, () => void feeds.refreshEpss().catch((error) => app.log.error(error, 'EPSS refresh failed')));
  if (config.CVE_REPO_PATH) cron.schedule(config.CVE_CRON, () => void cves.sync().catch((error) => app.log.error(error, 'CVE List V5 sync failed')));
}

const close = async () => { await app.close(); await db.end(); };
process.on('SIGINT', () => void close());
process.on('SIGTERM', () => void close());

await app.listen({ host: config.HOST, port: config.PORT });
