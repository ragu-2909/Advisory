import { z } from 'zod';

const envSchema = z.object({
  NODE_ENV: z.enum(['development', 'test', 'production']).default('development'),
  HOST: z.string().default('127.0.0.1'),
  PORT: z.coerce.number().int().positive().default(4100),
  LOG_LEVEL: z.string().default('info'),
  DATABASE_URL: z.string().min(1).default('postgresql://advisory:advisory@localhost:5432/advisory'),
  CROWDSTRIKE_BASE_URL: z.string().url().default('https://api.us-2.crowdstrike.com'),
  CROWDSTRIKE_CLIENT_ID: z.string().optional(),
  CROWDSTRIKE_CLIENT_SECRET: z.string().optional(),
  CROWDSTRIKE_HOST_CACHE_SECONDS: z.coerce.number().int().positive().default(900),
  NVD_API_KEY: z.string().optional(),
  CVE_REPO_PATH: z.string().optional(),
  DEFAULT_ALERT_CONSUMER: z.string().min(1).default('fusion-prod'),
  ENABLE_SCHEDULERS: z.string().default('true').transform((value) => value === 'true'),
  KEV_CRON: z.string().default('*/20 * * * *'),
  EPSS_CRON: z.string().default('15 20 * * *'),
  CVE_CRON: z.string().default('*/10 * * * *')
});

export type AppConfig = z.infer<typeof envSchema>;

export function loadConfig(env: NodeJS.ProcessEnv = process.env): AppConfig {
  return envSchema.parse(env);
}
