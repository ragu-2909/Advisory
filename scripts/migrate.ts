import { readdir, readFile } from 'node:fs/promises';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { loadConfig } from '../src/config.js';
import { createPool } from '../src/db/pool.js';

const config = loadConfig();
const pool = createPool(config.DATABASE_URL);
const migrationsDirectory = fileURLToPath(new URL('../migrations', import.meta.url));

await pool.query(`
  CREATE TABLE IF NOT EXISTS schema_migrations (
    name text PRIMARY KEY,
    applied_at timestamptz NOT NULL DEFAULT now()
  )
`);

const files = (await readdir(migrationsDirectory)).filter((file) => file.endsWith('.sql')).sort();
for (const file of files) {
  const alreadyApplied = await pool.query('SELECT 1 FROM schema_migrations WHERE name = $1', [file]);
  if (alreadyApplied.rowCount) continue;

  const sql = await readFile(join(migrationsDirectory, file), 'utf8');
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    await client.query(sql);
    await client.query('INSERT INTO schema_migrations(name) VALUES ($1)', [file]);
    await client.query('COMMIT');
    process.stdout.write(`Applied ${file}\n`);
  } catch (error) {
    await client.query('ROLLBACK');
    throw error;
  } finally {
    client.release();
  }
}

await pool.end();
