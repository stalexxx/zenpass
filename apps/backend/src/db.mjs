import { readFile, readdir } from 'node:fs/promises';
import { join } from 'node:path';
import { Pool } from 'pg';

export function createPool(config) {
  if (!config.databaseUrl) return null;
  return new Pool({ connectionString: config.databaseUrl, ssl: config.databaseSsl ? { rejectUnauthorized: true } : undefined, max: 10 });
}

export async function checkDatabase(pool) {
  if (!pool) return false;
  try { await pool.query('SELECT 1'); return true; } catch { return false; }
}

export async function migrate(pool, migrationsDir = join(process.cwd(), 'db', 'migrations')) {
  if (!pool) throw new Error('DATABASE_URL is required to run migrations');
  await pool.query('CREATE TABLE IF NOT EXISTS schema_migrations (version text PRIMARY KEY, applied_at timestamptz NOT NULL DEFAULT now())');
  const files = (await readdir(migrationsDir)).filter((f) => f.endsWith('.sql')).sort();
  for (const file of files) {
    const version = file.split('_', 1)[0];
    const { rows } = await pool.query('SELECT 1 FROM schema_migrations WHERE version = $1', [version]);
    if (rows.length) continue;
    const sql = await readFile(join(migrationsDir, file), 'utf8');
    await pool.query('BEGIN');
    try { await pool.query(sql); await pool.query('INSERT INTO schema_migrations(version) VALUES ($1)', [version]); await pool.query('COMMIT'); }
    catch (error) { await pool.query('ROLLBACK'); throw error; }
  }
}
