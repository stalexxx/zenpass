import { loadConfig } from './config.mjs';
import { createPool, migrate } from './db.mjs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const pool = createPool(loadConfig());
const migrationsDir = join(dirname(fileURLToPath(import.meta.url)), '../../../db/migrations');
try { await migrate(pool, migrationsDir); } finally { if (pool) await pool.end(); }
