import { test } from 'bun:test';
import assert from 'node:assert/strict';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { migrate } from '../src/db.mjs';

const migrationsDir = join(dirname(fileURLToPath(import.meta.url)), '../../../db/migrations');

function createMigrationPool() {
  const applied = new Set();
  const migrationStatements = [];
  const calls = [];
  return {
    migrationStatements,
    calls,
    async query(sql, parameters = []) {
      calls.push({ sql, parameters });
      if (sql.startsWith('SELECT 1 FROM schema_migrations')) {
        return { rows: applied.has(parameters[0]) ? [{ exists: 1 }] : [] };
      }
      if (sql.startsWith('INSERT INTO schema_migrations')) {
        applied.add(parameters[0]);
        return { rows: [] };
      }
      if (sql.includes('CREATE TABLE IF NOT EXISTS accounts')) {
        migrationStatements.push(sql);
      }
      return { rows: [] };
    }
  };
}

test('migrations apply once and the second run is a no-op', async () => {
  const pool = createMigrationPool();

  await migrate(pool, migrationsDir);
  await migrate(pool, migrationsDir);

  // One migration statement count per migration file actually present under
  // db/migrations/ (currently 001_initial.sql, 002_auth_sessions_and_rate_limit.sql,
  // and 003_sync.sql, ADR-0006 §8 / B05); only 001 creates the `accounts`
  // table this pool's fake tracks specifically.
  assert.equal(pool.migrationStatements.length, 1);
  assert.equal(
    pool.calls.filter(({ sql }) => sql.startsWith('INSERT INTO schema_migrations')).length,
    3
  );
  assert.equal(pool.calls.filter(({ sql }) => sql === 'BEGIN').length, 3);
  assert.equal(pool.calls.filter(({ sql }) => sql === 'COMMIT').length, 3);
});
