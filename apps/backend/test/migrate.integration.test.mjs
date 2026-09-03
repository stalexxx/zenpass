import { test } from 'bun:test';
import assert from 'node:assert/strict';
import { mkdtemp, readdir, rm, writeFile } from 'node:fs/promises';
import { dirname, join } from 'node:path';
import { tmpdir } from 'node:os';
import { fileURLToPath } from 'node:url';
import { createPool, migrate } from '../src/db.mjs';

const migrationsDir = join(dirname(fileURLToPath(import.meta.url)), '../../../db/migrations');
const integrationTest = process.env.TEST_DATABASE_URL ? test : test.skip;

integrationTest('PostgreSQL migrations are repeatable and record versions atomically', async () => {
  const pool = createPool({ databaseUrl: process.env.TEST_DATABASE_URL, databaseSsl: false });
  const temporaryMigrationsDir = await mkdtemp(join(tmpdir(), 'zkpm-b02-migrations-'));
  try {
    const expectedVersions = (await readdir(migrationsDir))
      .filter((file) => file.endsWith('.sql'))
      .sort()
      .map((file) => file.split('_', 1)[0]);

    await migrate(pool, migrationsDir);
    await migrate(pool, migrationsDir);

    const { rows } = await pool.query('SELECT version FROM schema_migrations ORDER BY version');
    assert.deepEqual(rows.map(({ version }) => version), expectedVersions);

    await writeFile(
      join(temporaryMigrationsDir, '999_failure.sql'),
      'CREATE TABLE b02_atomicity_probe (id integer); SELECT missing_column FROM b02_atomicity_probe;'
    );
    await assert.rejects(() => migrate(pool, temporaryMigrationsDir));

    const failedVersion = await pool.query(
      'SELECT version FROM schema_migrations WHERE version = $1',
      ['999']
    );
    assert.deepEqual(failedVersion.rows, []);
  } finally {
    await rm(temporaryMigrationsDir, { recursive: true, force: true });
    await pool.end();
  }
});
