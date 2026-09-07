// RUST-04: migration-baseline compatibility check driven at the top level
// (real Bun migrate script + real Rust migrate binary, both invoked as
// actual subprocess/module entry points a deploy would use — not just
// RUST-02's internal `postgres.rs` simulation of the same logic).
//
// Two scenarios required by docs/tasks/RUST-04.md:
//  1. A database that already has the legacy Bun history (db/migrations
//     applied via apps/backend/src/migrate.mjs) adopts cleanly into the
//     Rust baseline (`zkpm-backend migrate`) with no DDL replay, and the
//     legacy `schema_migrations` table is preserved so the Bun backend
//     stays deployable afterward (checked by literally running Bun's own
//     migrate script again afterward and confirming it is a no-op).
//  2. A completely fresh database migrated only by the Rust binary ends up
//     schema-compatible with the Bun backend (Bun's migrate script also
//     reports "up to date" against it without erroring).
//
// Gated behind RUST04_E2E=1 + RUST04_TEST_DATABASE_URL.

import { expect, test } from "bun:test";
import { createPool, migrate as bunMigrate } from "../../apps/backend/src/db.mjs";
import { RUST04_E2E, TEST_DATABASE_URL, createScratchDatabase, migrate as rustMigrate } from "./helpers.ts";

const enabled = RUST04_E2E && !!TEST_DATABASE_URL;
const e2eTest = enabled ? test : test.skip;

const LEGACY_MIGRATIONS_DIR = new URL("../../db/migrations", import.meta.url).pathname;

e2eTest(
  "legacy Bun migration history adopts cleanly into the Rust baseline, and the Bun migrator still works afterward",
  async () => {
    const db = await createScratchDatabase("baseline_legacy");
    try {
      const pool = createPool({ databaseUrl: db.url, databaseSsl: false });
      await bunMigrate(pool, LEGACY_MIGRATIONS_DIR);
      const { rows: legacyBefore } = await pool.query("SELECT version FROM schema_migrations ORDER BY version");
      expect(legacyBefore.length).toBeGreaterThan(0);
      await pool.end();

      // Rust adopts the existing legacy history (proves schema equivalence
      // before writing SQLx baseline checksums; see apps/backend-rust's
      // migrate.rs / README "Migration history adoption").
      await rustMigrate(db.url);

      const verifyPool = createPool({ databaseUrl: db.url, databaseSsl: false });
      const { rows: sqlxRows } = await verifyPool.query('SELECT version FROM "_sqlx_migrations" ORDER BY version');
      expect(sqlxRows.length).toBe(legacyBefore.length);
      const { rows: legacyAfter } = await verifyPool.query("SELECT version FROM schema_migrations ORDER BY version");
      // Legacy history preserved unchanged (kept in sync) so the Bun
      // backend is still deployable against this database.
      expect(legacyAfter).toEqual(legacyBefore);

      // The Bun migrator, re-run against a Rust-migrated database, sees
      // every version already recorded and applies nothing new.
      await bunMigrate(verifyPool, LEGACY_MIGRATIONS_DIR);
      const { rows: legacyReRun } = await verifyPool.query("SELECT version FROM schema_migrations ORDER BY version");
      expect(legacyReRun).toEqual(legacyBefore);
      await verifyPool.end();
    } finally {
      await db.drop();
    }
  },
  30_000,
);

e2eTest(
  "a fresh database migrated only by the Rust binary is schema-compatible with the Bun migrator",
  async () => {
    const db = await createScratchDatabase("baseline_fresh");
    try {
      await rustMigrate(db.url);
      const pool = createPool({ databaseUrl: db.url, databaseSsl: false });
      const { rows: before } = await pool.query("SELECT version FROM schema_migrations ORDER BY version");
      expect(before.length).toBeGreaterThan(0);

      // Bun's migrator must recognize every version as already applied
      // (via the legacy schema_migrations table the Rust migrator keeps in
      // sync on a fresh install) and must not attempt to replay any DDL
      // against tables Rust already created.
      await bunMigrate(pool, LEGACY_MIGRATIONS_DIR);
      const { rows: after } = await pool.query("SELECT version FROM schema_migrations ORDER BY version");
      expect(after).toEqual(before);
      await pool.end();
    } finally {
      await db.drop();
    }
  },
  30_000,
);
