// RUST-04: backup restore rehearsal on a disposable database, using the
// existing, unmodified production scripts (`infra/backup.sh`,
// `infra/restore.sh` — read-only reference, not edited by this task)
// against a database populated entirely through the real Rust binary. This
// proves the existing backup/restore tooling needs no Rust-specific
// changes, because RUST-02/03 kept the on-disk schema byte-identical to
// the Bun reference's `db/migrations/`.
//
// pg_dump/pg_restore must match the server's major version exactly (a
// version-14 host `pg_dump` refuses to talk to a version-16 server, as
// this rehearsal itself discovered while it was being written). Rather
// than requiring a matching client toolchain on every machine that runs
// this suite, the scripts are executed *inside* a `postgres:16-alpine`
// container attached to the same disposable Docker network as the test
// PostgreSQL server — exactly the version the disposable server itself
// runs, and the same "docker exec"-adjacent shape `infra/backup.sh`
// documents for a real VPS deployment (private database, no host client
// tooling required).
//
// Never touches production: the network, container name and BACKUP_DIR are
// always disposable/throwaway; DATABASE_URL always targets a freshly
// created scratch database dropped at the end of the test.
//
// Gated behind RUST04_E2E=1 + RUST04_TEST_DATABASE_URL + RUST04_BACKUP_RESTORE=1
// (an extra explicit gate: this shells out to `docker run`) and
// RUST04_PG_NETWORK / RUST04_PG_HOST identifying the disposable Postgres
// container's Docker network and in-network hostname.

import { expect, test } from "bun:test";
import { spawn } from "node:child_process";
import { mkdtemp, readdir, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createPool } from "../../apps/backend/src/db.mjs";
import { ApiClient } from "../../packages/sdk/src/http-client.ts";
import { AuthClient } from "../../packages/sdk/src/auth-client.ts";
import { createWasmOpaqueClient } from "../../packages/sdk/src/opaque-client.ts";
import { RUST04_E2E, TEST_DATABASE_URL, createScratchDatabase, freePort, migrate, spawnBackend } from "./helpers.ts";

const pgNetwork = process.env.RUST04_PG_NETWORK;
const pgHost = process.env.RUST04_PG_HOST;
const enabled =
  RUST04_E2E && !!TEST_DATABASE_URL && process.env.RUST04_BACKUP_RESTORE === "1" && !!pgNetwork && !!pgHost;
const e2eTest = enabled ? test : test.skip;

const INFRA_DIR = new URL("../../infra", import.meta.url).pathname;

function run(command: string, args: string[]): Promise<{ code: number; out: string }> {
  return new Promise((resolve, reject) => {
    const child = spawn(command, args);
    let out = "";
    child.stdout.on("data", (c) => (out += c.toString()));
    child.stderr.on("data", (c) => (out += c.toString()));
    child.on("error", reject);
    child.on("close", (code) => resolve({ code: code ?? -1, out }));
  });
}

function dbNameFromUrl(url: string): string {
  return new URL(url).pathname.slice(1);
}

e2eTest(
  "infra/backup.sh and infra/restore.sh (unmodified) round-trip a Rust-populated database",
  async () => {
    const source = await createScratchDatabase("backup_src");
    const dir = await mkdtemp(join(tmpdir(), "rust04-backup-"));
    let restoreDbName: string | undefined;
    try {
      await migrate(source.url);
      const port = await freePort();
      const backend = await spawnBackend(source.url, { port });
      const accountId = `rust04-backup-${Date.now()}`;
      try {
        const api = new ApiClient({ baseUrl: backend.baseUrl });
        const auth = new AuthClient(api, await createWasmOpaqueClient());
        const password = new TextEncoder().encode("rust04-backup-rehearsal-password");
        await auth.register(accountId, password);
        await auth.login(accountId, password);
        await api.registerDevice("RUST-04 backup rehearsal device", new Uint8Array([7, 7, 7]));
      } finally {
        await backend.stop();
      }

      const sourceDbName = dbNameFromUrl(source.url);
      const backupResult = await run("docker", [
        "run",
        "--rm",
        "--network",
        pgNetwork!,
        "-v",
        `${INFRA_DIR}:/infra:ro`,
        "-v",
        `${dir}:/out`,
        "-e",
        `DATABASE_URL=postgres://postgres@${pgHost}:5432/${sourceDbName}`,
        "-e",
        "BACKUP_DIR=/out",
        "postgres:16-alpine",
        "bash",
        "/infra/backup.sh",
      ]);
      expect(backupResult.code).toBe(0);

      const dumpFiles = (await readdir(dir)).filter((f) => f.endsWith(".dump"));
      expect(dumpFiles.length).toBe(1);
      const dumpFile = dumpFiles[0];

      restoreDbName = `rust04_backup_dst_${process.pid}_${Date.now()}`;
      const admin = createPool({ databaseUrl: TEST_DATABASE_URL, databaseSsl: false });
      await admin.query(`CREATE DATABASE ${restoreDbName}`);
      await admin.end();

      const restoreResult = await run("docker", [
        "run",
        "--rm",
        "--network",
        pgNetwork!,
        "-v",
        `${INFRA_DIR}:/infra:ro`,
        "-v",
        `${dir}:/out:ro`,
        "-e",
        `DATABASE_URL=postgres://postgres@${pgHost}:5432/${restoreDbName}`,
        "postgres:16-alpine",
        "bash",
        "/infra/restore.sh",
        "--dump",
        `/out/${dumpFile}`,
      ]);
      expect(restoreResult.code).toBe(0);

      const restoreDbUrl = TEST_DATABASE_URL!.replace(/\/[^/]*$/, `/${restoreDbName}`);
      const restored = createPool({ databaseUrl: restoreDbUrl, databaseSsl: false });
      try {
        const { rows: accountRows } = await restored.query(
          "SELECT count(*)::int AS count FROM accounts WHERE account_id = $1",
          [accountId],
        );
        expect(accountRows[0].count).toBe(1);
        const { rows: deviceRows } = await restored.query("SELECT count(*)::int AS count FROM devices");
        expect(deviceRows[0].count).toBeGreaterThan(0);
      } finally {
        await restored.end();
      }
    } finally {
      await rm(dir, { recursive: true, force: true });
      await source.drop();
      if (restoreDbName) {
        const admin = createPool({ databaseUrl: TEST_DATABASE_URL, databaseSsl: false });
        await admin.query(`DROP DATABASE IF EXISTS ${restoreDbName}`).catch(() => {});
        await admin.end();
      }
    }
  },
  60_000,
);
