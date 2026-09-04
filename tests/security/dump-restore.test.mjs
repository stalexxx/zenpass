import { expect, test } from "bun:test";
import { randomUUID } from "node:crypto";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createPool } from "../../apps/backend/src/db.mjs";

const databaseUrl = process.env.TEST_DATABASE_URL;
const dumpEnabled = process.env.Q01_DUMP_INSPECTION === "1";
const restoreEnabled = process.env.Q01_BACKUP_RESTORE === "1";
const pgDump = process.env.Q01_PG_DUMP ?? "pg_dump";
const pgRestore = process.env.Q01_PG_RESTORE ?? "pg_restore";

async function run(command, args) {
  const child = Bun.spawn([command, ...args], { stdout: "pipe", stderr: "pipe" });
  const [exitCode, stdout, stderr] = await Promise.all([
    child.exited,
    new Response(child.stdout).text(),
    new Response(child.stderr).text(),
  ]);
  if (exitCode !== 0) throw new Error(`${command} failed (${exitCode}): ${stderr || stdout}`);
  return stdout;
}

function urlForDatabase(database) {
  const url = new URL(databaseUrl);
  url.pathname = `/${database}`;
  return url.toString();
}

if ((dumpEnabled || restoreEnabled) && !databaseUrl) {
  test("Q01 dump/restore configuration requires TEST_DATABASE_URL", () => {
    throw new Error("Q01_DUMP_INSPECTION=1 or Q01_BACKUP_RESTORE=1 requires TEST_DATABASE_URL.");
  });
}

(dumpEnabled && databaseUrl ? test : test.skip)("database dump contains opaque schema/data and no configured plaintext canary", async () => {
  const dump = await run(pgDump, ["--no-owner", "--no-privileges", "--dbname", databaseUrl]);
  expect(dump).toContain("vault_items");
  // CI may provide known test-only forbidden terms through this explicit
  // gate. The harness never supplies or persists vault plaintext itself.
  for (const forbidden of (process.env.Q01_DUMP_FORBIDDEN_TERMS ?? "Q01_NOT_PERSISTED_VAULT_PLAINTEXT").split(",")) {
    if (forbidden) expect(dump).not.toContain(forbidden);
  }
}, 30_000);

(restoreEnabled && databaseUrl ? test : test.skip)("backup restore preserves opaque records, revisions, and tombstones in an isolated database", async () => {
  const source = createPool({ databaseUrl, databaseSsl: false });
  const suffix = randomUUID().replaceAll("-", "");
  const accountId = `q01_backup_${suffix}`;
  const vaultId = `q01_vault_${suffix}`;
  const itemId = `q01_item_${suffix}`;
  const restoreDb = `q01_restore_${suffix.slice(0, 12)}`;
  const admin = createPool({ databaseUrl: urlForDatabase("postgres"), databaseSsl: false });
  const dir = await mkdtemp(join(tmpdir(), "zkpm-q01-backup-"));
  const backup = join(dir, "vault.dump");
  try {
    await source.query("INSERT INTO accounts (account_id) VALUES ($1)", [accountId]);
    await source.query("INSERT INTO vaults (vault_id, account_id) VALUES ($1, $2)", [vaultId, accountId]);
    await source.query(
      "INSERT INTO vault_items (vault_id, item_id, ciphertext, envelope_version, revision, deleted) VALUES ($1, $2, decode($3, 'base64'), $4, $5, $6)",
      [vaultId, itemId, "AAECAwQFBgc=", "crypto-envelope/v1", 7, true],
    );
    await run(pgDump, ["--format=custom", "--no-owner", "--no-privileges", "--file", backup, "--dbname", databaseUrl]);
    await admin.query(`CREATE DATABASE ${restoreDb}`);
    await run(pgRestore, ["--no-owner", "--no-privileges", "--dbname", urlForDatabase(restoreDb), backup]);
    const restored = createPool({ databaseUrl: urlForDatabase(restoreDb), databaseSsl: false });
    try {
      const { rows } = await restored.query(
        "SELECT encode(ciphertext, 'base64') AS ciphertext, revision, deleted FROM vault_items WHERE vault_id = $1 AND item_id = $2",
        [vaultId, itemId],
      );
      expect(rows).toHaveLength(1);
      expect(rows[0]).toMatchObject({ ciphertext: "AAECAwQFBgc=", revision: "7", deleted: true });
    } finally {
      await restored.end();
    }
  } finally {
    await source.query("DELETE FROM vault_items WHERE vault_id = $1", [vaultId]).catch(() => {});
    await source.query("DELETE FROM vaults WHERE vault_id = $1", [vaultId]).catch(() => {});
    await source.query("DELETE FROM accounts WHERE account_id = $1", [accountId]).catch(() => {});
    await source.end();
    await admin.query(`DROP DATABASE IF EXISTS ${restoreDb} WITH (FORCE)`).catch(() => {});
    await admin.end();
    await rm(dir, { recursive: true, force: true });
  }
}, 60_000);
