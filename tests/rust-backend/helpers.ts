// RUST-04: shared helpers for exercising the real `zkpm-backend` binary
// (apps/backend-rust) as a subprocess, driven over real HTTP by the same
// SDK code (packages/sdk) and real WASM crypto (packages/crypto-wasm) that
// the actual web/extension/desktop clients ship. This is deliberately not
// an in-process `app()` call (that only proves the Rust HTTP layer wiring,
// already covered by apps/backend-rust/tests/product.rs) — spawning the
// compiled binary and speaking real HTTP is what proves a real client can
// talk to the actual candidate server artifact.
//
// Every test using these helpers requires a dedicated, disposable
// PostgreSQL instance (RUST04_TEST_DATABASE_URL) — never production, never
// the Bun backend's own database. Tests are explicitly gated behind
// RUST04_E2E=1 (mirroring the Q01_E2E gate in tests/e2e) so they never run
// by accident in an environment without Docker/Postgres/a built binary.

import { spawn, type ChildProcessWithoutNullStreams } from "node:child_process";
import { randomUUID } from "node:crypto";

export const RUST04_E2E = process.env.RUST04_E2E === "1";
export const TEST_DATABASE_URL = process.env.RUST04_TEST_DATABASE_URL;

/** Path to the compiled zkpm-backend binary. Defaults to the debug profile
 * built by `cargo build --locked` from apps/backend-rust; override with
 * RUST04_BACKEND_BIN to point at a release build or an extracted container
 * layer's binary. */
export const BACKEND_BIN =
  process.env.RUST04_BACKEND_BIN ??
  new URL("../../apps/backend-rust/target/debug/zkpm-backend", import.meta.url).pathname;

function rewriteDatabase(url: string, database: string): string {
  const u = new URL(url);
  u.pathname = `/${database}`;
  return u.toString();
}

/** Creates a private, uniquely named scratch database on the given disposable
 * server for one test to own exclusively, and returns a function that drops
 * it again. Mirrors apps/backend-rust/tests/product.rs's TestDatabase. */
export async function createScratchDatabase(prefix: string): Promise<{ url: string; drop: () => Promise<void> }> {
  if (!TEST_DATABASE_URL) throw new Error("RUST04_TEST_DATABASE_URL is required");
  const { Pool } = await import("pg");
  // Postgres folds unquoted CREATE DATABASE identifiers to lowercase, but a
  // connection string's dbname is a literal, unfolded string — mixed-case
  // names would create one database and then fail to connect to another.
  // Lowercase everything up front so both sides agree.
  const name = `rust04_${prefix}_${process.pid}_${randomUUID().replaceAll("-", "").slice(0, 12)}`.toLowerCase();
  const admin = new Pool({ connectionString: TEST_DATABASE_URL, max: 2 });
  await admin.query(`CREATE DATABASE ${name}`);
  await admin.end();
  const url = rewriteDatabase(TEST_DATABASE_URL, name);
  return {
    url,
    drop: async () => {
      const cleanup = new Pool({ connectionString: TEST_DATABASE_URL, max: 2 });
      try {
        await cleanup.query(
          `SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname = $1 AND pid <> pg_backend_pid()`,
          [name],
        );
        await cleanup.query(`DROP DATABASE IF EXISTS ${name}`);
      } finally {
        await cleanup.end();
      }
    },
  };
}

function runBin(args: string[], env: Record<string, string>): Promise<{ code: number; stdout: string; stderr: string }> {
  return new Promise((resolve, reject) => {
    const child = spawn(BACKEND_BIN, args, { env: { ...process.env, ...env } });
    let stdout = "";
    let stderr = "";
    child.stdout.on("data", (chunk) => (stdout += chunk.toString()));
    child.stderr.on("data", (chunk) => (stderr += chunk.toString()));
    child.on("error", reject);
    child.on("close", (code) => resolve({ code: code ?? -1, stdout, stderr }));
  });
}

/** Runs `zkpm-backend migrate` to completion against the given database URL. */
export async function migrate(databaseUrl: string, extraEnv: Record<string, string> = {}): Promise<void> {
  const result = await runBin(["migrate"], {
    ZKPM_ENVIRONMENT: "test",
    ZKPM_DATABASE_URL: databaseUrl,
    ZKPM_DATABASE_TLS: "disabled",
    ...extraEnv,
  });
  if (result.code !== 0) {
    throw new Error(`zkpm-backend migrate failed (${result.code}): ${result.stderr || result.stdout}`);
  }
}

export interface RunningBackend {
  baseUrl: string;
  stop: () => Promise<void>;
}

/** Spawns the real compiled `zkpm-backend serve` process against an
 * already-migrated database and waits for `/health/live` to answer. Leaving
 * `opaqueServerSetup` unset (the default) is valid outside production: the
 * server generates one ephemeral value at startup (apps/backend-rust's
 * `Config`/`AuthState`, matching the Bun reference's
 * `loadOrGenerateServerSetup`) — fine for a fresh register+login pair
 * created entirely within one test, since nothing needs to survive a
 * restart with the same value.
 */
export async function spawnBackend(
  databaseUrl: string,
  opts: { port?: number; opaqueServerSetup?: string; extraEnv?: Record<string, string> } = {},
): Promise<RunningBackend> {
  const port = opts.port ?? 0;
  // Port 0 has no meaning for a real bind; callers must supply a free
  // loopback port (see freePort() below) since ZKPM_BIND requires a
  // concrete socket address, not ephemeral-port notation.
  if (port === 0) throw new Error("spawnBackend requires an explicit free port (see freePort())");
  const bind = `127.0.0.1:${port}`;
  const child: ChildProcessWithoutNullStreams = spawn(BACKEND_BIN, ["serve"], {
    env: {
      ...process.env,
      ZKPM_ENVIRONMENT: "test",
      ZKPM_BIND: bind,
      ZKPM_DATABASE_URL: databaseUrl,
      ZKPM_DATABASE_TLS: "disabled",
      ZKPM_OPAQUE_SERVER_SETUP: opts.opaqueServerSetup ?? "",
      ...opts.extraEnv,
    },
  });
  let stderr = "";
  child.stderr.on("data", (chunk) => (stderr += chunk.toString()));
  const baseUrl = `http://${bind}`;

  const deadline = Date.now() + 10_000;
  let ready = false;
  while (Date.now() < deadline) {
    try {
      const response = await fetch(`${baseUrl}/health/live`);
      if (response.ok) {
        ready = true;
        break;
      }
    } catch {
      // not listening yet
    }
    if (child.exitCode !== null) {
      throw new Error(`zkpm-backend exited early (${child.exitCode}): ${stderr}`);
    }
    await new Promise((r) => setTimeout(r, 100));
  }
  if (!ready) {
    child.kill("SIGKILL");
    throw new Error(`zkpm-backend did not become ready within 10s: ${stderr}`);
  }

  return {
    baseUrl,
    stop: () =>
      new Promise((resolve) => {
        child.once("close", () => resolve());
        child.kill("SIGTERM");
        // Bound wait matching the server's own shutdown_timeout default (10s).
        setTimeout(() => {
          if (child.exitCode === null) child.kill("SIGKILL");
        }, 12_000);
      }),
  };
}

/** Finds a free loopback TCP port by binding to port 0 and releasing it.
 * There is an unavoidable, small race between release and the caller's own
 * bind (same technique used by apps/backend-rust/tests/postgres.rs); tests
 * accept this as the standard approach for this kind of harness. */
export async function freePort(): Promise<number> {
  const net = await import("node:net");
  return new Promise((resolve, reject) => {
    const server = net.createServer();
    server.listen(0, "127.0.0.1", () => {
      const address = server.address();
      const port = typeof address === "object" && address ? address.port : 0;
      server.close(() => resolve(port));
    });
    server.on("error", reject);
  });
}
