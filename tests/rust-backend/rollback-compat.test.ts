// RUST-04: the "old-server rollback drill" required by docs/tasks/RUST-04.md
// — proves that an already-logged-in session survives a real cutover or
// rollback between the Bun and Rust backends on the *same* database,
// without forcing every connected client to re-authenticate.
//
// This is possible only because both backends store sessions identically:
// a 32-byte CSPRNG token, base64url (no padding) encoded, with only its
// SHA-256 hash persisted (apps/backend/src/auth/sessions.mjs `hashToken`;
// apps/backend-rust/src/auth/sessions.rs, confirmed byte-for-byte
// equivalent in the RUST-03 report's Security considerations). Nothing here
// asserts that by inspection alone — both directions are driven end to end
// against a real disposable PostgreSQL database.
//
// Direction A (rollback): register+login via the real Rust binary, obtain
// a bearer token, stop Rust, start the Bun backend in-process on the SAME
// database, and use that Rust-issued token against a Bun-authenticated
// route. Direction B (forward cutover): the mirror image — register+login
// via Bun, then use that Bun-issued token against the real Rust binary.
//
// Gated behind RUST04_E2E=1 + RUST04_TEST_DATABASE_URL, same as
// client-e2e.test.ts.

import { expect, test } from "bun:test";
import { randomBytes, randomUUID } from "node:crypto";
import { buildApp } from "../../apps/backend/src/app.mjs";
import { createPool } from "../../apps/backend/src/db.mjs";
import { ApiClient } from "../../packages/sdk/src/http-client.ts";
import { AuthClient } from "../../packages/sdk/src/auth-client.ts";
import { createWasmOpaqueClient } from "../../packages/sdk/src/opaque-client.ts";
import { RUST04_E2E, TEST_DATABASE_URL, createScratchDatabase, freePort, migrate, spawnBackend } from "./helpers.ts";

const enabled = RUST04_E2E && !!TEST_DATABASE_URL;
const e2eTest = enabled ? test : test.skip;

const bunConfig = Object.freeze({
  nodeEnv: "test",
  logLevel: "silent",
  requestIdHeader: "x-request-id",
  opaqueServerSetup: null,
  sessionTtlSeconds: 900,
  authRateLimitMax: 1000,
  authRateLimitWindowSeconds: 300,
});

async function withBunApp(databaseUrl: string, fn: (baseUrl: string) => Promise<void>) {
  const pool = createPool({ databaseUrl, databaseSsl: false });
  const app = buildApp(bunConfig, { pool });
  await app.listen({ port: 0, host: "127.0.0.1" });
  const address = app.server.address();
  const port = typeof address === "object" && address ? address.port : 0;
  try {
    await fn(`http://127.0.0.1:${port}`);
  } finally {
    await app.close();
  }
}

e2eTest(
  "rollback: a Rust-issued bearer session is accepted by the Bun backend on the same database",
  async () => {
    const db = await createScratchDatabase("rollback_a");
    await migrate(db.url);
    try {
      const accountId = `rust04-rb-${randomUUID()}`;
      const password = randomBytes(32);

      const port = await freePort();
      const rust = await spawnBackend(db.url, { port });
      let token: string;
      try {
        const api = new ApiClient({ baseUrl: rust.baseUrl });
        const auth = new AuthClient(api, await createWasmOpaqueClient());
        await auth.register(accountId, password);
        const session = await auth.login(accountId, password);
        token = session.accessToken;
      } finally {
        await rust.stop();
      }

      // Rust is fully stopped; the Bun backend now serves the same
      // database with the token minted by Rust.
      await withBunApp(db.url, async (bunBaseUrl) => {
        const response = await fetch(`${bunBaseUrl}/devices`, {
          headers: { Authorization: `Bearer ${token}` },
        });
        expect(response.status).toBe(200);
        const body = await response.json();
        expect(Array.isArray(body.devices)).toBe(true);
      });
    } finally {
      await db.drop();
    }
  },
  30_000,
);

e2eTest(
  "forward cutover: a Bun-issued bearer session is accepted by the real Rust binary on the same database",
  async () => {
    const db = await createScratchDatabase("rollback_b");
    await migrate(db.url);
    try {
      const accountId = `rust04-rb-${randomUUID()}`;
      const password = randomBytes(32);

      let token: string;
      await withBunApp(db.url, async (bunBaseUrl) => {
        const api = new ApiClient({ baseUrl: bunBaseUrl });
        const auth = new AuthClient(api, await createWasmOpaqueClient());
        await auth.register(accountId, password);
        const session = await auth.login(accountId, password);
        token = session.accessToken;
      });

      // Bun is fully stopped (withBunApp closed it); Rust now serves the
      // same database with the token minted by Bun.
      const port = await freePort();
      const rust = await spawnBackend(db.url, { port });
      try {
        const response = await fetch(`${rust.baseUrl}/devices`, {
          headers: { Authorization: `Bearer ${token!}` },
        });
        expect(response.status).toBe(200);
        const body = await response.json();
        expect(Array.isArray(body.devices)).toBe(true);
      } finally {
        await rust.stop();
      }
    } finally {
      await db.drop();
    }
  },
  30_000,
);
