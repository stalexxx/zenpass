// C04 E2E: a real, locally-trusted-CA-free HTTPS front for the real
// backend, so browser evidence can include an actual TLS handshake
// against the live API rather than only ever exercising it over plain
// HTTP. Self-signed (openssl, EC P-256, SAN=IP:127.0.0.1) — the same
// shape as infra/generate-selfsigned-cert.sh uses for the real VPS
// deployment, but generated fresh per run into a temp directory, never
// committed.
//
// Gated by two independent preconditions, both checked by the caller
// before this module does any work: a reachable TEST_DATABASE_URL (the
// real backend needs PostgreSQL) and a working local `openssl` binary.
// Neither failure is fatal to the browser evidence run as a whole — the
// caller records an explicit `skipped` reason instead of fabricating
// HTTPS coverage that never happened.
import { spawnSync } from 'node:child_process';
import { mkdtempSync, readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import https from 'node:https';
import http from 'node:http';
import { buildApp } from '../../apps/backend/src/app.mjs';
import { createPool } from '../../apps/backend/src/db.mjs';

export function opensslAvailable() {
  const result = spawnSync('openssl', ['version'], { stdio: 'ignore' });
  return result.status === 0;
}

function generateSelfSignedCert() {
  const dir = mkdtempSync(join(tmpdir(), 'c04-e2e-tls-'));
  const keyPath = join(dir, 'key.pem');
  const certPath = join(dir, 'cert.pem');
  const result = spawnSync(
    'openssl',
    [
      'req', '-x509', '-nodes', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:prime256v1',
      '-keyout', keyPath, '-out', certPath, '-days', '1', '-subj', '/CN=127.0.0.1',
      '-addext', 'subjectAltName=IP:127.0.0.1'
    ],
    { stdio: 'pipe' }
  );
  if (result.status !== 0) {
    throw new Error(`openssl cert generation failed: ${result.stderr?.toString() ?? 'unknown error'}`);
  }
  return { key: readFileSync(keyPath), cert: readFileSync(certPath), certPath };
}

/**
 * Starts the real Fastify app on a loopback-only plain HTTP port, then
 * fronts it with a real TLS-terminating reverse proxy on a second
 * loopback port using a freshly generated self-signed certificate.
 * Returns the HTTPS base URL, the cert path (for a caller that wants to
 * pin/inspect it), and a `close()` that tears both servers and the
 * database pool down.
 */
export async function startHttpsFixture({ databaseUrl }) {
  const { key, cert, certPath } = generateSelfSignedCert();

  const pool = createPool({ databaseUrl, databaseSsl: false });
  const config = Object.freeze({
    nodeEnv: 'test',
    logLevel: 'silent',
    requestIdHeader: 'x-request-id',
    opaqueServerSetup: null,
    sessionTtlSeconds: 900,
    authRateLimitMax: 1000,
    authRateLimitWindowSeconds: 300
  });
  const app = buildApp(config, { pool });
  await app.listen({ port: 0, host: '127.0.0.1' });
  const httpAddress = app.server.address();
  const httpPort = typeof httpAddress === 'object' && httpAddress ? httpAddress.port : 0;

  const proxy = https.createServer({ key, cert }, (req, res) => {
    const upstream = http.request(
      { host: '127.0.0.1', port: httpPort, path: req.url, method: req.method, headers: req.headers },
      (upstreamRes) => {
        res.writeHead(upstreamRes.statusCode ?? 502, upstreamRes.headers);
        upstreamRes.pipe(res);
      }
    );
    upstream.on('error', () => {
      res.writeHead(502);
      res.end();
    });
    req.pipe(upstream);
  });

  await new Promise((resolvePromise, reject) => {
    proxy.once('error', reject);
    proxy.listen(0, '127.0.0.1', resolvePromise);
  });
  const httpsAddress = proxy.address();
  const httpsPort = typeof httpsAddress === 'object' && httpsAddress ? httpsAddress.port : 0;

  return {
    url: `https://127.0.0.1:${httpsPort}`,
    certPath,
    async close() {
      await new Promise((r) => proxy.close(r));
      await app.close();
    }
  };
}
