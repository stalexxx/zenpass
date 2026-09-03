import { randomBytes } from 'node:crypto';
import { decodeB64, encodeB64 } from './codec.mjs';
import { ensureAccount, getCredentialRecord, saveCredentialRecordIfAbsent } from './credentials.mjs';
import { checkAndIncrement } from './rate-limit.mjs';
import { issueSession, revokeSession, rotateSession } from './sessions.mjs';
import { requireSession } from './authenticate.mjs';
import { sendBadRequest, sendUnauthorized } from './responses.mjs';

const OPAQUE_CONTEXT = Buffer.from('zkpm-opaque-v1');
// Fixed by the pinned Ristretto255 suite (ADR-0003); used only to keep the
// unknown-account decoy response the same shape as a real KE2 (ADR-0006 §9).
const KE1_LEN = 96;
const KE2_LEN = 320;
// Non-empty placeholder for the registration-finish leg, which has nothing
// meaningful to send back (server_registration_finish produces no message).
const REGISTRATION_ACK = Buffer.from([1]);

// See apps/backend/src/auth/responses.mjs for why handlers below never
// `return reply.send(...)`: they call `reply.code(x).send(y)` as a bare
// statement and then `return;` with no value.
function sendJson(reply, statusCode, body) {
  reply.code(statusCode).send(body);
}

export function registerAuthRoutes(app, { pool, ready, loginStateStore, config }) {
  const rateLimitOptions = { max: config.authRateLimitMax, windowSeconds: config.authRateLimitWindowSeconds };

  app.post('/auth/opaque/register', async (request, reply) => {
    const { accountId, clientMessage } = request.body ?? {};
    const message = decodeB64(clientMessage);
    if (!accountId || !message) {
      sendBadRequest(reply, request);
      return;
    }

    // auth_rate_limits.account_id is a foreign key, and rate limiting must
    // cover an account that doesn't have credentials yet (it's mid-
    // registration), so the ledger row is created unconditionally here.
    await ensureAccount(pool, accountId);
    const withinLimit = await checkAndIncrement(pool, accountId, 'register', rateLimitOptions);
    if (!withinLimit) {
      sendBadRequest(reply, request);
      return;
    }

    const { opaque, serverSetup } = await ready;
    let step;
    try {
      step = opaque.registrationStep(serverSetup, accountId, message);
    } catch {
      sendBadRequest(reply, request);
      return;
    }

    if (step.step === 'response') {
      sendJson(reply, 201, { message: encodeB64(step.message) });
      return;
    }

    await saveCredentialRecordIfAbsent(pool, accountId, Buffer.from(step.message));
    request.log.info({ event: 'auth.register.completed', accountId }, 'registration completed');
    sendJson(reply, 201, { message: encodeB64(REGISTRATION_ACK) });
  });

  app.post('/auth/opaque/login', async (request, reply) => {
    const { accountId, clientMessage } = request.body ?? {};
    const message = decodeB64(clientMessage);
    if (!accountId || !message) {
      sendUnauthorized(reply, request);
      return;
    }

    // Same FK/enumeration reasoning as registration above: the ledger row
    // must exist before rate limiting an account that may not be registered.
    await ensureAccount(pool, accountId);
    const withinLimit = await checkAndIncrement(pool, accountId, 'login', rateLimitOptions);
    if (!withinLimit) {
      sendUnauthorized(reply, request);
      return;
    }

    const { opaque, serverSetup } = await ready;

    if (!loginStateStore.hasPending(accountId)) {
      // Leg 1 (KE1 -> KE2). Length is validated before branching on account
      // existence so a malformed KE1 fails identically either way.
      if (message.length !== KE1_LEN) {
        sendUnauthorized(reply, request);
        return;
      }

      const credentialRecord = await getCredentialRecord(pool, accountId);
      if (!credentialRecord) {
        // Unknown account: respond with a same-shaped decoy KE2 rather than
        // an immediate distinguishable failure (ADR-0006 §9 residual gap:
        // this is HTTP-shape parity, not full OPRF-level indistinguishability).
        loginStateStore.setFake(accountId);
        sendJson(reply, 200, { message: encodeB64(randomBytes(KE2_LEN)) });
        return;
      }

      let start;
      try {
        start = opaque.loginStart(serverSetup, Buffer.from(credentialRecord), accountId, message, OPAQUE_CONTEXT);
      } catch {
        sendUnauthorized(reply, request);
        return;
      }
      loginStateStore.setReal(accountId, Buffer.from(start.state));
      sendJson(reply, 200, { message: encodeB64(start.message) });
      return;
    }

    // Leg 2 (KE3 -> Session).
    const pending = loginStateStore.take(accountId);
    if (!pending || pending.kind === 'fake') {
      sendUnauthorized(reply, request);
      return;
    }

    try {
      opaque.loginFinish(pending.stateBytes, message, OPAQUE_CONTEXT);
    } catch {
      sendUnauthorized(reply, request);
      return;
    }

    const session = await issueSession(pool, accountId, config.sessionTtlSeconds);
    request.log.info({ event: 'auth.login.succeeded', accountId }, 'login succeeded');
    sendJson(reply, 200, { accessToken: session.accessToken, expiresAt: session.expiresAt });
  });

  app.post('/auth/refresh', { preHandler: requireSession(pool) }, async (request, reply) => {
    // requireSession already responded (401) if this is unset; see
    // authenticate.mjs for why this check exists instead of relying on
    // Fastify to skip this handler on its own.
    const { authSession } = request;
    if (!authSession) return;
    // ADR-0005 §2: only a non-revoked device-bound session may refresh.
    if (!authSession.device_id) {
      sendUnauthorized(reply, request);
      return;
    }
    const session = await rotateSession(pool, authSession, config.sessionTtlSeconds);
    sendJson(reply, 200, { accessToken: session.accessToken, expiresAt: session.expiresAt });
  });

  app.post('/auth/logout', { preHandler: requireSession(pool) }, async (request, reply) => {
    if (!request.authSession) return;
    await revokeSession(pool, request.authSession.session_id);
    sendJson(reply, 204, undefined);
  });
}
