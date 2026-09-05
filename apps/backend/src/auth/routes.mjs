import { randomBytes } from 'node:crypto';
import { decodeB64, encodeB64 } from './codec.mjs';
import { ensureAccount, getCredentialRecord, saveCredentialRecordIfAbsent } from './credentials.mjs';
import { checkAndIncrement } from './rate-limit.mjs';
import { issueSession, revokeSession, rotateSession } from './sessions.mjs';
import { requireSession } from './authenticate.mjs';
import { sendBadRequest, sendUnauthorized } from './responses.mjs';
import { isValidAccountId } from './validation.mjs';
import { admissionKey, createAdmissionLimiter } from './admission-limit.mjs';

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
  // SEC-07: a coarse, cheap admission control shared by both routes, kept
  // ahead of ensureAccount/checkAndIncrement below. See admission-limit.mjs.
  const admissionLimiter = createAdmissionLimiter({
    max: config.authAdmissionRateLimitMax,
    windowMs: config.authAdmissionRateLimitWindowSeconds
      ? config.authAdmissionRateLimitWindowSeconds * 1000
      : undefined
  });

  app.post('/auth/opaque/register', async (request, reply) => {
    const { accountId, clientMessage } = request.body ?? {};
    const message = decodeB64(clientMessage);
    // SEC-07: reject a malformed accountId or clientMessage before any
    // persistent write. This must stay routed through the same generic
    // sendBadRequest body as every other rejection below so a malformed
    // request is indistinguishable from an unknown/known-account one.
    if (!isValidAccountId(accountId) || !message) {
      sendBadRequest(reply, request);
      return;
    }

    // SEC-07: a coarse, IP-scoped admission check ahead of the durable
    // per-account limiter and any persistent write, so raw request volume
    // alone (many distinct synthetic accountIds) can't inflate
    // accounts/auth_rate_limits.
    if (!admissionLimiter.allow(admissionKey(request))) {
      sendBadRequest(reply, request);
      return;
    }

    const { opaque, serverSetup } = await ready;
    let step;
    try {
      // SEC-07: registrationStep parses and rejects a malformed message
      // (wrong length/shape for either leg) internally; this call performs
      // no I/O and must complete before any persistent write below.
      step = opaque.registrationStep(serverSetup, accountId, message);
    } catch {
      sendBadRequest(reply, request);
      return;
    }

    // auth_rate_limits.account_id is a foreign key, and rate limiting must
    // cover an account that doesn't have credentials yet (it's mid-
    // registration), so the ledger row is created unconditionally here --
    // but only now that accountId grammar and OPAQUE message shape are
    // both confirmed well-formed above (SEC-07).
    await ensureAccount(pool, accountId);
    const withinLimit = await checkAndIncrement(pool, accountId, 'register', rateLimitOptions);
    if (!withinLimit) {
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
    // SEC-07: reject a malformed accountId or clientMessage before any
    // persistent write, via the same generic sendUnauthorized body used by
    // every other rejection below.
    if (!isValidAccountId(accountId) || !message) {
      sendUnauthorized(reply, request);
      return;
    }

    const hasPending = loginStateStore.hasPending(accountId);

    // SEC-07: leg 1 (fresh KE1) has a length fixed by the pinned suite;
    // validate it -- identically for a malformed request either way --
    // before any persistent write. Leg 2's shape is verified by
    // loginFinish below, once real per-account state already exists.
    if (!hasPending && message.length !== KE1_LEN) {
      sendUnauthorized(reply, request);
      return;
    }

    // SEC-07: a coarse, IP-scoped admission check ahead of the durable
    // per-account limiter and any persistent write, so raw request volume
    // alone (many distinct synthetic accountIds) can't inflate
    // accounts/auth_rate_limits.
    if (!admissionLimiter.allow(admissionKey(request))) {
      sendUnauthorized(reply, request);
      return;
    }

    // Same FK/enumeration reasoning as registration above: the ledger row
    // must exist before rate limiting an account that may not be
    // registered -- but only now that accountId grammar and message shape
    // are both confirmed well-formed above (SEC-07).
    await ensureAccount(pool, accountId);
    const withinLimit = await checkAndIncrement(pool, accountId, 'login', rateLimitOptions);
    if (!withinLimit) {
      sendUnauthorized(reply, request);
      return;
    }

    const { opaque, serverSetup } = await ready;

    if (!hasPending) {
      // Leg 1 (KE1 -> KE2).
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
    // SEC-06: rotateSession re-checks liveness/device-binding atomically
    // under its own transaction and returns null if this session lost the
    // race (already rotated/revoked/expired by another concurrent caller,
    // or its device was revoked concurrently) — a generic unauthorized
    // response, never a second successor for the same original session.
    const session = await rotateSession(pool, authSession, config.sessionTtlSeconds);
    if (!session) {
      sendUnauthorized(reply, request);
      return;
    }
    sendJson(reply, 200, { accessToken: session.accessToken, expiresAt: session.expiresAt });
  });

  app.post('/auth/logout', { preHandler: requireSession(pool) }, async (request, reply) => {
    if (!request.authSession) return;
    await revokeSession(pool, request.authSession.session_id);
    sendJson(reply, 204, undefined);
  });
}
