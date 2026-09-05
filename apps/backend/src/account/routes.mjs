// ADR-0011 G1: authenticated account key-bundle GET/PUT. Ownership is
// derived exclusively from the bearer session (never from a client-
// supplied accountId in the body/path).
import { decodeB64, encodeB64 } from '../auth/codec.mjs';
import { requireSession } from '../auth/authenticate.mjs';
import { sendBadRequest, sendNotFound } from '../auth/responses.mjs';
import { validateAccountBundleBytes, MAX_OUTER_BYTES } from './bundle-codec.mjs';
import { getKeyBundle, publishKeyBundle } from './store.mjs';

// Bounds the base64-encoded wire string before decoding: base64 expands by
// 4/3 plus padding, so this is a generous but finite ceiling ahead of the
// exact post-decode `MAX_OUTER_BYTES` check.
const MAX_OUTER_B64_LENGTH = Math.ceil(MAX_OUTER_BYTES / 3) * 4 + 16;
const MAX_VERSION = 2147483647;

// See apps/backend/src/auth/responses.mjs for why handlers below never
// `return reply.send(...)`.
function sendJson(reply, statusCode, body) {
  reply.code(statusCode).send(body);
}

export function registerAccountRoutes(app, { pool }) {
  const auth = { preHandler: requireSession(pool) };

  // See apps/backend/src/auth/authenticate.mjs for why every handler below
  // re-checks `request.authSession` even though the preHandler already
  // responded on failure.

  app.get('/account/key-bundle', auth, async (request, reply) => {
    if (!request.authSession) return;
    const row = await getKeyBundle(pool, request.authSession.account_id);
    if (!row) {
      sendNotFound(reply, request);
      return;
    }
    sendJson(reply, 200, { bundle: encodeB64(row.bundle), version: row.version });
  });

  app.put('/account/key-bundle', auth, async (request, reply) => {
    if (!request.authSession) return;
    const body = request.body ?? {};
    const { bundle, version } = body;

    if (typeof bundle !== 'string' || bundle.length === 0 || bundle.length > MAX_OUTER_B64_LENGTH) {
      sendBadRequest(reply, request);
      return;
    }
    if (!Number.isInteger(version) || version < 1 || version > MAX_VERSION) {
      sendBadRequest(reply, request);
      return;
    }

    const bytes = decodeB64(bundle);
    if (!bytes) {
      sendBadRequest(reply, request);
      return;
    }

    const validated = validateAccountBundleBytes(bytes);
    if (!validated) {
      sendBadRequest(reply, request);
      return;
    }
    // The bundle's own `accountId` field must match the authenticated
    // session — this is a redundant-by-design defense-in-depth check:
    // storage is already keyed by the session's account_id, never by the
    // client-supplied field, so a mismatch can only ever reject, never
    // misroute a write.
    if (validated.accountId !== request.authSession.account_id) {
      sendBadRequest(reply, request);
      return;
    }

    const result = await publishKeyBundle(pool, request.authSession.account_id, bytes, version);
    if (result.outcome === 'conflict') {
      sendJson(reply, 409, {
        error: 'key_bundle_conflict',
        currentVersion: result.currentVersion,
        attemptedVersion: version
      });
      return;
    }
    sendJson(reply, 204, undefined);
  });
}
