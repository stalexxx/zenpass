import { requireSession } from '../auth/authenticate.mjs';
import { sendBadRequest, sendNotFound } from '../auth/responses.mjs';
import { decodeB64 } from '../auth/codec.mjs';
import {
  acquireMutationLock,
  ensureVaultOwnership,
  findMutationOutcome,
  getItemForUpdate,
  listChanges,
  recordMutationOutcome,
  toItemRecord,
  upsertItem,
  vaultOwnedBy,
  withTransaction
} from './store.mjs';

const ID_PATTERN = /^[A-Za-z0-9][A-Za-z0-9_-]{0,127}$/;
const CIPHERTEXT_PATTERN = /^b64:[A-Za-z0-9+/]+={0,2}$/;

// See apps/backend/src/auth/responses.mjs for why handlers below never
// `return reply.send(...)`.
function sendJson(reply, statusCode, body) {
  reply.code(statusCode).send(body);
}

function isValidMutation(body) {
  if (!body || typeof body !== 'object') return false;
  const { mutationId, itemId, vaultId, baseRevision, ciphertext, envelopeVersion, deleted } = body;
  if (typeof mutationId !== 'string' || !ID_PATTERN.test(mutationId)) return false;
  if (typeof itemId !== 'string' || !ID_PATTERN.test(itemId)) return false;
  if (typeof vaultId !== 'string' || !ID_PATTERN.test(vaultId)) return false;
  if (!Number.isInteger(baseRevision) || baseRevision < 0) return false;
  if (typeof ciphertext !== 'string' || !CIPHERTEXT_PATTERN.test(ciphertext)) return false;
  if (envelopeVersion !== 'crypto-envelope/v1') return false;
  if (typeof deleted !== 'boolean') return false;
  return true;
}

function encodeCursor(sequence) {
  return Buffer.from(String(sequence), 'utf8').toString('base64url');
}

/** Returns the decoded non-negative integer sequence string, or null if
 * `cursor` isn't a well-formed opaque cursor. */
function decodeCursor(cursor) {
  if (typeof cursor !== 'string' || cursor.length === 0) return null;
  let decoded;
  try {
    decoded = Buffer.from(cursor, 'base64url').toString('utf8');
  } catch {
    return null;
  }
  if (!/^[0-9]+$/.test(decoded)) return null;
  return decoded;
}

/**
 * Applies one mutation inside a single transaction. Returns
 * `{ statusCode, body }` on a definite outcome, or `{ notFound: true }` /
 * `{ badRequest: true }` for the two failure paths that never touch
 * `vault_items` or `mutation_outcomes`.
 */
async function applyMutation(pool, accountId, vaultId, mutation, ciphertext) {
  return withTransaction(pool, async (client) => {
    await acquireMutationLock(client, accountId, mutation.mutationId);

    // Re-check idempotency after acquiring the lock: a concurrent request
    // carrying the same mutationId may have committed while this
    // transaction waited on the lock above.
    const replayed = await findMutationOutcome(client, accountId, mutation.mutationId);
    if (replayed) return { statusCode: replayed.statusCode, body: replayed.body };

    const owns = await ensureVaultOwnership(client, accountId, vaultId);
    if (!owns) return { notFound: true };

    const existing = await getItemForUpdate(client, vaultId, mutation.itemId);
    const currentRevision = existing ? Number(existing.revision) : 0;

    if (mutation.baseRevision !== currentRevision) {
      if (!existing) {
        // No item exists yet, so there is no ItemRecord to embed in a
        // Conflict response's `current` (required, non-null per
        // openapi.yaml). A non-zero baseRevision against a nonexistent
        // item is a client-side bug, not a recoverable conflict: reject
        // it as a bad request instead of inventing an undocumented
        // conflict shape.
        return { badRequest: true };
      }
      const body = {
        error: 'conflict',
        mutationId: mutation.mutationId,
        current: toItemRecord(existing),
        attempted: mutation
      };
      await recordMutationOutcome(client, accountId, mutation.mutationId, vaultId, 409, body);
      return { statusCode: 409, body };
    }

    const row = await upsertItem(client, {
      vaultId,
      itemId: mutation.itemId,
      ciphertext,
      envelopeVersion: mutation.envelopeVersion,
      revision: currentRevision + 1,
      deleted: mutation.deleted
    });
    const body = toItemRecord(row);
    await recordMutationOutcome(client, accountId, mutation.mutationId, vaultId, 201, body);
    return { statusCode: 201, body };
  });
}

export function registerSyncRoutes(app, { pool }) {
  const auth = { preHandler: requireSession(pool) };

  // See apps/backend/src/auth/authenticate.mjs for why every handler below
  // re-checks `request.authSession` even though the preHandler already
  // responded on failure.

  app.post('/vaults/:vaultId/items', auth, async (request, reply) => {
    if (!request.authSession) return;
    const accountId = request.authSession.account_id;
    const { vaultId } = request.params;
    const mutation = request.body;

    if (!ID_PATTERN.test(vaultId ?? '') || !isValidMutation(mutation) || mutation.vaultId !== vaultId) {
      sendBadRequest(reply, request);
      return;
    }

    const ciphertext = decodeB64(mutation.ciphertext);
    if (!ciphertext) {
      sendBadRequest(reply, request);
      return;
    }

    // Idempotency fast path: most replays arrive after the original
    // mutation already committed, so this point read (no lock, no
    // transaction) avoids the lock/transaction overhead below entirely.
    // `applyMutation` re-checks under the advisory lock for the narrow
    // concurrent-double-submit race this fast path can't catch.
    const replay = await findMutationOutcome(pool, accountId, mutation.mutationId);
    if (replay) {
      sendJson(reply, replay.statusCode, replay.body);
      return;
    }

    const outcome = await applyMutation(pool, accountId, vaultId, mutation, ciphertext);
    if (outcome.notFound) {
      sendNotFound(reply, request);
      return;
    }
    if (outcome.badRequest) {
      sendBadRequest(reply, request);
      return;
    }
    sendJson(reply, outcome.statusCode, outcome.body);
  });

  app.get('/vaults/:vaultId/changes', auth, async (request, reply) => {
    if (!request.authSession) return;
    const accountId = request.authSession.account_id;
    const { vaultId } = request.params;
    if (!ID_PATTERN.test(vaultId ?? '')) {
      sendBadRequest(reply, request);
      return;
    }

    const { cursor, limit: limitRaw } = request.query ?? {};
    let afterSequence = '0';
    if (cursor !== undefined) {
      const decoded = decodeCursor(cursor);
      if (decoded === null) {
        sendBadRequest(reply, request);
        return;
      }
      afterSequence = decoded;
    }

    let limit = 100;
    if (limitRaw !== undefined) {
      limit = Number(limitRaw);
      if (!Number.isInteger(limit) || limit < 1 || limit > 200) {
        sendBadRequest(reply, request);
        return;
      }
    }

    const owns = await vaultOwnedBy(pool, accountId, vaultId);
    if (!owns) {
      sendNotFound(reply, request);
      return;
    }

    const rows = await listChanges(pool, vaultId, afterSequence, limit);
    const changes = rows.map(toItemRecord);
    const nextCursor = rows.length > 0 ? encodeCursor(rows[rows.length - 1].sequence) : (cursor ?? encodeCursor(0));

    sendJson(reply, 200, { changes, nextCursor });
  });
}
