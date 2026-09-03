import { decodeB64 } from '../auth/codec.mjs';
import { requireSession } from '../auth/authenticate.mjs';
import { bindSessionToDevice } from '../auth/sessions.mjs';
import { sendBadRequest, sendNotFound } from '../auth/responses.mjs';
import { createDevice, listDevices, revokeDevice } from './store.mjs';

function toApiDevice(row) {
  return {
    deviceId: row.device_id,
    name: row.name,
    createdAt: new Date(row.created_at).toISOString(),
    lastSeenAt: row.last_seen_at ? new Date(row.last_seen_at).toISOString() : null,
    revokedAt: row.revoked_at ? new Date(row.revoked_at).toISOString() : null
  };
}

// See apps/backend/src/auth/responses.mjs for why handlers below never
// `return reply.send(...)`.
function sendJson(reply, statusCode, body) {
  reply.code(statusCode).send(body);
}

export function registerDeviceRoutes(app, { pool }) {
  const auth = { preHandler: requireSession(pool) };

  // See apps/backend/src/auth/authenticate.mjs for why every handler below
  // re-checks `request.authSession` even though the preHandler already
  // responded on failure.

  app.get('/devices', auth, async (request, reply) => {
    if (!request.authSession) return;
    const devices = await listDevices(pool, request.authSession.account_id);
    sendJson(reply, 200, { devices: devices.map(toApiDevice) });
  });

  app.post('/devices', auth, async (request, reply) => {
    if (!request.authSession) return;
    const { name, publicKey } = request.body ?? {};
    const key = decodeB64(publicKey);
    if (!name || typeof name !== 'string' || name.length > 128 || !key) {
      sendBadRequest(reply, request);
      return;
    }
    const device = await createDevice(pool, request.authSession.account_id, { name, publicKey: key });
    // Explicit device registration binds the current session (ADR-0005 §2).
    await bindSessionToDevice(pool, request.authSession.session_id, device.device_id);
    sendJson(reply, 201, toApiDevice(device));
  });

  app.post('/devices/:deviceId/revoke', auth, async (request, reply) => {
    if (!request.authSession) return;
    const revoked = await revokeDevice(pool, request.authSession.account_id, request.params.deviceId);
    if (!revoked) {
      sendNotFound(reply, request);
      return;
    }
    sendJson(reply, 204, undefined);
  });
}
