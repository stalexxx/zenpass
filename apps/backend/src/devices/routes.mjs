import { decodeB64 } from '../auth/codec.mjs';
import { requireSession } from '../auth/authenticate.mjs';
import { bindSessionToDevice } from '../auth/sessions.mjs';
import { sendBadRequest, sendNotFound } from '../auth/responses.mjs';
import { createDevice, enrollBearerSessionDevice, listDevices, revokeDevice } from './store.mjs';

const NAME_MAX_LENGTH = 128;

function isValidName(name) {
  return typeof name === 'string' && name.length > 0 && name.length <= NAME_MAX_LENGTH;
}

/**
 * ADR-0011 G2: `DeviceCreate` is a disjoint union of the legacy
 * (`name`, `publicKey`) branch and the new (`name`,
 * `enrollmentMode:"bearer-session-v1"`) branch — never both, never
 * neither, and no unknown fields in either. Returns `null` for anything
 * that isn't exactly one of the two shapes.
 */
function classifyDeviceCreate(body) {
  if (!body || typeof body !== 'object' || Array.isArray(body)) return null;
  const hasPublicKey = Object.prototype.hasOwnProperty.call(body, 'publicKey');
  const hasMode = Object.prototype.hasOwnProperty.call(body, 'enrollmentMode');
  if (hasPublicKey === hasMode) return null; // both or neither: reject

  const keys = Object.keys(body);
  if (hasMode) {
    if (body.enrollmentMode !== 'bearer-session-v1') return null;
    if (!keys.every((k) => k === 'name' || k === 'enrollmentMode')) return null;
    return { kind: 'bearer-session-v1', name: body.name };
  }
  if (!keys.every((k) => k === 'name' || k === 'publicKey')) return null;
  return { kind: 'legacy-public-key', name: body.name, publicKey: body.publicKey };
}

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
    const classified = classifyDeviceCreate(request.body);
    if (!classified || !isValidName(classified.name)) {
      sendBadRequest(reply, request);
      return;
    }

    if (classified.kind === 'legacy-public-key') {
      const key = decodeB64(classified.publicKey);
      if (!key) {
        sendBadRequest(reply, request);
        return;
      }
      const device = await createDevice(pool, request.authSession.account_id, { name: classified.name, publicKey: key });
      // Explicit device registration binds the current session (ADR-0005 §2).
      await bindSessionToDevice(pool, request.authSession.session_id, device.device_id);
      sendJson(reply, 201, toApiDevice(device));
      return;
    }

    // bearer-session-v1 (ADR-0011 G2): binding happens inside
    // enrollBearerSessionDevice itself, under the session row's lock, so
    // a device-unbound check and the bind commit as one atomic step.
    const result = await enrollBearerSessionDevice(pool, request.authSession.session_id, classified.name);
    if (result.error) {
      sendBadRequest(reply, request);
      return;
    }
    sendJson(reply, 201, toApiDevice(result.device));
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
