import { resolveSession } from './sessions.mjs';
import { sendUnauthorized } from './responses.mjs';

/**
 * Fastify preHandler: resolves `Authorization: Bearer <token>` into
 * `request.authSession`, or responds 401 itself.
 *
 * Route handlers using this preHandler must still check
 * `if (!request.authSession) return;` at the top, even though this hook
 * already sent a response on failure: Fastify decides whether to run the
 * route handler by checking `reply.sent`, which only becomes true once the
 * raw HTTP response has fully ended — asynchronous, and not guaranteed to
 * have happened yet when this hook's promise resolves. Without the guard,
 * the handler can still run with no session, throw, and collide with the
 * preHandler's already-in-flight response (ERR_HTTP_HEADERS_SENT).
 */
export function requireSession(pool) {
  return async (request, reply) => {
    const header = request.headers.authorization || '';
    const [scheme, token] = header.split(' ');
    if (scheme !== 'Bearer' || !token) {
      sendUnauthorized(reply, request);
      return;
    }
    const session = await resolveSession(pool, token);
    if (!session) {
      sendUnauthorized(reply, request);
      return;
    }
    request.authSession = session;
  };
}
