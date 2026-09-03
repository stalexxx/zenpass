// Fixed, generic bodies only (T09/T17: no distinguishing detail leaks
// whether a credential, account, or rate limit was the reason for failure).
//
// Never `return reply.send(...)` from an async handler/hook. Returning a
// non-undefined value makes Fastify's wrap-thenable try to send the reply a
// SECOND time; `reply.sent` only flips once the raw response has fully
// ended (asynchronous), so the second send can race ahead of that guard ->
// intermittent "ERR_HTTP_HEADERS_SENT". These helpers send and return
// nothing; call sites must not wrap them in a `return` that yields a value.
//
// The same lagging-`reply.sent` behavior also means a `preHandler` that
// sends an early response (e.g. `requireSession` below) cannot rely on
// Fastify skipping the route handler afterward — see
// apps/backend/src/auth/authenticate.mjs for how callers guard against
// that instead (checking `request.authSession` at the top of the handler,
// rather than `reply.hijack()`, which requires bypassing `reply.send()`
// entirely in favor of raw response methods and isn't a fit here).
export function sendUnauthorized(reply, request) {
  reply.code(401).send({ error: 'authentication_failed', message: 'Invalid credentials.', requestId: request.id });
}

export function sendBadRequest(reply, request) {
  reply.code(400).send({ error: 'invalid_request', message: 'The request could not be processed.', requestId: request.id });
}

export function sendNotFound(reply, request) {
  reply.code(404).send({ error: 'not_found', message: 'The resource was not found.', requestId: request.id });
}
