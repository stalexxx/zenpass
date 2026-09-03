# Backend foundation (B02)

Fastify/PostgreSQL service boundary. This package currently provides only
configuration, redacted request logging, liveness/readiness, and migrations;
auth and sync handlers belong to B04/B05.

## Local run

From the repository root, start PostgreSQL with `docker compose -f
infra/docker-compose.yml up -d postgres` (host port `5434`), then run `bun run --filter @zkpm/backend
migrate` and `bun run --filter @zkpm/backend dev`.

Production requires an explicit `DATABASE_URL`. The service never logs request
bodies or opaque secret fields. The database schema stores only OPAQUE records,
hashes, public keys, wrapped bundles, and encrypted item bytes.

Health endpoints are `/health/live` and `/health/ready`; readiness returns 503
until PostgreSQL responds to `SELECT 1`.
