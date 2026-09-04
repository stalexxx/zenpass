# R01-VPS-DEPLOY: Backend deployment artifacts for a personal VPS

Goal: Produce the production-shaped deployment artifacts needed to run the
`apps/backend` API and PostgreSQL on a single clean VPS the release owner
controls, fronted by TLS via a reverse proxy, without touching crypto
protocol or API contracts.

Scope note: This is the personal/internal-deployment slice of R01 authorized
by the human scope decision recorded in `docs/plan/STATUS.md` (2026-09-04).
It does not close R01, does not touch H02, and does not represent a public
release. `docs/security/H02-RESIDUAL-RISK-ACCEPTANCE.md` is the authorizing
document.

Dependencies: Q01 (merged), B02/B04/B05 (merged backend).

Allowed paths: `infra/`, `docs/runbooks/`, `docs/tasks/R01-VPS-DEPLOY.md`.

Forbidden paths: `crates/`, `packages/crypto-*`, `docs/contracts/`,
`apps/backend/src/` (no application code changes — this task packages and
deploys the existing, already-verified backend), any file under `apps/web`,
`apps/extension`, `apps/desktop`.

Do not commit real secrets, API keys, domains, IP addresses, or credentials.
Use placeholders (`<DOMAIN>`, `<VPS_IP>`) and `.env.example` files only.

## Required implementation

1. `infra/docker-compose.prod.yml`: production-shaped compose stack —
   `postgres` (pinned image, named volume, healthcheck, **not** exposing
   5432/5434 to the host), `migrate` (runs once, depends on `postgres`
   healthy), `api` (built from `infra/Dockerfile`, `NODE_ENV=production`,
   reads all secrets from environment/`.env`, not baked into the image,
   restart policy `unless-stopped`, **not** publishing its port to the host
   directly — only reachable via the reverse proxy network), and `caddy`
   (or another simple automatic-TLS reverse proxy — justify the choice in the
   completion report if not Caddy) terminating TLS on 80/443 and proxying to
   `api:3000`.
2. `infra/Caddyfile` (or equivalent) with a `<DOMAIN>` placeholder, proxying
   to the api service, forwarding `X-Forwarded-*` correctly, and not logging
   request bodies.
3. `infra/.env.production.example`: every environment variable the compose
   stack needs (`DATABASE_URL` components, `PORT`, `HOST`, any secret named
   by `apps/backend/src/config.mjs`), documented, with obviously-fake example
   values — never real secrets.
4. Update `docs/runbooks/DEPLOYMENT.md` (or add
   `docs/runbooks/VPS-DEPLOYMENT.md` if that reads better) with concrete,
   copy-pasteable steps for a first-time deploy on a clean Debian/Ubuntu VPS:
   installing Docker, cloning the repo, populating `.env.production` from the
   example, DNS pointing `<DOMAIN>` at `<VPS_IP>`, `docker compose -f
   infra/docker-compose.prod.yml up -d`, verifying `/health/ready` through
   the TLS domain, and how to roll out an update (pull, rebuild, migrate,
   restart with zero/minimal downtime is a bonus, not required for v1).
5. Firewall guidance: only 22/80/443 open; Postgres and the API's own port
   must not be reachable from the public internet.

## Constraints carried over from `AGENTS.md`

- No plaintext vault data, keys, passwords, or TOTP secrets may be logged,
  fixtured, or persisted anywhere you touch.
- Do not edit `docs/contracts/*` or any crypto/protocol code.
- Atomic commits prefixed `R01-VPS-DEPLOY:`.
- Do not merge your own branch — report back to the integrator when done.

## Required tests / verification

- `docker compose -f infra/docker-compose.prod.yml config` validates without
  error (no real secrets needed for this — placeholders are fine).
- If Docker is available in your sandbox, actually bring the stack up
  locally with a throwaway `.env.production` (fake values, e.g.
  `DOMAIN=localhost`, self-signed/`internal` Caddy TLS) and confirm
  `api` reaches `healthy` and `/health/ready` responds. If Docker/network
  access is unavailable in your sandbox, say so explicitly in the report
  instead of claiming it was verified.
- `bun run check:boundaries` still passes (you shouldn't be touching
  anything it checks, but confirm).

## Completion report format

Use the template in `docs/plan/INTEGRATOR.md` (`Task / Status / Commits /
Changed paths / Contract changes / Verification commands and results / Known
limitations / Security considerations / Follow-up tasks`). Explicitly state
in "Follow-up tasks" that the actual `<VPS_IP>`/`<DOMAIN>` provisioning and
DNS setup are the release owner's manual steps, not automated by this task.
