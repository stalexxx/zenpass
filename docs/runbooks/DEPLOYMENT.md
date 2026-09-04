# Deployment runbook

This runbook is for the approved personal/internal single-VPS deployment.
It does not authorize a public release. The release owner supplies the real
`<DOMAIN>` and `<VPS_IP>` manually; neither is stored in this repository.

## First deployment on Debian or Ubuntu

1. Create a non-root deploy user with SSH-key access, then allow only SSH and
   HTTPS traffic (and HTTP for ACME certificate issuance/redirects). With
   UFW, run:

   ```sh
   sudo apt-get update
   sudo apt-get install -y ca-certificates curl git ufw
   sudo ufw allow OpenSSH
   sudo ufw allow 80/tcp
   sudo ufw allow 443/tcp
   sudo ufw enable
   sudo ufw status verbose
   ```

   Do not allow PostgreSQL (`5432`, or the development-only `5434`) or the
   API port (`3000`). The production Compose file does not publish either
   port to the host.

2. Install Docker Engine and the Compose plugin from Docker's apt repository,
   then verify the installation:

   ```sh
   sudo install -m 0755 -d /etc/apt/keyrings
   sudo curl -fsSL "https://download.docker.com/linux/$(. /etc/os-release && echo "$ID")/gpg" -o /etc/apt/keyrings/docker.asc
   sudo chmod a+r /etc/apt/keyrings/docker.asc
   echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/$(. /etc/os-release && echo "$ID") $(. /etc/os-release && echo "$VERSION_CODENAME") stable" | sudo tee /etc/apt/sources.list.d/docker.list > /dev/null
   sudo apt-get update
   sudo apt-get install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
   docker --version
   docker compose version
   ```

   Add the deploy user to the `docker` group only if that user is trusted
   with root-equivalent Docker access; otherwise use `sudo docker` below.

3. Point the DNS A/AAAA record for `<DOMAIN>` at `<VPS_IP>`. Wait for public
   DNS propagation before starting Caddy, because Caddy obtains its TLS
   certificate automatically.

   **No domain yet?** Run `infra/generate-selfsigned-cert.sh <VPS_IP>` once
   (writes `infra/certs/selfsigned.{crt,key}`, git-ignored). Then set
   `DOMAIN=<VPS_IP>`, `CADDY_SITE_ADDRESS=:443`, and
   `CADDY_TLS_DIRECTIVE=tls /certs/selfsigned.crt /certs/selfsigned.key` in
   `infra/.env.production` instead. A real browser (and curl, and every
   standard TLS library) does not send SNI when connecting to a literal IP
   address (RFC 6066), so the site address must not be host-restricted —
   only `:443` (not the IP itself) matches those connections — and the
   certificate must be a statically loaded file rather than automatically
   issued: Caddy's automatic HTTPS, including its `tls internal` on-demand
   issuer, is keyed by SNI and has nothing to issue against when SNI is
   absent. Browsers will show an untrusted-certificate warning on every
   visit. This is acceptable for personal/internal use only — switch to a
   real domain (`CADDY_SITE_ADDRESS=<DOMAIN>`, `CADDY_TLS_DIRECTIVE=` empty)
   before any public release.

4. Clone the reviewed release commit and create the untracked production
   environment file:

   ```sh
   git clone <REPOSITORY_URL> zkpm
   cd zkpm
   cp infra/.env.production.example infra/.env.production
   chmod 600 infra/.env.production
   ```

   Edit `infra/.env.production`: replace all `<...>` placeholders, use a
   long unique database password in both PostgreSQL fields, and set
   `DATABASE_URL` with the same URL-encoded password. Set `DOMAIN` and
   `WEB_ORIGIN` to the real HTTPS hostname.

5. Generate and save the required OPAQUE server setup once, without printing
   it to the terminal. Run this from the repository root only after the
   placeholder has been left unchanged in `infra/.env.production`:

   ```sh
   bun -e "import init,{generate_server_setup}from './packages/crypto-server/pkg/crypto_server.js';await init();const s=Buffer.from(generate_server_setup()).toString('base64'),p='infra/.env.production',t=await Bun.file(p).text();if(!t.includes('OPAQUE_SERVER_SETUP=<GENERATE_AND_STORE_A_BASE64_OPAQUE_SERVER_SETUP>'))throw new Error('OPAQUE_SERVER_SETUP must contain the example placeholder');await Bun.write(p,t.replace('OPAQUE_SERVER_SETUP=<GENERATE_AND_STORE_A_BASE64_OPAQUE_SERVER_SETUP>','OPAQUE_SERVER_SETUP='+s));"
   ```

   Back up this value securely with the database backup. It is server secret
   material; losing or changing it prevents existing accounts from using
   their stored OPAQUE credentials. Do not put it in shell history, tickets,
   logs, or this repository.

6. Validate the rendered Compose model and start the stack:

   ```sh
   docker compose --env-file infra/.env.production -f infra/docker-compose.prod.yml config
   docker compose --env-file infra/.env.production -f infra/docker-compose.prod.yml up -d --build
   docker compose --env-file infra/.env.production -f infra/docker-compose.prod.yml ps
   curl --fail --show-error https://<DOMAIN>/health/ready
   ```

   `migrate` exits successfully after applying pending migrations. `api`
   must show healthy before Caddy starts accepting traffic. Do not use
   `docker compose logs` to inspect request payloads.

## Updating a deployed VPS

1. Back up PostgreSQL and the protected `OPAQUE_SERVER_SETUP` value according
   to the backup/recovery runbook. Never rotate that value as part of a normal
   application update.
2. Fetch the reviewed release, rebuild, run migrations explicitly, then
   recreate the API and proxy:

   ```sh
   git pull --ff-only
   docker compose --env-file infra/.env.production -f infra/docker-compose.prod.yml build
   docker compose --env-file infra/.env.production -f infra/docker-compose.prod.yml run --rm migrate
   docker compose --env-file infra/.env.production -f infra/docker-compose.prod.yml up -d --no-deps api caddy
   curl --fail --show-error https://<DOMAIN>/health/ready
   ```

   This single-VPS procedure may briefly interrupt API requests while the API
   container is replaced. Confirm the readiness endpoint before considering
   the rollout complete.
