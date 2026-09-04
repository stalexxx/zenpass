FROM oven/bun:1.2.15-alpine
WORKDIR /workspace
COPY package.json bun.lock ./
COPY apps/backend/package.json apps/backend/package.json
COPY apps/desktop/package.json apps/desktop/package.json
COPY apps/extension/package.json apps/extension/package.json
COPY apps/web/package.json apps/web/package.json
COPY packages/contracts/package.json packages/contracts/package.json
COPY packages/crypto-fixtures/package.json packages/crypto-fixtures/package.json
COPY packages/crypto-server/package.json packages/crypto-server/package.json
COPY packages/crypto-wasm/package.json packages/crypto-wasm/package.json
COPY packages/crypto-worker/package.json packages/crypto-worker/package.json
COPY packages/domain/package.json packages/domain/package.json
COPY packages/extension-adapters/package.json packages/extension-adapters/package.json
COPY packages/importers/package.json packages/importers/package.json
COPY packages/sdk/package.json packages/sdk/package.json
RUN bun install --frozen-lockfile --production
WORKDIR /workspace/apps/backend
COPY apps/backend/src ./src
# The backend imports this generated WASM binding by repository-relative path.
# It is built by the verified crypto-server package; this image only packages
# the generated runtime artifact and does not build cryptography.
COPY packages/crypto-server/pkg /workspace/packages/crypto-server/pkg
# Keep the repository layout at runtime. The migration runner resolves the
# migrations relative to src/, rather than relative to the process CWD.
COPY db /workspace/db
CMD ["bun", "src/server.mjs"]
