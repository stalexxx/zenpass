FROM oven/bun:1.2.15-alpine
WORKDIR /workspace
COPY package.json bun.lock ./
COPY apps/backend/package.json apps/backend/package.json
COPY apps/extension/package.json apps/extension/package.json
COPY apps/web/package.json apps/web/package.json
COPY packages/contracts/package.json packages/contracts/package.json
COPY packages/sdk/package.json packages/sdk/package.json
RUN bun install --frozen-lockfile --production
WORKDIR /workspace/apps/backend
COPY apps/backend/src ./src
# Keep the repository layout at runtime. The migration runner resolves the
# migrations relative to src/, rather than relative to the process CWD.
COPY db /workspace/db
CMD ["bun", "src/server.mjs"]
