FROM node:20-alpine
WORKDIR /workspace/apps/backend
COPY apps/backend/package.json ./package.json
RUN npm install --omit=dev
COPY apps/backend/src ./src
# Keep the repository layout at runtime. The migration runner resolves the
# migrations relative to src/, rather than relative to the process CWD.
COPY db /workspace/db
CMD ["node", "src/server.mjs"]
