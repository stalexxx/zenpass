FROM node:20-alpine
WORKDIR /app
COPY apps/backend/package.json ./package.json
RUN npm install --omit=dev
COPY apps/backend/src ./src
COPY db ./db
CMD ["node", "src/server.mjs"]
