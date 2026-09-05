# Web vault

Web application boundary. Product implementation belongs to C01.

## Local development

Start PostgreSQL and the backend on `127.0.0.1:8787`, then run
`bun run --filter @zkpm/web dev`. The web dev server listens on
`http://127.0.0.1:5173` and proxies API routes through the same origin.
