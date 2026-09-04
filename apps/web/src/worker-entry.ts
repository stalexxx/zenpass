// This app's actual dedicated Worker entrypoint. It is intentionally just
// packages/crypto-worker/src/worker.ts's three lines, re-hosted inside
// apps/web/src/ so `new Worker(new URL("./worker-entry.ts", import.meta.url))`
// in worker-client.ts has one stable relative path Bun's bundler can
// resolve identically in dev and in a production `bun build` (an
// import.meta.url-relative path reaching outside this package's own
// source tree, as crypto-worker/src/worker.ts itself would require, is
// not something the bundler can be relied on to rewrite consistently
// across both modes). No logic lives here beyond that re-hosting —
// packages/crypto-worker's actual host/backend/protocol code is untouched
// and this file is not a new export from that package.
import { CryptoWorkerHost } from "../../../packages/crypto-worker/src/index.ts";
import { installCryptoWorker, type WorkerScope } from "../../../packages/crypto-worker/src/entrypoint.ts";
import { createWasmBackend } from "../../../packages/crypto-worker/src/wasm-adapter.ts";

const scope = self as unknown as WorkerScope;
const backend = await createWasmBackend();
installCryptoWorker(scope, new CryptoWorkerHost(backend));
