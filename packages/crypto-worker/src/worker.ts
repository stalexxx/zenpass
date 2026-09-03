import { CryptoWorkerHost } from "./index.ts";
import { installCryptoWorker } from "./entrypoint.ts";
import { createWasmBackend } from "./wasm-adapter.ts";

const scope = self as unknown as import("./entrypoint.ts").WorkerScope;
const backend = await createWasmBackend();
installCryptoWorker(scope, new CryptoWorkerHost(backend));
