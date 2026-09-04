// Production build: Bun's own bundler, no separate build-tool dependency
// (see the completion report's UI-stack decision). Bundles the main app
// entry and the crypto Worker entry as two independent browser targets,
// plus copies the WASM binary and stylesheet next to them, into
// apps/web/dist — exactly what index.html references.
import { mkdir, cp, rm } from "node:fs/promises";
import { existsSync } from "node:fs";

const root = new URL("..", import.meta.url).pathname;
const dist = `${root}dist`;

await rm(dist, { recursive: true, force: true });
await mkdir(dist, { recursive: true });

const shared = {
  target: "browser" as const,
  outdir: dist,
  minify: true,
  sourcemap: "linked" as const,
};

const mainResult = await Bun.build({ ...shared, entrypoints: [`${root}src/main.ts`] });
const workerResult = await Bun.build({ ...shared, entrypoints: [`${root}src/worker-entry.ts`] });

for (const [name, result] of [["main", mainResult], ["worker-entry", workerResult]] as const) {
  if (!result.success) {
    console.error(`build failed: ${name}`);
    for (const message of result.logs) console.error(message);
    process.exit(1);
  }
}

await cp(`${root}src/style.css`, `${dist}/style.css`);

const wasmSrc = `${root}../../packages/crypto-wasm/pkg/crypto_wasm_bg.wasm`;
if (!existsSync(wasmSrc)) {
  console.error(`missing built WASM binary at ${wasmSrc} — run 'bun run --filter crypto-wasm build:wasm' first`);
  process.exit(1);
}
await cp(wasmSrc, `${dist}/crypto_wasm_bg.wasm`);

console.log("web build complete:", dist);
