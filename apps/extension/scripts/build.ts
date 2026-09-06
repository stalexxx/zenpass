const outdir = new URL("../dist/common/", import.meta.url).pathname;
await Bun.build({ entrypoints: [new URL("../src/background.ts", import.meta.url).pathname], outdir, target: "browser", format: "esm", naming: "background.js", minify: true });
await Bun.build({ entrypoints: [new URL("../src/content.ts", import.meta.url).pathname], outdir, target: "browser", format: "iife", naming: "content.js", minify: true });
await Bun.build({ entrypoints: [new URL("../src/popup.ts", import.meta.url).pathname], outdir, target: "browser", format: "esm", naming: "popup.js", minify: true });
for (const file of ["popup.html", "popup.css"]) {
  await Bun.write(`${outdir}/${file}`, Bun.file(new URL(`../${file}`, import.meta.url).pathname));
}
// The generated WASM glue (packages/crypto-wasm/pkg/crypto_wasm.js, bundled
// into background.js above) loads its compiled module at runtime via
// `fetch(new URL('crypto_wasm_bg.wasm', import.meta.url))` — a runtime
// string, not a static import Bun's bundler can inline — so the actual
// .wasm binary must ship alongside background.js in each packaged
// extension directory for that fetch to resolve (ADR-0011 D6: packaged
// WASM only, loaded from the extension's own origin, never a remote URL).
const wasmBinaryPath = new URL("../../../packages/crypto-wasm/pkg/crypto_wasm_bg.wasm", import.meta.url).pathname;
await Bun.write(`${outdir}/crypto_wasm_bg.wasm`, Bun.file(wasmBinaryPath));
for (const [target, manifest] of [["chrome", "manifest.chrome.json"], ["firefox", "manifest.firefox.json"]] as const) {
  const targetDir = new URL(`../dist/${target}/`, import.meta.url).pathname;
  for (const file of ["background.js", "content.js", "popup.js", "popup.html", "popup.css", "crypto_wasm_bg.wasm"]) {
    await Bun.write(`${targetDir}/${file}`, Bun.file(`${outdir}/${file}`));
  }
  await Bun.write(`${targetDir}/manifest.json`, Bun.file(new URL(`../${manifest}`, import.meta.url).pathname));
}
