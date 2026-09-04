const outdir = new URL("../dist/common/", import.meta.url).pathname;
await Bun.build({ entrypoints: [new URL("../src/background.ts", import.meta.url).pathname], outdir, target: "browser", format: "esm", naming: "background.js", minify: true });
await Bun.build({ entrypoints: [new URL("../src/content.ts", import.meta.url).pathname], outdir, target: "browser", format: "iife", naming: "content.js", minify: true });
await Bun.build({ entrypoints: [new URL("../src/popup.ts", import.meta.url).pathname], outdir, target: "browser", format: "esm", naming: "popup.js", minify: true });
for (const file of ["popup.html", "popup.css"]) {
  await Bun.write(`${outdir}/${file}`, Bun.file(new URL(`../${file}`, import.meta.url).pathname));
}
for (const [target, manifest] of [["chrome", "manifest.chrome.json"], ["firefox", "manifest.firefox.json"]] as const) {
  const targetDir = new URL(`../dist/${target}/`, import.meta.url).pathname;
  for (const file of ["background.js", "content.js", "popup.js", "popup.html", "popup.css"]) {
    await Bun.write(`${targetDir}/${file}`, Bun.file(`${outdir}/${file}`));
  }
  await Bun.write(`${targetDir}/manifest.json`, Bun.file(new URL(`../${manifest}`, import.meta.url).pathname));
}
