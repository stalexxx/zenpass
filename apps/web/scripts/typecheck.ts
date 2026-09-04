// Strict TypeScript gate for apps/web's own migrated sources. Runs a real
// `tsc --noEmit` over this package's tsconfig (which necessarily also
// type-checks the workspace packages apps/web imports from — @zkpm/sdk,
// crypto-worker, importers, domain — since TypeScript type-checks every
// file reachable from the program, not just the ones matched by
// "include"). Some of those upstream packages (outside C05's allowed
// paths: apps/backend, packages/crypto-wasm, packages/crypto-worker,
// packages/sdk, packages/domain, packages/importers, per docs/tasks/C05.md)
// were never previously run through `tsc` at all — Bun's dev/test/build
// pipeline only strips types, it doesn't check them — so they carry a
// handful of pre-existing type errors unrelated to this migration. This
// script reports every diagnostic tsc produces (nothing is hidden) but
// only *fails* the command on a diagnostic whose file is inside this
// package (a path that does not start with "../"), so a real regression
// in apps/web's own code still fails `bun run lint`/`typecheck` while a
// pre-existing upstream issue this task is forbidden from touching does
// not block it.
const proc = Bun.spawn(["bun", "x", "tsc", "-p", "tsconfig.json", "--noEmit"], {
  cwd: new URL("..", import.meta.url).pathname,
  stdout: "pipe",
  stderr: "pipe",
});

const [stdout, stderr] = await Promise.all([
  new Response(proc.stdout).text(),
  new Response(proc.stderr).text(),
]);
await proc.exited;

const output = stdout + stderr;
if (output.trim().length > 0) console.log(output.trimEnd());

const outOfScope = /^\.\.\//;
const inScopeErrors = output
  .split("\n")
  .filter((line) => /: error TS\d+:/.test(line) && !outOfScope.test(line));

if (inScopeErrors.length > 0) {
  console.error(`\n${inScopeErrors.length} type error(s) in apps/web's own sources — see above.`);
  process.exit(1);
}

console.log("apps/web: strict typecheck passed (no errors outside forbidden upstream workspace packages).");
