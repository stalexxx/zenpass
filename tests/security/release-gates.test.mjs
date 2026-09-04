import { expect, test } from "bun:test";
import { readdir } from "node:fs/promises";
import { join } from "node:path";

const sourceRoots = ["apps", "packages", "crates", "infra", ".github"];
const ignoredDirectories = new Set(["node_modules", "dist", "pkg", "coverage", ".git"]);
const secretPatterns = [
  /-----BEGIN (?:RSA |EC |OPENSSH |PGP )?PRIVATE KEY-----/,
  /(?:AKIA|ASIA)[A-Z0-9]{16}/,
  /gh[pousr]_[A-Za-z0-9]{20,}/,
];

async function trackedSourceFiles(root) {
  const found = [];
  async function walk(dir) {
    for (const entry of await readdir(dir, { withFileTypes: true })) {
      const path = join(dir, entry.name);
      if (entry.isDirectory()) {
        if (!ignoredDirectories.has(entry.name)) await walk(path);
      } else if (/\.(?:[cm]?[jt]sx?|json|ya?ml|toml|rs|sql|sh)$/.test(entry.name)) {
        found.push(path);
      }
    }
  }
  await walk(root);
  return found;
}

test("secret scan finds no committed private-key or live-token signatures in production sources", async () => {
  const files = (await Promise.all(sourceRoots.map(trackedSourceFiles))).flat();
  const findings = [];
  for (const file of files) {
    const contents = await Bun.file(file).text();
    if (secretPatterns.some((pattern) => pattern.test(contents))) findings.push(file);
  }
  expect(findings).toEqual([]);
});

test("SAST guard: production sources do not use dynamic code evaluation", async () => {
  const files = (await Promise.all(sourceRoots.map(trackedSourceFiles))).flat();
  const findings = [];
  for (const file of files) {
    const contents = await Bun.file(file).text();
    if (/\beval\s*\(|\bnew\s+Function\s*\(/.test(contents)) findings.push(file);
  }
  expect(findings).toEqual([]);
});

test("SBOM input: Bun resolves the complete workspace dependency graph", async () => {
  const child = Bun.spawn([process.execPath, "pm", "ls", "--all"], { cwd: process.cwd(), stdout: "pipe", stderr: "pipe" });
  const [exitCode, stdout, stderr] = await Promise.all([
    child.exited,
    new Response(child.stdout).text(),
    new Response(child.stderr).text(),
  ]);
  expect(exitCode, `${stdout}\n${stderr}`).toBe(0);
  expect(stdout).toContain("@zkpm/backend@workspace:");
  expect(stdout).toContain("crypto-wasm@workspace:");
});
