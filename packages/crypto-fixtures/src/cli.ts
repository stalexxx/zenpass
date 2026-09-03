import { spawn } from "node:child_process";
import { loadFixtures, type Case } from "./loader.ts";
import { ADAPTER_ENV_VAR, ADAPTER_PROTOCOL_VERSION } from "./constants.ts";

function usage(): never { console.error("usage: bun run src/cli.ts --mode=structure|full [--adapter <command>]"); process.exit(2); }
const args = process.argv.slice(2); const modeArg = args.find((a) => a.startsWith("--mode=")); const mode = modeArg?.slice(7) ?? "full";
if (mode !== "structure" && mode !== "full") usage();
const adapter = process.env[ADAPTER_ENV_VAR] ?? (args.includes("--adapter") ? args[args.indexOf("--adapter") + 1] : undefined);
try {
  const loaded = await loadFixtures();
  console.log(`structure: pass (${loaded.fixtures.length} fixtures, ${loaded.cases.length} adapter cases)`);
  if (mode === "structure") process.exit(0);
  if (!adapter) throw new Error(`adapter missing: set ${ADAPTER_ENV_VAR} or pass --adapter`);
  const responses = await runAdapter(adapter, loaded.cases);
  const expected = new Map(loaded.cases.map((c) => [c.caseId, c])); const got = new Set<string>();
  for (const r of responses) {
    if (got.has(r.caseId) || !expected.has(r.caseId)) throw new Error(`adapter returned unknown or duplicate case ${r.caseId}`); got.add(r.caseId);
    const c = expected.get(r.caseId)!; if (r.operation !== c.operation || r.outcome !== c.expected.outcome || (r.outcome === "reject" && r.error !== c.expected.error)) throw new Error(`adapter mismatch for ${r.caseId}`);
  }
  if (got.size !== loaded.cases.length) throw new Error(`adapter omitted cases (${loaded.cases.length - got.size})`);
  console.log(`adapter: pass (${got.size} cases); protocol=${ADAPTER_PROTOCOL_VERSION}`);
} catch (e) { console.error(`crypto-fixtures: ${(e as Error).message}`); process.exit(1); }

type Response = { caseId: string; operation: string; outcome: string; error?: string };
async function runAdapter(command: string, cases: Case[]): Promise<Response[]> {
  const parts = command.trim().split(/\s+/); const child = spawn(parts[0], parts.slice(1), { stdio: ["pipe", "pipe", "pipe"] });
  const lines = cases.map((c) => JSON.stringify({ protocol: ADAPTER_PROTOCOL_VERSION, caseId: c.caseId, operation: c.operation, inputs: c.inputs, expected: c.expected })).join("\n") + "\n";
  child.stdin.write(lines); child.stdin.end(); let out = ""; let err = ""; child.stdout.on("data", (d) => out += d); child.stderr.on("data", (d) => err += d);
  const code: number = await new Promise((resolve) => child.on("close", resolve)); if (code !== 0) throw new Error(`adapter exited ${code}${err ? ` (${err.trim().slice(0, 160)})` : ""}`);
  const result: Response[] = []; for (const line of out.split(/\r?\n/).filter(Boolean)) { let r: any; try { r = JSON.parse(line); } catch { throw new Error("adapter emitted malformed JSON"); } if (!r || typeof r.caseId !== "string" || typeof r.operation !== "string" || !["pass", "reject"].includes(r.outcome) || (r.outcome === "reject" && typeof r.error !== "string")) throw new Error("adapter emitted invalid response"); result.push(r); } return result;
}
