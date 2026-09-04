import { describe, expect, test } from "bun:test";
import { renderImport } from "../src/views/import.tsx";
import { renderExport, buildEncryptedExport } from "../src/views/export.tsx";
import { buildTestContext } from "./helpers/context.ts";
import { generateTestBundle } from "./helpers/bundle.ts";

function type(input: HTMLInputElement, value: string): void {
  input.value = value;
  input.dispatchEvent(new Event("input", { bubbles: true }));
}
async function waitFor(predicate: () => boolean, timeoutMs = 5000): Promise<void> {
  const start = Date.now();
  while (!predicate()) {
    if (Date.now() - start > timeoutMs) throw new Error("waitFor: timed out");
    await new Promise((resolve) => setTimeout(resolve, 10));
  }
}

describe("import", () => {
  test("shows a field-mapping preview with warnings before writing anything", async () => {
    const { ctx, container } = await buildTestContext();
    await generateTestBundle(ctx);
    renderImport(container, ctx);

    const csv = "title,username,password\nGitHub,octocat,hunter2\n,,x\n";
    const file = new File([csv], "export.csv", { type: "text/csv" });
    const input = container.querySelector("#file") as HTMLInputElement;
    Object.defineProperty(input, "files", { value: [file], configurable: true });
    input.dispatchEvent(new Event("change", { bubbles: true }));
    await waitFor(() => container.textContent!.includes("Preview:"));

    expect(container.textContent).toContain("1 item(s) found");
    expect(container.textContent).toMatch(/warning/i); // the titleless row is reported, not silently dropped
    expect(ctx.vault.list()).toEqual([]); // nothing written yet — preview only

    container.querySelector("button + button, button")!; // sanity: buttons exist
    const importButton = [...container.querySelectorAll("button")].find((b) => b.textContent?.startsWith("Import "))!;
    importButton.dispatchEvent(new Event("click", { bubbles: true }));
    await waitFor(() => ctx.vault.list().length > 0);
    expect(ctx.vault.list().map((i) => i.title)).toEqual(["GitHub"]);
  });
});

describe("export", () => {
  test("encrypted export never contains plaintext and requires no re-authentication", async () => {
    const { ctx, container } = await buildTestContext();
    const { bundle, password } = await generateTestBundle(ctx);
    await ctx.auth.login(bundle.accountId, password); // establishes an API session for the sync push below
    await ctx.vault.saveItem({ type: "login", title: "Bank", username: "alice", password: "s3cr3t-plaintext" });
    await ctx.sync.pushAll(); // encrypted export reads the repo's durable (post-sync) ciphertext, not the in-memory queue

    const json = await buildEncryptedExport(ctx);
    expect(json).not.toContain("s3cr3t-plaintext");
    expect(json).not.toContain("alice");
    expect(json).toContain("b64:");

    renderExport(container, ctx);
    // No password field is shown on the encrypted path.
    expect(container.querySelector("form")).toBeNull();
  });

  test("plaintext export is gated behind a typed confirmation and re-authentication", async () => {
    const { ctx, container } = await buildTestContext();
    await generateTestBundle(ctx);
    await ctx.vault.saveItem({ type: "login", title: "Bank", username: "alice", password: "s3cr3t-plaintext" });
    renderExport(container, ctx);

    const plaintextButton = [...container.querySelectorAll("button")].find((b) => b.textContent?.includes("Export as plaintext"))!;
    plaintextButton.dispatchEvent(new Event("click", { bubbles: true }));
    await waitFor(() => container.querySelector("input[aria-label]") !== null);

    // Wrong confirmation text does not advance to re-auth.
    const confirmInput = container.querySelector("input[aria-label]") as HTMLInputElement;
    type(confirmInput, "nope");
    container.querySelector("form")!.dispatchEvent(new Event("submit", { bubbles: true, cancelable: true }));
    expect(container.querySelector("#password")).toBeNull();

    // Correct confirmation text advances to the re-authentication step.
    type(confirmInput, "EXPORT PLAINTEXT");
    container.querySelector("form")!.dispatchEvent(new Event("submit", { bubbles: true, cancelable: true }));
    await waitFor(() => container.querySelector("#password") !== null);
    expect(container.textContent).toMatch(/re-enter your master password/i);
  });
});
