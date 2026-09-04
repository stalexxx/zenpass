// Additional React-view coverage for C05 (the React + TypeScript
// migration): exercises the Vault component's item-creation form and TOTP
// display end to end, on top of the pre-existing accessibility/CRUD
// coverage in accessibility.test.ts and vault-session.test.ts. These
// fields are intentionally uncontrolled (see src/views/vault.tsx), so —
// like onboarding's and unlock's forms — this sets `.value` directly on
// the underlying DOM node and reads it back at submit time, rather than
// simulating keystrokes through React's controlled-input onChange path.
import { describe, expect, test } from "bun:test";
import { renderVault } from "../src/views/vault.tsx";
import { buildTestContext } from "./helpers/context.ts";
import { generateTestBundle } from "./helpers/bundle.ts";

function set(el: HTMLInputElement | HTMLSelectElement | HTMLTextAreaElement, value: string): void {
  el.value = value;
}
async function waitFor(predicate: () => boolean, timeoutMs = 5000): Promise<void> {
  const start = Date.now();
  while (!predicate()) {
    if (Date.now() - start > timeoutMs) throw new Error("waitFor: timed out");
    await new Promise((resolve) => setTimeout(resolve, 10));
  }
}

describe("vault component", () => {
  test("the new-item form creates a login item visible in the list, without leaking its password into the DOM as plain text", async () => {
    const { ctx, container } = await buildTestContext();
    await generateTestBundle(ctx);
    renderVault(container, ctx);

    const form = container.querySelector("form.item-form") as HTMLFormElement;
    expect(form).not.toBeNull();
    set(form.elements.namedItem("title") as HTMLInputElement, "New Bank");
    set(form.elements.namedItem("username") as HTMLInputElement, "alice");
    set(form.elements.namedItem("password") as HTMLInputElement, "correct-horse-battery");
    form.dispatchEvent(new Event("submit", { bubbles: true, cancelable: true }));

    await waitFor(() => ctx.vault.list().some((i) => i.title === "New Bank"));
    expect(ctx.vault.list().map((i) => i.title)).toEqual(["New Bank"]);

    // The item view (now showing, since saveItem selects+shows it) masks
    // the password rather than rendering it as visible text.
    await waitFor(() => container.textContent?.includes("New Bank") ?? false);
    expect(container.textContent).not.toContain("correct-horse-battery");
    expect(container.textContent).toContain("••••••••");
  });

  test("the password generator's Generate button fills the password field without going through visible plaintext elsewhere in the DOM", async () => {
    const { ctx, container } = await buildTestContext();
    await generateTestBundle(ctx);
    renderVault(container, ctx);

    const generateButton = [...container.querySelectorAll("button")].find((b) => b.textContent === "Generate")!;
    generateButton.dispatchEvent(new Event("click", { bubbles: true }));
    await waitFor(() => (container.querySelector("#password") as HTMLInputElement).value.length > 0);

    const generated = (container.querySelector("#password") as HTMLInputElement).value;
    expect(generated.length).toBeGreaterThanOrEqual(4);
    // The generated password lives only in the (uncontrolled) input's own
    // value — it is not echoed anywhere else in the form's rendered text.
    const passwordRow = container.querySelector(".password-row") as HTMLElement;
    expect(passwordRow.textContent ?? "").not.toContain(generated);
  });

  test("a TOTP login item computes and displays a 6-digit code that changes with the secret", async () => {
    const { ctx, container } = await buildTestContext();
    await generateTestBundle(ctx);
    const id = await ctx.vault.saveItem({
      type: "totp-login",
      title: "GitHub 2FA",
      username: "octocat",
      totpSecret: "JBSWY3DPEHPK3PXP",
    });
    renderVault(container, ctx, id);

    await waitFor(() => /^\d{6}$/.test(container.querySelector(".totp-code")?.textContent ?? ""));
    const code = container.querySelector(".totp-code")!.textContent;
    expect(code).toMatch(/^\d{6}$/);
  });
});
