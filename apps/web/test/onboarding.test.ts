import { describe, expect, test } from "bun:test";
import { renderOnboarding } from "../src/views/onboarding.tsx";
import { buildTestContext } from "./helpers/context.ts";
import { loadAccountBundle } from "../src/vault/account-bundle.ts";
import { getOrCreateAccountId } from "../src/crypto/account-id.ts";

function type(input: HTMLInputElement, value: string): void {
  input.value = value;
  input.dispatchEvent(new Event("input", { bubbles: true }));
}

// Async submit handlers run a real Argon2id KDF derivation (deliberately
// slow, ~200ms+) via the real WASM binding, so a fixed short delay is not
// reliable — poll until the observable side effect we're waiting on
// actually happens.
async function waitFor(predicate: () => boolean, timeoutMs = 5000): Promise<void> {
  const start = Date.now();
  while (!predicate()) {
    if (Date.now() - start > timeoutMs) throw new Error("waitFor: timed out");
    await new Promise((resolve) => setTimeout(resolve, 10));
  }
}

describe("onboarding component", () => {
  test("registration requires revealing and correctly confirming the recovery key before the vault is usable", async () => {
    localStorage.clear();
    const { ctx, container, views } = await buildTestContext();
    renderOnboarding(container, ctx);

    const form = container.querySelector("form")!;
    type(form.querySelector("#email")!, "alice@example.com");
    type(form.querySelector("#password")!, "correct horse battery staple");
    type(form.querySelector("#passwordConfirm")!, "correct horse battery staple");
    form.dispatchEvent(new Event("submit", { bubbles: true, cancelable: true }));
    await waitFor(() => container.querySelector(".recovery-key") !== null);

    // Reveal step: the recovery key is shown, plainly labeled provisional.
    const pre = container.querySelector(".recovery-key") as HTMLElement;
    const shownKey = pre.textContent!.trim();
    expect(shownKey).toMatch(/^[0-9a-f]{64}$/);
    expect(container.textContent).toContain("Provisional format");
    expect(container.textContent).toMatch(/support cannot recover/i);

    container.querySelector("button")!.dispatchEvent(new Event("click", { bubbles: true }));
    await waitFor(() => container.querySelector("#recoveryConfirm") !== null);

    // A wrong entry is rejected and does not unlock the vault.
    let confirmForm = container.querySelector("form")!;
    let confirmInput = confirmForm.querySelector("#recoveryConfirm") as HTMLInputElement;
    type(confirmInput, "0".repeat(64));
    confirmForm.dispatchEvent(new Event("submit", { bubbles: true, cancelable: true }));
    await waitFor(() => /doesn't match/i.test(container.textContent ?? ""));
    expect(views).toEqual([]); // never navigated away on a wrong confirmation
    expect(loadAccountBundle(getOrCreateAccountId())).toBeNull(); // nothing persisted yet

    // The correct entry opens the vault and persists the wrapped bundle.
    confirmForm = container.querySelector("form")!;
    confirmInput = confirmForm.querySelector("#recoveryConfirm") as HTMLInputElement;
    type(confirmInput, shownKey);
    confirmForm.dispatchEvent(new Event("submit", { bubbles: true, cancelable: true }));
    await waitFor(() => views.length > 0, 10_000);
    expect(views).toEqual([{ name: "vault" }]);
    expect(ctx.vault.isUnlocked).toBe(true);
    expect(loadAccountBundle(getOrCreateAccountId())).not.toBeNull();
  }, 15_000);

  test("a weak or mismatched master password is rejected before any account is created", async () => {
    localStorage.clear();
    const { ctx, container } = await buildTestContext();
    renderOnboarding(container, ctx);
    const form = container.querySelector("form")!;
    type(form.querySelector("#email")!, "a@b.com");
    type(form.querySelector("#password")!, "short");
    type(form.querySelector("#passwordConfirm")!, "short");
    form.dispatchEvent(new Event("submit", { bubbles: true, cancelable: true }));
    await waitFor(() => /at least 12 characters/i.test(container.textContent ?? ""));
    expect(container.querySelector(".recovery-key")).toBeNull();
  });
});
