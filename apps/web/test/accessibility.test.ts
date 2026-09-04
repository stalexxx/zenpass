import { describe, expect, test } from "bun:test";

// Click handlers update React state asynchronously (React 18+ schedules
// even discrete-event updates through its own scheduler rather than
// flushing before `dispatchEvent` returns for a non-trusted synthetic
// event) — so, like the other view tests in this suite, poll for the
// resulting DOM change instead of asserting immediately after dispatch.
async function waitFor(predicate: () => boolean, timeoutMs = 5000): Promise<void> {
  const start = Date.now();
  while (!predicate()) {
    if (Date.now() - start > timeoutMs) throw new Error("waitFor: timed out");
    await new Promise((resolve) => setTimeout(resolve, 10));
  }
}
import { renderOnboarding } from "../src/views/onboarding.tsx";
import { renderUnlock } from "../src/views/unlock.tsx";
import { renderVault } from "../src/views/vault.tsx";
import { buildTestContext } from "./helpers/context.ts";
import { generateTestBundle } from "./helpers/bundle.ts";
import { saveAccountBundle } from "../src/vault/account-bundle.ts";

/** Every text/password/email/url/search/number input and select/textarea
 * must have an associated <label for="..."> (or be inside a <label>) —
 * docs/ux/flows.md: "use semantic labels". */
function assertAllControlsLabeled(root: HTMLElement): void {
  const controls = root.querySelectorAll("input, select, textarea");
  for (const control of controls) {
    const id = control.getAttribute("id");
    const hasFor = id && root.querySelector(`label[for="${id}"]`);
    const hasAriaLabel = control.hasAttribute("aria-label") || control.hasAttribute("aria-labelledby");
    const insideLabel = control.closest("label") !== null;
    expect(Boolean(hasFor || hasAriaLabel || insideLabel)).toBe(true);
  }
}

/** Every button must have discernible text content (not empty, not
 * relying on color/icon alone). */
function assertAllButtonsHaveText(root: HTMLElement): void {
  for (const button of root.querySelectorAll("button")) {
    expect((button.textContent ?? "").trim().length).toBeGreaterThan(0);
  }
}

describe("accessibility", () => {
  test("the aria-live announcer exposes a polite status region and an assertive alert region", async () => {
    const { ctx } = await buildTestContext();
    const polite = document.body.querySelector('[aria-live="polite"][role="status"]');
    const assertive = document.body.querySelector('[aria-live="assertive"][role="alert"]');
    expect(polite).not.toBeNull();
    expect(assertive).not.toBeNull();
    ctx.announcer.error("something failed");
  });

  test("onboarding form controls are all labeled and buttons have text", async () => {
    const { ctx, container } = await buildTestContext();
    renderOnboarding(container, ctx);
    assertAllControlsLabeled(container);
    assertAllButtonsHaveText(container);
  });

  test("unlock form controls are labeled", async () => {
    const { ctx, container } = await buildTestContext();
    const { bundle } = await generateTestBundle(ctx);
    await ctx.vault.lock();
    saveAccountBundle(bundle);
    renderUnlock(container, ctx);
    assertAllControlsLabeled(container);
    assertAllButtonsHaveText(container);
  });

  test("vault view controls are labeled, and the delete flow requires typed text confirmation (not color-only)", async () => {
    const { ctx, container } = await buildTestContext();
    await generateTestBundle(ctx);
    const id = await ctx.vault.saveItem({ type: "login", title: "GitHub", username: "octocat", password: "hunter2" });
    renderVault(container, ctx, id);
    assertAllControlsLabeled(container);
    assertAllButtonsHaveText(container);

    const deleteButton = [...container.querySelectorAll("button")].find((b) => b.textContent === "Delete")!;
    deleteButton.dispatchEvent(new Event("click", { bubbles: true }));
    await waitFor(() => container.querySelector("#deleteConfirm") !== null);

    // The confirmation gate is a required text input, not a checkbox or a
    // color-coded button alone.
    const confirmInput = container.querySelector("#deleteConfirm") as HTMLInputElement;
    expect(confirmInput).not.toBeNull();
    expect(confirmInput.type).not.toBe("checkbox");
    expect(confirmInput.required).toBe(true);
    expect(container.textContent).toMatch(/type the item's title/i);
  });

  test("every focusable control is reachable via tabIndex (no positive tabindex traps, nothing hidden from keyboard)", async () => {
    const { ctx, container } = await buildTestContext();
    await generateTestBundle(ctx);
    await ctx.vault.saveItem({ type: "note", title: "Note" });
    renderVault(container, ctx);
    for (const el of container.querySelectorAll("button, input, select, textarea, a[href]")) {
      const tabindex = el.getAttribute("tabindex");
      if (tabindex !== null) expect(Number(tabindex)).toBeLessThanOrEqual(0); // no positive tabindex (would break natural order)
      expect(el.hasAttribute("disabled") && el.getAttribute("aria-hidden") === "true").toBe(false);
    }
  });
});
