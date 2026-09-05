// ADR-0011 G1/D1: explicit web publication of the account key bundle and
// copyable accountId (apps/web/src/views/extension-setup.tsx).
import { describe, expect, test } from "bun:test";
import { renderExtensionSetup } from "../src/views/extension-setup.tsx";
import { buildTestContext } from "./helpers/context.ts";
import { generateTestBundle } from "./helpers/bundle.ts";
import { buildAccountBundle } from "@zkpm/sdk";
import { getOrCreateAccountId } from "../src/crypto/account-id.ts";

async function waitFor(predicate: () => boolean, timeoutMs = 5000): Promise<void> {
  const start = Date.now();
  while (!predicate()) {
    if (Date.now() - start > timeoutMs) throw new Error("waitFor: timed out");
    await new Promise((resolve) => setTimeout(resolve, 10));
  }
}

describe("extension setup view", () => {
  test("shows the copyable accountId and publishes the key bundle on first use", async () => {
    localStorage.clear();
    const { ctx, container } = await buildTestContext();
    // The extension-setup view reads getOrCreateAccountId() (the same
    // client-local id onboarding.tsx uses for both registration and the
    // bundle it creates) — match that here so the published bundle's own
    // `accountId` field lines up with what the view displays.
    const { bundle } = await generateTestBundle(ctx, getOrCreateAccountId());
    renderExtensionSetup(container, ctx);

    expect(container.textContent).toContain(bundle.accountId);

    const publishButton = [...container.querySelectorAll("button")].find((b) => /publish key bundle/i.test(b.textContent ?? ""))!;
    publishButton.dispatchEvent(new Event("click", { bubbles: true }));

    await waitFor(() => /published\./i.test(container.textContent ?? ""));

    const stored = await ctx.api.getKeyBundle();
    expect(stored.status).toBe(200);
    if (stored.status === 200) {
      expect(stored.keyBundle.version).toBe(1);
      expect(stored.keyBundle.bundle).toBe(buildAccountBundle(bundle));
    }
  });

  test("a conflicting remote bundle is never overwritten; the view reports a conflict instead", async () => {
    const foreignBundle = buildAccountBundle({
      accountId: "some-other-account",
      vaultId: "v",
      itemId: "i",
      kdfParametersCbor: new Uint8Array([1]),
      wrappedAccountKey: new Uint8Array([1]),
      wrappedVaultKey: new Uint8Array([1]),
      wrappedItemKey: new Uint8Array([1]),
      wrappedRecoveryKey: new Uint8Array([1]),
    });
    localStorage.clear();
    const { ctx, container } = await buildTestContext({ seedKeyBundle: { bundle: foreignBundle, version: 1 } });
    await generateTestBundle(ctx, getOrCreateAccountId());
    renderExtensionSetup(container, ctx);

    const publishButton = [...container.querySelectorAll("button")].find((b) => /publish key bundle/i.test(b.textContent ?? ""))!;
    publishButton.dispatchEvent(new Event("click", { bubbles: true }));

    await waitFor(() => /already published/i.test(container.textContent ?? ""));

    // The foreign bundle must still be exactly what's stored — nothing was
    // overwritten by the failed publish attempt.
    const stored = await ctx.api.getKeyBundle();
    expect(stored.status).toBe(200);
    if (stored.status === 200) expect(stored.keyBundle.bundle).toBe(foreignBundle);
  });

  test("copy button writes the accountId to the clipboard", async () => {
    localStorage.clear();
    const { ctx, container } = await buildTestContext();
    const { bundle } = await generateTestBundle(ctx, getOrCreateAccountId());
    let written = "";
    Object.defineProperty(navigator, "clipboard", {
      configurable: true,
      value: { writeText: async (v: string) => { written = v; } },
    });
    renderExtensionSetup(container, ctx);
    const copyButton = [...container.querySelectorAll("button")].find((b) => /copy account id/i.test(b.textContent ?? ""))!;
    copyButton.dispatchEvent(new Event("click", { bubbles: true }));
    await waitFor(() => written.length > 0);
    expect(written).toBe(bundle.accountId);
  });
});
