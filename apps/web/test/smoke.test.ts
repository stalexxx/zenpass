// Browser smoke test: boots the actual app shell (src/app.ts's view
// wiring) against a real DOM, completes onboarding end to end, and
// exercises a basic CRUD round trip — the rendered-page-level check
// docs/tasks/C01.md's "Required tests" asks for. Uses the same fake
// OPAQUE/backend doubles as the other UI tests (real crypto path, fake
// network), rather than a live backend/browser process, per the task's
// scope — see the completion report for why.
import { describe, expect, test } from "bun:test";
import { ApiClient, AuthClient } from "@zkpm/sdk";
import init from "crypto-wasm";
import { CryptoWorkerClient } from "../src/crypto/worker-client.ts";
import { IndexedDBLocalRepository } from "../src/db/indexeddb-repository.ts";
import { Announcer } from "../src/lib/announcer.ts";
import { createContext, type View } from "../src/lib/context.ts";
import { renderOnboarding } from "../src/views/onboarding.ts";
import { renderVault } from "../src/views/vault.ts";
import { renderUnlock } from "../src/views/unlock.ts";
import { createFakeFetch, createFakeCryptoWorker, fakeOpaqueClient } from "./helpers/fake-backend.ts";
import { hasAccountBundle } from "../src/vault/account-bundle.ts";
import { getOrCreateAccountId } from "../src/crypto/account-id.ts";

function type(input: HTMLInputElement, value: string): void {
  input.value = value;
  input.dispatchEvent(new Event("input", { bubbles: true }));
}
async function waitFor(predicate: () => boolean, timeoutMs = 8000): Promise<void> {
  const start = Date.now();
  while (!predicate()) {
    if (Date.now() - start > timeoutMs) throw new Error("waitFor: timed out");
    await new Promise((resolve) => setTimeout(resolve, 10));
  }
}

describe("browser smoke test", () => {
  test("app boots, onboarding completes, and a login item can be created, edited, and deleted", async () => {
    localStorage.clear();
    await init();
    const root = document.createElement("main");
    document.body.append(root);
    const announcer = new Announcer(document.body);
    const api = new ApiClient({ baseUrl: "http://vault.test.invalid", fetchImpl: createFakeFetch() });
    const auth = new AuthClient(api, fakeOpaqueClient);
    const cryptoClient = new CryptoWorkerClient(await createFakeCryptoWorker());
    const accountId = getOrCreateAccountId();
    const repo = new IndexedDBLocalRepository(`smoke-${crypto.randomUUID()}`);

    let current: View = { name: hasAccountBundle(accountId) ? "unlock" : "onboarding" };
    const ctx = createContext({
      api, auth, crypto: cryptoClient, repo, announcer,
      navigate: (view) => { current = view; renderCurrent(); },
      resetInactivityTimer: () => {},
    });
    function renderCurrent(): void {
      if (current.name === "onboarding") return renderOnboarding(root, ctx);
      if (current.name === "unlock") return renderUnlock(root, ctx);
      if (current.name === "vault") return renderVault(root, ctx, current.itemId);
    }
    renderCurrent();

    // 1. The app boots straight to onboarding for a fresh profile.
    expect(root.querySelector("h1")?.textContent).toBe("Create your vault");

    // 2. Complete registration (email + master password + recovery
    // reveal/confirm — the same real-crypto path as the onboarding
    // component test).
    const form = root.querySelector("form")!;
    type(form.querySelector("#email")!, "smoke@example.com");
    type(form.querySelector("#password")!, "a very long smoke test password");
    type(form.querySelector("#passwordConfirm")!, "a very long smoke test password");
    form.dispatchEvent(new Event("submit", { bubbles: true, cancelable: true }));
    await waitFor(() => root.querySelector(".recovery-key") !== null);
    const recoveryKey = (root.querySelector(".recovery-key") as HTMLElement).textContent!.trim();
    root.querySelector("button")!.dispatchEvent(new Event("click", { bubbles: true }));
    await waitFor(() => root.querySelector("#recoveryConfirm") !== null);
    const confirmForm = root.querySelector("form")!;
    type(confirmForm.querySelector("#recoveryConfirm")!, recoveryKey);
    confirmForm.dispatchEvent(new Event("submit", { bubbles: true, cancelable: true }));
    await waitFor(() => current.name === "vault", 10_000);

    // 3. Basic CRUD round trip in the vault view.
    expect(root.querySelector(".vault-layout")).not.toBeNull();
    expect(ctx.vault.list()).toEqual([]);

    await ctx.vault.saveItem({ type: "login", title: "Example Site", username: "smokeuser", password: "hunter2" });
    expect(ctx.vault.list().map((i) => i.title)).toEqual(["Example Site"]);

    const id = ctx.vault.list()[0].itemId;
    await ctx.vault.saveItem({ type: "login", title: "Example Site (renamed)", username: "smokeuser", password: "hunter2" }, id);
    expect(ctx.vault.getItemData(id)?.title).toBe("Example Site (renamed)");

    await ctx.vault.deleteItem(id);
    expect(ctx.vault.list()).toEqual([]);

    // 4. Lock actually clears in-memory state (also covered in depth by
    // test/vault-session.test.ts's lock-lifecycle suite).
    await ctx.vault.lock();
    expect(ctx.vault.isUnlocked).toBe(false);
    expect(ctx.vault.debugMemoryState()).toEqual({ itemCacheSize: 0, searchEntries: 0, selectedItemId: null, unlocked: false });
  }, 20_000);
});
