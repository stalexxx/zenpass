import { ApiClient, AuthClient, createWasmOpaqueClient } from "@zkpm/sdk";
import type { Conflict } from "@zkpm/sdk";
import { CryptoWorkerClient } from "./crypto/worker-client.ts";
import { IndexedDBLocalRepository } from "./db/indexeddb-repository.ts";
import { Announcer } from "./lib/announcer.ts";
import { createContext, type AppContext, type View } from "./lib/context.ts";
import { getOrCreateAccountId } from "./crypto/account-id.ts";
import { hasAccountBundle } from "./vault/account-bundle.ts";
import { renderOnboarding } from "./views/onboarding.ts";
import { renderUnlock } from "./views/unlock.ts";
import { renderVault } from "./views/vault.ts";
import { renderImport } from "./views/import.ts";
import { renderExport } from "./views/export.ts";
import { renderDevices } from "./views/devices.ts";
import { renderConflicts } from "./views/conflicts.ts";

const INACTIVITY_LOCK_MS = 5 * 60_000; // 5 minutes (docs/ux/flows.md: "Automatic lock triggers after inactivity")
const API_BASE_URL = (globalThis as { ZKPM_API_BASE_URL?: string }).ZKPM_API_BASE_URL ?? "http://localhost:8787";

export async function bootApp(root: HTMLElement): Promise<AppContext> {
  const announcer = new Announcer(root.parentElement ?? root);
  const opaque = await createWasmOpaqueClient();
  const api = new ApiClient({ baseUrl: API_BASE_URL });
  const auth = new AuthClient(api, opaque);
  const cryptoClient = new CryptoWorkerClient();
  const accountId = getOrCreateAccountId();
  const repo = new IndexedDBLocalRepository(accountId);

  let inactivityTimer: ReturnType<typeof setTimeout> | null = null;
  let pendingConflicts: Conflict[] = [];
  let current: View = { name: hasAccountBundle(accountId) ? "unlock" : "onboarding" };

  const ctx = createContext({
    api, auth, crypto: cryptoClient, repo, announcer,
    navigate: (view) => { current = view; renderCurrent(); },
    resetInactivityTimer: () => {
      if (inactivityTimer) clearTimeout(inactivityTimer);
      inactivityTimer = setTimeout(async () => {
        if (ctx.vault.isUnlocked) {
          await ctx.vault.lock();
          announcer.status("Locked due to inactivity.");
          current = { name: "unlock" };
          renderCurrent();
        }
      }, INACTIVITY_LOCK_MS);
    },
  });

  for (const evt of ["mousemove", "keydown", "click", "touchstart"] as const) {
    root.ownerDocument.addEventListener(evt, () => {
      if (ctx.vault.isUnlocked) ctx.resetInactivityTimer();
    });
  }

  // Browser restart / reload never carries an unlocked state across (the
  // in-memory Worker session and VaultSession cache do not survive a page
  // reload at all) — this is inherent to the design, not something to
  // special-case: on boot we always start at "unlock" (or "onboarding"),
  // never at "vault".
  window.addEventListener("beforeunload", () => {
    // Best-effort: terminate the Worker so no session lingers past
    // navigation. A page reload discards this JS heap regardless.
    cryptoClient.terminate();
  });

  async function syncNow(): Promise<void> {
    if (!ctx.vault.isUnlocked) return;
    try {
      await ctx.sync.pull(ctx.vault.accountBundle!.vaultId);
      const outcomes = await ctx.sync.pushAll();
      const conflicts: Conflict[] = [];
      for (const outcome of outcomes.values()) {
        if (outcome.kind === "conflict") conflicts.push(outcome.conflict);
      }
      if (conflicts.length > 0) {
        pendingConflicts = conflicts;
        announcer.error(`${conflicts.length} sync conflict(s) need your attention.`);
      }
      await ctx.vault.refreshFromRepository();
    } catch {
      // Offline or transient network failure: SyncEngine's own RETRYABLE
      // state handles retry timing; nothing further to do here.
    }
  }

  window.addEventListener("online", () => { syncNow(); });

  function renderCurrent(): void {
    switch (current.name) {
      case "onboarding": return renderOnboarding(root, ctx);
      case "unlock": return renderUnlock(root, ctx);
      case "vault":
        if (!ctx.vault.isUnlocked) { current = { name: "unlock" }; return renderUnlock(root, ctx); }
        return renderVault(root, ctx, current.itemId);
      case "import":
        if (!ctx.vault.isUnlocked) { current = { name: "unlock" }; return renderUnlock(root, ctx); }
        return renderImport(root, ctx);
      case "export":
        if (!ctx.vault.isUnlocked) { current = { name: "unlock" }; return renderUnlock(root, ctx); }
        return renderExport(root, ctx);
      case "devices":
        if (!ctx.vault.isUnlocked) { current = { name: "unlock" }; return renderUnlock(root, ctx); }
        return renderDevices(root, ctx);
      case "conflicts":
        if (!ctx.vault.isUnlocked) { current = { name: "unlock" }; return renderUnlock(root, ctx); }
        return renderConflicts(root, ctx, pendingConflicts);
    }
  }

  renderCurrent();
  return ctx;
}
