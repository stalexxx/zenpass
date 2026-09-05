// Top-level React tree: owns view-switching state and the effects that
// used to live as closured variables/listeners inside app.ts's bootApp
// (inactivity timer, beforeunload Worker teardown, online-triggered sync).
// The non-UI setup (constructing the SDK clients, the CryptoWorkerClient,
// the repository) still happens once, outside React, in `createAppDeps`
// below — React only owns rendering and view navigation state.
import { useEffect, useMemo, useRef, useState } from "react";
import type { ReactNode } from "react";
import { ApiClient, AuthClient, createWasmOpaqueClient } from "@zkpm/sdk";
import type { Conflict } from "@zkpm/sdk";
import { CryptoWorkerClient } from "./crypto/worker-client.ts";
import { IndexedDBLocalRepository } from "./db/indexeddb-repository.ts";
import { Announcer } from "./lib/announcer.ts";
import { createContext, type View } from "./lib/context.ts";
import { getOrCreateAccountId } from "./crypto/account-id.ts";
import { hasAccountBundle } from "./vault/account-bundle.ts";
import { Onboarding } from "./views/onboarding.tsx";
import { Unlock } from "./views/unlock.tsx";
import { Vault } from "./views/vault.tsx";
import { Import } from "./views/import.tsx";
import { Export } from "./views/export.tsx";
import { Devices } from "./views/devices.tsx";
import { Conflicts } from "./views/conflicts.tsx";
import { ExtensionSetup } from "./views/extension-setup.tsx";

const INACTIVITY_LOCK_MS = 5 * 60_000; // 5 minutes (docs/ux/flows.md: "Automatic lock triggers after inactivity")
const API_BASE_URL = (globalThis as { ZKPM_API_BASE_URL?: string }).ZKPM_API_BASE_URL ?? "http://localhost:8787";

export interface AppDeps {
  announcer: Announcer;
  api: ApiClient;
  auth: AuthClient;
  cryptoClient: CryptoWorkerClient;
  accountId: string;
  repo: IndexedDBLocalRepository;
}

/** Everything that must happen before the first render: construct the
 * WASM OPAQUE client, the SDK clients, the crypto Worker client, and the
 * local repository. Kept out of the React tree itself (it's async and has
 * no UI of its own) — main.tsx awaits this once, then mounts <App/>. */
export async function createAppDeps(root: HTMLElement): Promise<AppDeps> {
  const announcer = new Announcer(root.parentElement ?? root);
  const opaque = await createWasmOpaqueClient();
  const api = new ApiClient({ baseUrl: API_BASE_URL });
  const auth = new AuthClient(api, opaque);
  const cryptoClient = new CryptoWorkerClient();
  const accountId = getOrCreateAccountId();
  const repo = new IndexedDBLocalRepository(accountId);
  return { announcer, api, auth, cryptoClient, accountId, repo };
}

export function App({ announcer, api, auth, cryptoClient, accountId, repo }: AppDeps): ReactNode {
  const [view, setView] = useState<View>(() => (hasAccountBundle(accountId) ? { name: "unlock" } : { name: "onboarding" }));
  const [pendingConflicts, setPendingConflicts] = useState<Conflict[]>([]);

  // Mutable timer handle the inactivity resetter reads/writes — a plain
  // ref cell (not state) since the timer id itself never needs to trigger
  // a re-render.
  const timerRef = useRef<ReturnType<typeof setTimeout> | null>(null);

  // syncNow (below) closes over ctx/setPendingConflicts and so can only be
  // defined after ctx exists; triggerSync needs to be part of ctx itself
  // (unlock/onboarding call it right after establishing a session). This
  // ref breaks the cycle: ctx.triggerSync reads whatever syncNow the later
  // effect has stored here, defaulting to a no-op until then (there is
  // nothing to sync before a session exists anyway).
  const syncNowRef = useRef<() => void>(() => {});

  const ctx = useMemo(
    () =>
      createContext({
        api,
        auth,
        crypto: cryptoClient,
        repo,
        announcer,
        navigate: (next) => setView(next),
        triggerSync: () => { syncNowRef.current(); },
        resetInactivityTimer: () => {
          if (timerRef.current) clearTimeout(timerRef.current);
          timerRef.current = setTimeout(async () => {
            if (ctx.vault.isUnlocked) {
              await ctx.vault.lock();
              announcer.status("Locked due to inactivity.");
              setView({ name: "unlock" });
            }
          }, INACTIVITY_LOCK_MS);
        },
      }),
    // Constructed exactly once, mirroring the single `createContext` call
    // in the pre-migration bootApp.
    // eslint-disable-next-line react-hooks/exhaustive-deps
    [],
  );

  useEffect(() => {
    const handleActivity = () => {
      if (ctx.vault.isUnlocked) ctx.resetInactivityTimer();
    };
    const events = ["mousemove", "keydown", "click", "touchstart"] as const;
    for (const evt of events) document.addEventListener(evt, handleActivity);

    // Browser restart / reload never carries an unlocked state across
    // (the in-memory Worker session and VaultSession cache do not survive
    // a page reload at all) — this is inherent to the design, not
    // something to special-case: on boot we always start at "unlock" (or
    // "onboarding"), never at "vault" (see the useState initializer
    // above).
    const handleBeforeUnload = () => {
      // Best-effort: terminate the Worker so no session lingers past
      // navigation. A page reload discards this JS heap regardless.
      cryptoClient.terminate();
    };
    window.addEventListener("beforeunload", handleBeforeUnload);

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
          setPendingConflicts(conflicts);
          announcer.error(`${conflicts.length} sync conflict(s) need your attention.`);
        }
        await ctx.vault.refreshFromRepository();
      } catch {
        // Offline or transient network failure: SyncEngine's own
        // RETRYABLE state handles retry timing; nothing further to do
        // here.
      }
    }
    window.addEventListener("online", syncNow);
    syncNowRef.current = () => { syncNow(); };

    return () => {
      for (const evt of events) document.removeEventListener(evt, handleActivity);
      window.removeEventListener("beforeunload", handleBeforeUnload);
      window.removeEventListener("online", syncNow);
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  switch (view.name) {
    case "onboarding":
      return <Onboarding ctx={ctx} />;
    case "unlock":
      return <Unlock ctx={ctx} />;
    case "vault":
      if (!ctx.vault.isUnlocked) return <Unlock ctx={ctx} />;
      return <Vault ctx={ctx} initialItemId={view.itemId} />;
    case "import":
      if (!ctx.vault.isUnlocked) return <Unlock ctx={ctx} />;
      return <Import ctx={ctx} />;
    case "export":
      if (!ctx.vault.isUnlocked) return <Unlock ctx={ctx} />;
      return <Export ctx={ctx} />;
    case "devices":
      if (!ctx.vault.isUnlocked) return <Unlock ctx={ctx} />;
      return <Devices ctx={ctx} />;
    case "conflicts":
      if (!ctx.vault.isUnlocked) return <Unlock ctx={ctx} />;
      return <Conflicts ctx={ctx} conflicts={pendingConflicts} />;
    case "extension-setup":
      if (!ctx.vault.isUnlocked) return <Unlock ctx={ctx} />;
      return <ExtensionSetup ctx={ctx} />;
  }
}
