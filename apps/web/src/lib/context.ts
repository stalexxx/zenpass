import { ApiClient, AuthClient, SyncEngine, type LocalRepository } from "@zkpm/sdk";
import { CryptoWorkerClient } from "../crypto/worker-client.ts";
import { VaultSession } from "../vault/vault-session.ts";
import { Announcer } from "./announcer.ts";

export type View =
  | { name: "onboarding" }
  | { name: "unlock" }
  | { name: "vault"; itemId?: string }
  | { name: "import" }
  | { name: "export" }
  | { name: "devices" }
  | { name: "conflicts" };

/** Everything a view needs, assembled once at boot. Holds no plaintext
 * itself — VaultSession is the only piece that ever does, and it's
 * cleared on lock. */
export interface AppContext {
  api: ApiClient;
  auth: AuthClient;
  crypto: CryptoWorkerClient;
  repo: LocalRepository;
  sync: SyncEngine;
  vault: VaultSession;
  announcer: Announcer;
  online: boolean;
  navigate(view: View): void;
  resetInactivityTimer(): void;
  /** Fire-and-forget: kicks off a pull+pushAll cycle. Callers use this
   * right after a successful unlock/account creation so a newly created
   * item actually reaches the server soon, rather than only ever syncing
   * on the browser's `online` event (which never fires if the device was
   * never offline in the first place). Safe to call when locked or when
   * no sync trigger was provided (a no-op) — errors are swallowed by the
   * underlying trigger, matching App.tsx's own syncNow(). */
  triggerSync(): void;
}

export function createContext(opts: {
  api: ApiClient;
  auth: AuthClient;
  crypto: CryptoWorkerClient;
  repo: LocalRepository;
  announcer: Announcer;
  navigate(view: View): void;
  resetInactivityTimer(): void;
  triggerSync?(): void;
}): AppContext {
  const sync = new SyncEngine(opts.api, opts.repo);
  const vault = new VaultSession(opts.crypto, opts.repo, sync);
  return { ...opts, sync, vault, online: navigator.onLine, triggerSync: opts.triggerSync ?? (() => {}) };
}
