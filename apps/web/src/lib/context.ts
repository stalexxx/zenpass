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
}

export function createContext(opts: {
  api: ApiClient;
  auth: AuthClient;
  crypto: CryptoWorkerClient;
  repo: LocalRepository;
  announcer: Announcer;
  navigate(view: View): void;
  resetInactivityTimer(): void;
}): AppContext {
  const sync = new SyncEngine(opts.api, opts.repo);
  const vault = new VaultSession(opts.crypto, opts.repo, sync);
  return { ...opts, sync, vault, online: navigator.onLine };
}
