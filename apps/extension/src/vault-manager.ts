/**
 * Real `VaultManager` (ADR-0011 D1/D2/D3/D5/D6): independent OPAQUE login,
 * G2 bearer-session device enrollment, key-bundle fetch/opening via the
 * background-private `CryptoWorkerHost`/WASM adapter, in-memory item
 * cache built from the sync change feed, popup save/update, and TOTP
 * display/fill. Online-only: every secret display, fill, TOTP generation
 * and mutation revalidates a fresh authenticated check (at most 30s apart,
 * 5s network deadline) before proceeding; a network failure or 401 locks,
 * with no offline cached-data fallback. No wrapped-bundle cache, item
 * cache, or mutation queue is ever persisted (D4) — everything here lives
 * only in memory for the life of the unlocked session.
 */
import {
  ApiClient,
  AuthClient,
  HttpError,
  createWasmOpaqueClient,
  decodeB64,
  encodeB64,
  parseAccountBundle,
  type ApiClientOptions,
  type Mutation,
  type OpaqueClient,
} from "../../../packages/sdk/src/index.ts";
import { CryptoWorkerHost, type CryptoBackend } from "../../../packages/crypto-worker/src/index.ts";
import { createWasmBackend } from "../../../packages/crypto-worker/src/wasm-adapter.ts";
import { matchOrigin } from "../../../packages/domain/src/origin.ts";
import {
  computeTotp,
  secondsRemaining as totpSecondsRemaining,
  type FillFields,
  type ItemSummary,
  type LoginCandidate,
  type SaveItemInput,
  type SaveItemResult,
  type TotpDisplay,
  type UnlockResult,
  type VaultManager as VaultManagerInterface,
} from "../../../packages/extension-adapters/src/index.ts";
import { confirmApiOrigin, pinnedFetch } from "./origin.ts";
import { decodeItemData, encodeItemData, validateItemData, type VaultItemData } from "./item-codec.ts";

const KEY_VERSION = 1n;
const ENVELOPE_VERSION = "crypto-envelope/v1";
/** Matches apps/web's default (256 MiB) so both clients report the same
 * KDF resource envelope against the same C01 hierarchy. */
const DEFAULT_REPORTED_MEMORY_KIB = 262_144n;
/** D5: "at most 30 seconds apart" between fresh authenticated checks. */
const FRESH_CHECK_INTERVAL_MS = 30_000;
/** D5: "a 5-second network deadline". */
const NETWORK_DEADLINE_MS = 5_000;
/** Proactively rotate the bearer token this far ahead of its reported
 * expiry, so a fresh check doesn't race an expiring token. */
const REFRESH_MARGIN_MS = 30_000;

interface ItemEntry {
  itemId: string;
  revision: number;
  data: VaultItemData;
}

interface UnlockedState {
  api: ApiClient;
  host: CryptoWorkerHost;
  session: number;
  accountId: string;
  vaultId: string;
  accessTokenExpiresAt: string;
  items: Map<string, ItemEntry>;
}

export interface VaultManagerDeps {
  /** Non-secret, human-readable device name enrolled via G2's
   * bearer-session-v1 branch on every unlock. */
  deviceName: string;
  now?: () => number;
  reportedPhysicalMemoryKiB?: bigint;
  createApiClient?: (options: ApiClientOptions) => ApiClient;
  createOpaqueClient?: () => Promise<OpaqueClient>;
  createCryptoBackend?: () => Promise<CryptoBackend>;
  /** Called whenever a fresh authenticated check fails (network error or
   * 401) or a refresh fails — the caller's `BackgroundPolicy` uses this to
   * lock its own `SessionStateMachine` (bumping its generation) in lockstep
   * with this manager disposing its own state. */
  onAuthFailure?: () => void;
}

function nextId(counter: { n: number }): string {
  counter.n += 1;
  return String(counter.n);
}

/** Races a promise against a timeout. The SDK's `ApiClient` has no
 * AbortSignal wiring (out of this task's scope to add — `packages/sdk` is
 * a forbidden path), so a timed-out request may still resolve in the
 * background after this races it away; its result is simply never
 * observed, and the timeout itself is treated as a fresh-check/mutation
 * failure exactly like any other network error. */
function withDeadline<T>(promise: Promise<T>, ms: number): Promise<T> {
  return new Promise<T>((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error("network deadline exceeded")), ms);
    promise.then(
      (value) => { clearTimeout(timer); resolve(value); },
      (error) => { clearTimeout(timer); reject(error); },
    );
  });
}

export class ExtensionVaultManager implements VaultManagerInterface {
  readonly #now: () => number;
  readonly #deviceName: string;
  readonly #reportedPhysicalMemoryKiB: bigint;
  readonly #createApiClient: (options: ApiClientOptions) => ApiClient;
  readonly #createOpaqueClient: () => Promise<OpaqueClient>;
  readonly #createCryptoBackend: () => Promise<CryptoBackend>;
  readonly #onAuthFailure: () => void;
  readonly #idCounter = { n: 0 };
  #state: UnlockedState | null = null;
  #lastFreshCheckAt = 0;
  #refreshInFlight: Promise<void> | null = null;

  constructor(deps: VaultManagerDeps) {
    this.#now = deps.now ?? (() => Date.now());
    this.#deviceName = deps.deviceName;
    this.#reportedPhysicalMemoryKiB = deps.reportedPhysicalMemoryKiB ?? DEFAULT_REPORTED_MEMORY_KIB;
    this.#createApiClient = deps.createApiClient ?? ((options) => new ApiClient(options));
    this.#createOpaqueClient = deps.createOpaqueClient ?? createWasmOpaqueClient;
    this.#createCryptoBackend = deps.createCryptoBackend ?? createWasmBackend;
    this.#onAuthFailure = deps.onAuthFailure ?? (() => {});
  }

  isUnlocked(): boolean {
    return this.#state !== null;
  }

  /** Always starts from a clean slate: a failed unlock never leaves
   * partial state (a stale token, a live host session, etc.) lying around. */
  async unlock(accountId: string, apiOrigin: string, password: Uint8Array): Promise<UnlockResult> {
    this.#dispose();
    try {
      if (typeof accountId !== "string" || accountId.length === 0 || accountId.length > 256) {
        return { ok: false, reason: "unlock-failed" };
      }
      const confirmed = confirmApiOrigin(apiOrigin);
      if (!confirmed) return { ok: false, reason: "unlock-failed" };

      const api = this.#createApiClient({ baseUrl: confirmed.origin, fetchImpl: pinnedFetch(confirmed.origin) });
      const opaque = await this.#createOpaqueClient();
      const auth = new AuthClient(api, opaque);
      const session = await withDeadline(auth.login(accountId, password), NETWORK_DEADLINE_MS);

      // G2: bind this fresh, device-unbound session to its own named
      // device before anything else. If this fails, the whole unlock
      // fails closed — without a device binding, a server-side revoke
      // cannot invalidate this session (D5's revocation criterion).
      await withDeadline(api.registerBearerSessionDevice(this.#deviceName), NETWORK_DEADLINE_MS);

      const bundleOutcome = await withDeadline(api.getKeyBundle(), NETWORK_DEADLINE_MS);
      if (bundleOutcome.status !== 200) return { ok: false, reason: "unlock-failed" };
      const parsed = parseAccountBundle(bundleOutcome.keyBundle.bundle);
      if (!parsed || parsed.accountId !== accountId) return { ok: false, reason: "unlock-failed" };

      const backend = await this.#createCryptoBackend();
      const host = new CryptoWorkerHost(backend);
      const unlockResponse = host.handle({
        id: nextId(this.#idCounter),
        type: "unlock-item-session",
        password,
        kdfParametersCbor: decodeB64(parsed.kdfParametersCbor),
        reportedPhysicalMemoryKiB: this.#reportedPhysicalMemoryKiB,
        accountId: parsed.accountId,
        vaultId: parsed.vaultId,
        itemId: parsed.itemId,
        accountKeyVersion: KEY_VERSION,
        vaultKeyVersion: KEY_VERSION,
        itemKeyVersion: KEY_VERSION,
        wrappedAccountKey: decodeB64(parsed.wrappedAccountKey),
        wrappedVaultKey: decodeB64(parsed.wrappedVaultKey),
        wrappedItemKey: decodeB64(parsed.wrappedItemKey),
      });
      if (!unlockResponse.ok || unlockResponse.type !== "session") {
        host.dispose();
        return { ok: false, reason: "unlock-failed" };
      }

      const items = await this.#loadAllItems(api, host, unlockResponse.session, parsed.accountId, parsed.vaultId);
      this.#state = {
        api,
        host,
        session: unlockResponse.session,
        accountId: parsed.accountId,
        vaultId: parsed.vaultId,
        accessTokenExpiresAt: session.expiresAt,
        items,
      };
      this.#lastFreshCheckAt = this.#now();
      return { ok: true };
    } catch {
      this.#dispose();
      return { ok: false, reason: "unlock-failed" };
    } finally {
      password.fill(0);
    }
  }

  async #loadAllItems(
    api: ApiClient,
    host: CryptoWorkerHost,
    session: number,
    accountId: string,
    vaultId: string,
  ): Promise<Map<string, ItemEntry>> {
    const items = new Map<string, ItemEntry>();
    let cursor: string | undefined;
    for (;;) {
      let page;
      try {
        page = await withDeadline(api.listChanges(vaultId, cursor), NETWORK_DEADLINE_MS);
      } catch (error) {
        // A brand-new vault that has never had an item created returns 404
        // (the backend only auto-creates the vault row on first mutation)
        // — an empty vault must still unlock successfully (T07/T09), so
        // this is "no items yet", not a failure. Any other error still
        // propagates (network failure, 401, etc. all still fail closed).
        if (error instanceof HttpError && error.status === 404 && cursor === undefined) break;
        throw error;
      }
      for (const record of page.changes) {
        if (record.deleted) {
          items.delete(record.itemId);
          continue;
        }
        const opened = host.handle({
          id: nextId(this.#idCounter),
          type: "open-item-payload",
          session,
          accountId,
          vaultId,
          itemId: record.itemId,
          keyVersion: KEY_VERSION,
          envelope: decodeB64(record.ciphertext),
        });
        if (!opened.ok || opened.type !== "bytes") continue; // corrupt/foreign record: skip, never crash the whole load
        try {
          const data = decodeItemData(opened.bytes);
          items.set(record.itemId, { itemId: record.itemId, revision: record.revision, data });
        } catch {
          // malformed payload: skip, log nothing (may contain plaintext)
        }
      }
      // The backend's `/vaults/:id/changes` route (apps/backend/src/sync/
      // routes.mjs) returns the *same* nextCursor back — never null — on
      // an empty page once the vault has ever had a change (only a vault
      // that has *never* had one returns 404, handled above). So `!page.
      // nextCursor` is never a safe termination check once any item
      // exists: the correct signal that pagination has reached the end is
      // an empty page (no new changes), not a falsy cursor — using the
      // wrong check here previously caused this loop to never terminate.
      if (page.changes.length === 0 || !page.nextCursor) break;
      cursor = page.nextCursor;
    }
    return items;
  }

  /** Best-effort teardown of whatever unlocked state exists; always safe
   * to call, including when already locked. */
  #dispose(): void {
    const state = this.#state;
    this.#state = null;
    this.#lastFreshCheckAt = 0;
    this.#refreshInFlight = null;
    if (state) {
      try { state.host.dispose(); } catch { /* continue clearing */ }
      try { state.api.setAccessToken(null); } catch { /* continue clearing */ }
    }
  }

  #handleAuthFailure(): void {
    this.#dispose();
    try { this.#onAuthFailure(); } catch { /* never let a callback throw escape */ }
  }

  /** Purely local lock (no network call): see the interface doc comment. */
  lock(): void {
    this.#dispose();
  }

  /** Logout attempts server revocation but always clears local state in
   * `finally` — a failed logout cannot promise server revocation. */
  async logout(): Promise<void> {
    const state = this.#state;
    try {
      if (state) await withDeadline(state.api.logout(), NETWORK_DEADLINE_MS);
    } catch {
      // Best-effort only; local state clears below regardless.
    } finally {
      this.#dispose();
    }
  }

  async #maybeRefresh(state: UnlockedState): Promise<boolean> {
    if (this.#refreshInFlight) {
      try { await this.#refreshInFlight; } catch { return false; }
      return this.#state === state;
    }
    const msLeft = Date.parse(state.accessTokenExpiresAt) - this.#now();
    if (!Number.isFinite(msLeft) || msLeft > REFRESH_MARGIN_MS) return true;
    const attempt = (async () => {
      const refreshed = await withDeadline(state.api.refresh(), NETWORK_DEADLINE_MS);
      if (this.#state !== state) return; // locked/relocked during the refresh; drop it
      // Rotates the one in-memory token atomically; the old token is
      // never retried after this — `state.api` only ever holds one token.
      state.api.setAccessToken(refreshed.accessToken);
      state.accessTokenExpiresAt = refreshed.expiresAt;
    })();
    this.#refreshInFlight = attempt;
    try {
      await attempt;
      return this.#state === state;
    } catch {
      if (this.#state === state) this.#handleAuthFailure();
      return false;
    } finally {
      if (this.#refreshInFlight === attempt) this.#refreshInFlight = null;
    }
  }

  /** D5: the fresh authenticated check required before every
   * candidate/secret display, fill, TOTP generation and mutation, reused
   * within a rolling 30s window. */
  async checkFresh(): Promise<boolean> {
    const state = this.#state;
    if (!state) return false;
    const now = this.#now();
    if (now - this.#lastFreshCheckAt <= FRESH_CHECK_INTERVAL_MS) return true;
    if (!(await this.#maybeRefresh(state))) return false;
    if (this.#state !== state) return false;
    try {
      await withDeadline(state.api.listDevices(), NETWORK_DEADLINE_MS);
      if (this.#state !== state) return false; // superseded by a lock during the await
      this.#lastFreshCheckAt = this.#now();
      return true;
    } catch {
      if (this.#state === state) this.#handleAuthFailure();
      return false;
    }
  }

  candidatesFor(pageOrigin: string): readonly LoginCandidate[] {
    const state = this.#state;
    if (!state) return [];
    const result: LoginCandidate[] = [];
    for (const [itemId, entry] of state.items) {
      if (entry.data.type !== "login" && entry.data.type !== "totp-login") continue;
      if (!entry.data.url || !matchOrigin(entry.data.url, pageOrigin).matches) continue;
      result.push({ id: itemId, title: entry.data.title, origin: pageOrigin });
    }
    return result;
  }

  async fieldsFor(itemId: string, pageOrigin: string): Promise<FillFields | null> {
    const state = this.#state;
    if (!state) return null;
    if (!(await this.checkFresh()) || this.#state !== state) return null;
    const entry = state.items.get(itemId);
    if (!entry || !entry.data.url || !matchOrigin(entry.data.url, pageOrigin).matches) return null;
    const fields: FillFields = { username: entry.data.username ?? "", password: entry.data.password ?? "" };
    if (entry.data.type === "totp-login" && entry.data.totpSecret) {
      try {
        fields.totp = await computeTotp(entry.data.totpSecret, {}, this.#now());
      } catch {
        // A malformed seed omits the TOTP field rather than failing the
        // whole (still-valid) username/password fill.
      }
    }
    return this.#state === state ? fields : null;
  }

  async getTotp(itemId: string): Promise<TotpDisplay | null> {
    const state = this.#state;
    if (!state) return null;
    if (!(await this.checkFresh()) || this.#state !== state) return null;
    const entry = state.items.get(itemId);
    if (!entry || entry.data.type !== "totp-login" || !entry.data.totpSecret) return null;
    try {
      const code = await computeTotp(entry.data.totpSecret, {}, this.#now());
      if (this.#state !== state) return null;
      return { code, secondsRemaining: totpSecondsRemaining(30, this.#now()) };
    } catch {
      return null;
    }
  }

  listItems(): readonly ItemSummary[] {
    const state = this.#state;
    if (!state) return [];
    return [...state.items.values()].map((entry) => ({
      itemId: entry.itemId,
      title: entry.data.title,
      type: entry.data.type,
      username: entry.data.username,
      url: entry.data.url,
    }));
  }

  async saveItem(input: SaveItemInput): Promise<SaveItemResult> {
    const state = this.#state;
    if (!state) return { ok: false, reason: "locked" };
    const data: VaultItemData = {
      type: input.type,
      title: input.title,
      username: input.username,
      password: input.password,
      url: input.url,
      notes: input.notes,
      totpSecret: input.totpSecret,
    };
    const problems = validateItemData(data);
    if (problems.length > 0) return { ok: false, reason: "validation", problems };
    if (!(await this.checkFresh()) || this.#state !== state) return { ok: false, reason: "network" };

    const itemId = input.itemId ?? crypto.randomUUID();
    const baseRevision = input.itemId ? (state.items.get(input.itemId)?.revision ?? 0) : 0;
    let envelope: Uint8Array;
    try {
      const sealed = state.host.handle({
        id: nextId(this.#idCounter),
        type: "seal-item-payload",
        session: state.session,
        accountId: state.accountId,
        vaultId: state.vaultId,
        itemId,
        keyVersion: KEY_VERSION,
        plaintext: encodeItemData(data),
      });
      if (!sealed.ok || sealed.type !== "bytes") return { ok: false, reason: "locked" };
      envelope = sealed.bytes;
    } catch {
      return { ok: false, reason: "locked" };
    }

    const mutation: Mutation = {
      mutationId: crypto.randomUUID(),
      itemId,
      vaultId: state.vaultId,
      baseRevision,
      ciphertext: encodeB64(envelope),
      envelopeVersion: ENVELOPE_VERSION,
      deleted: false,
    };
    try {
      const outcome = await withDeadline(state.api.mutateItem(state.vaultId, mutation), NETWORK_DEADLINE_MS);
      if (this.#state !== state) return { ok: false, reason: "locked" };
      if (outcome.status === 409) return { ok: false, reason: "conflict" };
      state.items.set(itemId, { itemId, revision: outcome.item.revision, data });
      return { ok: true, itemId };
    } catch (error) {
      if (this.#state === state && error instanceof HttpError && error.status === 401) this.#handleAuthFailure();
      return { ok: false, reason: "network" };
    }
  }
}
