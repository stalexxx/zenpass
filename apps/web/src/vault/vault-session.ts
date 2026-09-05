// Central orchestrator tying the crypto Worker, the encrypted local
// repository, and the SDK's SyncEngine together into "unlock, use, lock".
// This is the one place in apps/web that holds decrypted item data in
// memory (docs/ux/flows.md: "Lock clears the in-memory key handles, search
// index, selected item, and clipboard timer") — everything it hands back
// to the UI is plaintext-shaped, but nothing it touches is ever persisted,
// logged, or transmitted as plaintext; persistence always goes through
// `CryptoWorkerClient.sealItemPayload` first.
import { decodeB64, encodeB64, type Conflict, type Id, type ItemRecord, type LocalRepository, type Mutation, type SyncEngine } from "@zkpm/sdk";
import type { CryptoWorkerClient } from "../crypto/worker-client.ts";
import type { AccountBundle } from "./account-bundle.ts";
import { decodeItemData, encodeItemData, validateItemData, type VaultItemData } from "./item-codec.ts";
import { searchItems, type SearchEntry } from "./search.ts";

const KEY_VERSION = 1n;
const ENVELOPE_VERSION = "crypto-envelope/v1";
/** How long a clipboard copy is kept before this app clears it again
 * (T15: "Minimize copying, clear clipboard where possible"). */
export const CLIPBOARD_CLEAR_MS = 20_000;

export interface DecryptedConflict {
  mutationId: Id;
  current: { revision: number; data: VaultItemData; updatedAt: string };
  attempted: { baseRevision: number; data: VaultItemData };
}

export class VaultSession {
  private session: number | null = null;
  private bundle: AccountBundle | null = null;
  private itemCache = new Map<Id, VaultItemData>();
  private revisionCache = new Map<Id, number>();
  private deletedLocally = new Set<Id>();
  private clipboardTimer: ReturnType<typeof setTimeout> | null = null;
  selectedItemId: Id | null = null;

  /** Monotonic token bumped by `lock()` and by every unlock (a fresh
   * session — whether re-unlocking the same account or switching to a
   * different one). Every async method that writes decrypted data into
   * `itemCache` (or returns cached data) captures this before its first
   * `await` and re-checks it, via `isGenerationCurrent`, immediately
   * before every subsequent touch of the cache. `lock()` clears the
   * cache synchronously, but an operation already in flight when
   * `lock()` runs would otherwise resume afterwards and unconditionally
   * repopulate it with plaintext (GitHub issue #5) — this token is what
   * lets a resumed operation notice its session ended and drop the
   * write instead. It intentionally does *not* gate
   * `sync.enqueueEdit`/`sync.resolveConflict`: the encrypted mutation
   * queue is durable state that must still be persisted even if the
   * session that produced it has since locked — only the plaintext
   * cache write/return path is invalidated. */
  private generation = 0;

  /** True only if no `lock()`/unlock has happened since `generation` was
   * captured, and the session is (still) unlocked. Call immediately
   * before every plaintext cache write or read that follows an
   * `await`. */
  private isGenerationCurrent(generation: number): boolean {
    return generation === this.generation && this.session !== null;
  }

  constructor(
    private readonly client: CryptoWorkerClient,
    private readonly repo: LocalRepository,
    private readonly sync: SyncEngine,
  ) {}

  get isUnlocked(): boolean {
    return this.session !== null;
  }

  get accountBundle(): AccountBundle | null {
    return this.bundle;
  }

  async unlockWithPassword(bundle: AccountBundle, password: Uint8Array, reportedPhysicalMemoryKiB = 262_144n): Promise<void> {
    this.generation += 1;
    this.session = await this.client.unlockItemSession({
      password,
      kdfParametersCbor: bundle.kdfParametersCbor,
      reportedPhysicalMemoryKiB,
      accountId: bundle.accountId,
      vaultId: bundle.vaultId,
      itemId: bundle.itemId,
      accountKeyVersion: KEY_VERSION,
      vaultKeyVersion: KEY_VERSION,
      itemKeyVersion: KEY_VERSION,
      wrappedAccountKey: bundle.wrappedAccountKey,
      wrappedVaultKey: bundle.wrappedVaultKey,
      wrappedItemKey: bundle.wrappedItemKey,
    });
    this.bundle = bundle;
    await this.loadAllItemsIntoMemory();
  }

  async unlockWithRecovery(bundle: AccountBundle, recoveryKey: Uint8Array): Promise<void> {
    this.generation += 1;
    this.session = await this.client.unlockItemSessionWithRecovery({
      recoveryKey,
      accountId: bundle.accountId,
      vaultId: bundle.vaultId,
      itemId: bundle.itemId,
      accountKeyVersion: KEY_VERSION,
      vaultKeyVersion: KEY_VERSION,
      itemKeyVersion: KEY_VERSION,
      wrappedAccountKey: bundle.wrappedRecoveryKey,
      wrappedVaultKey: bundle.wrappedVaultKey,
      wrappedItemKey: bundle.wrappedItemKey,
    });
    this.bundle = bundle;
    await this.loadAllItemsIntoMemory();
  }

  private async loadAllItemsIntoMemory(): Promise<void> {
    if (this.session === null || !this.bundle) return;
    // Captured before any `await`: `this.session`/`this.bundle` may be
    // cleared by a concurrent `lock()` (or replaced by a concurrent
    // unlock) while this method is suspended below, so every subsequent
    // line uses these locals instead of re-reading `this.session`/
    // `this.bundle` — and `isGenerationCurrent(generation)` gates every
    // write into `itemCache`/`deletedLocally`.
    const generation = this.generation;
    const session = this.session;
    const bundle = this.bundle;
    const records = await this.repo.listItems(bundle.vaultId);
    if (!this.isGenerationCurrent(generation)) return;
    for (const record of records) {
      if (!this.isGenerationCurrent(generation)) return;
      this.revisionCache.set(record.itemId, record.revision);
      if (record.deleted) {
        this.deletedLocally.add(record.itemId);
        continue;
      }
      try {
        const plaintext = await this.client.openItemPayload(
          session, bundle.accountId, bundle.vaultId, record.itemId, KEY_VERSION, decodeB64(record.ciphertext),
        );
        if (!this.isGenerationCurrent(generation)) return;
        this.itemCache.set(record.itemId, decodeItemData(plaintext));
      } catch {
        // A record that fails to decrypt/parse (corrupt, wrong envelope
        // version, etc.) is skipped rather than crashing the whole vault
        // load. No plaintext or key material is available to log here in
        // any case; only the non-secret itemId would be, and this module
        // deliberately logs nothing.
      }
    }
    if (!this.isGenerationCurrent(generation)) return;
    // A create/edit is durably queued (LocalRepository.enqueueMutation)
    // *before* any network call — see SyncEngine.enqueueEdit — but only
    // lands in the confirmed `items` store once the server accepts it
    // (SyncEngine.pushOne's 201 path). Sync itself only runs opportunistically
    // (apps/web/src/App.tsx's `online` handler), so a newly created item can
    // sit queued-but-unconfirmed indefinitely (e.g. this device never sees an
    // offline->online transition, or the server is briefly unreachable).
    // Without this overlay, a fresh unlock would only ever see confirmed
    // records and the item would look silently lost, even though its
    // ciphertext is safely persisted in the queue. CONFLICT entries are
    // deliberately excluded — those need explicit caller resolution
    // (ctx.vault.decryptConflict/resolveConflict), not a plain overlay.
    const queued = await this.repo.listQueuedMutations();
    if (!this.isGenerationCurrent(generation)) return;
    for (const entry of queued) {
      if (!this.isGenerationCurrent(generation)) return;
      if (entry.state === "CONFLICT") continue;
      const { mutation } = entry;
      if (mutation.vaultId !== bundle.vaultId) continue;
      if (mutation.deleted) {
        this.deletedLocally.add(mutation.itemId);
        continue;
      }
      try {
        const plaintext = await this.client.openItemPayload(
          session, bundle.accountId, bundle.vaultId, mutation.itemId, KEY_VERSION, decodeB64(mutation.ciphertext),
        );
        if (!this.isGenerationCurrent(generation)) return;
        this.itemCache.set(mutation.itemId, decodeItemData(plaintext));
        this.deletedLocally.delete(mutation.itemId);
      } catch {
        // Same rationale as above: skip, log nothing.
      }
    }
  }

  /** Lock: clears the in-memory key handle (via the Worker), the search
   * index, the selected item, and the clipboard timer — per
   * docs/ux/flows.md. Safe to call when already locked. */
  async lock(): Promise<void> {
    try {
      if (this.session !== null) await this.client.lock();
    } finally {
      // Bumped first (and unconditionally, even if `this.client.lock()`
      // above threw): any save/load/resolveConflict already in flight
      // captured the old generation before its first `await` and will
      // see this mismatch the next time it checks, so it drops its
      // plaintext cache write instead of repopulating the cache this
      // block is about to clear (GitHub issue #5).
      this.generation += 1;
      this.session = null;
      this.bundle = null;
      this.itemCache.clear();
      this.revisionCache.clear();
      this.deletedLocally.clear();
      this.selectedItemId = null;
      this.clearClipboardTimer();
    }
  }

  /** Everything currently visible in memory, for a lock-lifecycle test to
   * assert is truly empty after lock(). */
  debugMemoryState(): { itemCacheSize: number; searchEntries: number; selectedItemId: Id | null; unlocked: boolean } {
    return {
      itemCacheSize: this.itemCache.size,
      searchEntries: this.listVisible().length,
      selectedItemId: this.selectedItemId,
      unlocked: this.isUnlocked,
    };
  }

  /** `itemCache` should already be empty post-lock (`lock()` clears it
   * synchronously), but this defensively refuses to surface anything
   * while locked in case a stale in-flight write (already dropped by its
   * own generation check) raced this read, or any other residual state
   * survives. */
  private listVisible(): SearchEntry[] {
    if (this.session === null) return [];
    const entries: SearchEntry[] = [];
    for (const [itemId, data] of this.itemCache) {
      if (this.deletedLocally.has(itemId)) continue;
      entries.push({ itemId, title: data.title, username: data.username, url: data.url, type: data.type });
    }
    return entries;
  }

  list(): SearchEntry[] {
    return this.listVisible();
  }

  search(query: string): SearchEntry[] {
    return searchItems(this.listVisible(), query);
  }

  /** See `listVisible`'s note: defensively refuses cached data while
   * locked, even though the cache should already be empty. */
  getItemData(itemId: Id): VaultItemData | null {
    if (this.session === null) return null;
    if (this.deletedLocally.has(itemId)) return null;
    return this.itemCache.get(itemId) ?? null;
  }

  private requireUnlocked(): { session: number; bundle: AccountBundle } {
    if (this.session === null || !this.bundle) throw new Error("vault is locked");
    return { session: this.session, bundle: this.bundle };
  }

  /** Validates, encrypts, and queues a create/edit. Returns the itemId
   * (freshly generated for a create). Updates the in-memory cache
   * optimistically so the UI reflects the edit immediately, ahead of the
   * sync engine actually pushing it.
   *
   * The encrypted mutation is always sealed and enqueued (durable,
   * ciphertext-only work that must survive a concurrent `lock()`), but
   * the optimistic plaintext cache write at the end is skipped if the
   * session generation captured before this method's first `await`
   * no longer matches — i.e. `lock()` (or a re-unlock/account switch)
   * ran while `sealItemPayload`/`enqueueEdit` was in flight. Without
   * this, a slow save completing after `lock()` would silently
   * repopulate `itemCache` with plaintext post-lock (GitHub issue #5). */
  async saveItem(data: VaultItemData, itemId?: Id): Promise<Id> {
    const problems = validateItemData(data);
    if (problems.length > 0) throw new Error(problems.join(" "));
    const { session, bundle } = this.requireUnlocked();
    const generation = this.generation;
    const id = itemId ?? crypto.randomUUID();
    const plaintext = encodeItemData(data);
    const envelope = await this.client.sealItemPayload(session, bundle.accountId, bundle.vaultId, id, KEY_VERSION, plaintext);
    const mutation: Mutation = {
      mutationId: crypto.randomUUID(),
      itemId: id,
      vaultId: bundle.vaultId,
      baseRevision: this.revisionCache.get(id) ?? 0,
      ciphertext: encodeB64(envelope),
      envelopeVersion: ENVELOPE_VERSION,
      deleted: false,
    };
    await this.sync.enqueueEdit(mutation);
    if (this.isGenerationCurrent(generation)) {
      this.itemCache.set(id, data);
      this.deletedLocally.delete(id);
    }
    return id;
  }

  /** Confirmation-gating is the caller's (UI's) job — this always deletes
   * once called. Creates a tombstone mutation and returns its mutationId
   * so the caller can offer local undo while it remains unsynced. */
  async deleteItem(itemId: Id): Promise<Id> {
    const { session, bundle } = this.requireUnlocked();
    const data = this.itemCache.get(itemId);
    if (!data) throw new Error("unknown item");
    const plaintext = encodeItemData(data);
    const envelope = await this.client.sealItemPayload(session, bundle.accountId, bundle.vaultId, itemId, KEY_VERSION, plaintext);
    const mutation: Mutation = {
      mutationId: crypto.randomUUID(),
      itemId,
      vaultId: bundle.vaultId,
      baseRevision: this.revisionCache.get(itemId) ?? 0,
      ciphertext: encodeB64(envelope),
      envelopeVersion: ENVELOPE_VERSION,
      deleted: true,
    };
    await this.sync.enqueueEdit(mutation);
    this.deletedLocally.add(itemId);
    if (this.selectedItemId === itemId) this.selectedItemId = null;
    return mutation.mutationId;
  }

  /** Undo a delete while its tombstone mutation is still only local
   * (queued, not yet applied by the server). Returns false if the
   * mutation is no longer queued (already synced) — the caller must
   * re-save the item to restore it (a new mutation, not this undo path),
   * per docs/ux/flows.md: "undo is available while the tombstone remains
   * local". */
  async undoDeleteIfLocal(mutationId: Id, itemId: Id): Promise<boolean> {
    const queued = await this.repo.getQueuedMutation(mutationId);
    if (!queued || queued.state === "LOCAL_CLEAN") return false;
    await this.repo.dequeueMutation(mutationId);
    this.deletedLocally.delete(itemId);
    return true;
  }

  /** Cancels any pending auto-clear timer, without touching the clipboard
   * itself — used when a fresh copy supersedes the previous timer. */
  private cancelClipboardTimer(): void {
    if (this.clipboardTimer !== null) {
      clearTimeout(this.clipboardTimer);
      this.clipboardTimer = null;
    }
  }

  /** Cancels the timer and best-effort clears the clipboard right now
   * (T15) — called on lock, not on every copy. Some browsers require a
   * user gesture / focused document for a clipboard write to succeed
   * outside of the original copy's own gesture, so failures are
   * swallowed — this is defense in depth alongside the timer, not the
   * only mitigation. */
  private clearClipboardTimer(): void {
    this.cancelClipboardTimer();
    if (typeof navigator !== "undefined" && navigator.clipboard?.writeText) {
      navigator.clipboard.writeText("").catch(() => {});
    }
  }

  /** Copies `value` to the clipboard and schedules it to be cleared again
   * after CLIPBOARD_CLEAR_MS (T15). Locking also clears any pending timer
   * and best-effort clears the clipboard immediately. */
  async copyToClipboard(value: string): Promise<void> {
    this.cancelClipboardTimer();
    await navigator.clipboard.writeText(value);
    this.clipboardTimer = setTimeout(() => {
      navigator.clipboard.writeText("").catch(() => {});
      this.clipboardTimer = null;
    }, CLIPBOARD_CLEAR_MS);
  }

  /** Decrypts both sides of a sync Conflict for a field-level comparison
   * view. SyncEngine never decrypts (it hands back opaque ciphertext) —
   * this is the one place that does, using the still-open session. */
  async decryptConflict(conflict: Conflict): Promise<DecryptedConflict> {
    const { session, bundle } = this.requireUnlocked();
    const currentPlaintext = await this.client.openItemPayload(
      session, bundle.accountId, bundle.vaultId, conflict.current.itemId, KEY_VERSION, decodeB64(conflict.current.ciphertext),
    );
    const attemptedPlaintext = await this.client.openItemPayload(
      session, bundle.accountId, bundle.vaultId, conflict.attempted.itemId, KEY_VERSION, decodeB64(conflict.attempted.ciphertext),
    );
    return {
      mutationId: conflict.mutationId,
      current: { revision: conflict.current.revision, data: decodeItemData(currentPlaintext), updatedAt: conflict.current.updatedAt },
      attempted: { baseRevision: conflict.attempted.baseRevision, data: decodeItemData(attemptedPlaintext) },
    };
  }

  /** Resolves a conflict by re-sealing `resolution` as a fresh mutation
   * based on the current server revision, per SyncEngine.resolveConflict's
   * contract (new mutationId, baseRevision = conflict.current.revision).
   *
   * As with `saveItem`: the encrypted mutation is always sealed and
   * handed to `sync.resolveConflict` (durable ciphertext work that must
   * survive a concurrent `lock()`), but the optimistic plaintext cache
   * write is skipped if the generation captured before the first
   * `await` no longer matches. */
  async resolveConflict(conflict: Conflict, resolution: VaultItemData): Promise<void> {
    const { session, bundle } = this.requireUnlocked();
    const generation = this.generation;
    const problems = validateItemData(resolution);
    if (problems.length > 0) throw new Error(problems.join(" "));
    const envelope = await this.client.sealItemPayload(
      session, bundle.accountId, bundle.vaultId, conflict.current.itemId, KEY_VERSION, encodeItemData(resolution),
    );
    const newMutation: Mutation = {
      mutationId: crypto.randomUUID(),
      itemId: conflict.current.itemId,
      vaultId: bundle.vaultId,
      baseRevision: conflict.current.revision,
      ciphertext: encodeB64(envelope),
      envelopeVersion: ENVELOPE_VERSION,
      deleted: false,
    };
    await this.sync.resolveConflict(conflict.mutationId, newMutation);
    if (this.isGenerationCurrent(generation)) {
      this.itemCache.set(conflict.current.itemId, resolution);
      this.deletedLocally.delete(conflict.current.itemId);
    }
  }

  /** Re-syncs local view state after a successful push/pull cycle (the
   * caller drives SyncEngine.pushAll/pull and calls this to refresh
   * revisions and re-decrypt anything the pull applied). */
  async refreshFromRepository(): Promise<void> {
    if (this.session === null || !this.bundle) return;
    await this.loadAllItemsIntoMemory();
  }
}

/** Convenience for a caller building the ItemRecord shape a Conflict's
 * `current` side already is — exported for UI code that needs to read a
 * plain ItemRecord alongside a decrypted one. */
export type { ItemRecord };
