import type { Id, ItemRecord, Mutation } from "./types.ts";
import type { MutationSyncState } from "./sync-state-machine.ts";

/**
 * Thrown by a `LocalRepository.putItem` implementation when applying
 * `incoming` over the record already stored for the same
 * `(vaultId, itemId)` would let a dishonest server roll back or silently
 * rewrite vault state (SEC-04 / GitHub issue #4). Callers (notably
 * `SyncEngine.pull`) must treat this as a visible, fail-closed error — not
 * swallow it and skip the record — so local data and the sync cursor are
 * left exactly as they were before the rejected write.
 */
export class RecordConflictError extends Error {
  constructor(
    message: string,
    public readonly reason: "revision-regression" | "revision-mismatch",
  ) {
    super(message);
    this.name = "RecordConflictError";
  }
}

function sameRecordBytes(a: ItemRecord, b: ItemRecord): boolean {
  return (
    a.ciphertext === b.ciphertext &&
    a.envelopeVersion === b.envelopeVersion &&
    a.deleted === b.deleted &&
    a.createdAt === b.createdAt &&
    a.updatedAt === b.updatedAt
  );
}

/**
 * Every `LocalRepository.putItem` implementation must call this (with the
 * record currently stored for `incoming`'s `(vaultId, itemId)`, or `null`
 * if there is none) before persisting `incoming`, and must not persist it
 * if this throws. Enforces the two invariants achievable without changing
 * the frozen `crypto-envelope/v1` AAD (see SEC-04's completion report for
 * the residual gap this cannot close):
 *
 *  - Revision monotonicity: `incoming.revision` must never be lower than
 *    `existing.revision` — rejects a server replaying an old, genuinely
 *    valid ciphertext at a lower revision (including reviving a tombstoned
 *    record, since `deleted` is part of the same rejected write).
 *  - Same-revision integrity: if the revisions are equal, every field of
 *    `incoming` must match `existing` exactly — rejects a same-revision
 *    record whose ciphertext, `envelopeVersion`, or `deleted` flag was
 *    altered in transit or by a dishonest server.
 *
 * This cannot detect a genuinely-valid *older* ciphertext relabeled by the
 * server under a fabricated *higher* revision number: `crypto-envelope/v1`'s
 * AAD binds `keyVersion` but not `revision`/`deleted`, so nothing in the
 * envelope lets the client tell that case apart from a legitimate new
 * write. Closing that gap requires an ADR-gated AAD change (out of scope
 * here — see SEC-04's completion report).
 */
export function assertMonotonicPut(existing: ItemRecord | null, incoming: ItemRecord): void {
  if (!existing) return;
  if (incoming.revision < existing.revision) {
    throw new RecordConflictError(
      `putItem rejected: revision ${incoming.revision} regresses stored revision ${existing.revision} ` +
        `for ${incoming.vaultId}/${incoming.itemId}`,
      "revision-regression",
    );
  }
  if (incoming.revision === existing.revision && !sameRecordBytes(existing, incoming)) {
    throw new RecordConflictError(
      `putItem rejected: revision ${incoming.revision} for ${incoming.vaultId}/${incoming.itemId} ` +
        `is already stored with different content`,
      "revision-mismatch",
    );
  }
}

/** A mutation sitting in the local offline queue, with its own sync state.
 * Everything on this shape is already ciphertext/metadata (Mutation, from
 * @pass/contracts, carries `ciphertext`/`envelopeVersion`, never
 * plaintext) — the repository interface this belongs to must never accept
 * or produce plaintext, per C02's brief. */
export interface QueuedMutation {
  mutation: Mutation;
  state: MutationSyncState;
  attempts: number;
  /** Epoch milliseconds; set when `state` is RETRYABLE so a caller's retry
   * loop knows not to retry before this time (exponential backoff). */
  nextRetryAt?: number;
  lastError?: string;
}

/**
 * The SDK's encrypted local repository interface: an abstraction the SDK
 * writes ciphertext ItemRecords, revisions, cursors, and queued mutations
 * *through*. Implementations own actual persistence (e.g. IndexedDB in a
 * later browser client task) — this package defines only the contract and
 * an in-memory reference implementation for its own tests.
 *
 * Every method here accepts or returns only ciphertext-and-metadata shapes
 * (`ItemRecord`, `Mutation`, opaque cursor strings) — never plaintext. A
 * conforming implementation must not decrypt anything either; decryption
 * requires a caller-held key this interface never sees.
 *
 * "Durable" in this file's and the sync engine's terminology means this
 * interface's write call has resolved — not that any particular storage
 * backend has synced to disk; that guarantee is the concrete
 * implementation's responsibility to provide if its backend needs it.
 */
export interface LocalRepository {
  getItem(vaultId: Id, itemId: Id): Promise<ItemRecord | null>;
  /** Writes (inserts or replaces) one server-confirmed ItemRecord. */
  putItem(item: ItemRecord): Promise<void>;
  listItems(vaultId: Id): Promise<ItemRecord[]>;

  /** The last durably-applied change-feed cursor for a vault, or null if
   * this vault has never been pulled. */
  getCursor(vaultId: Id): Promise<string | null>;
  /** Must only be called by the sync engine after every record in a page
   * has been durably applied via putItem — never before, and never for a
   * page that failed partway through (APPLYING --page invalid--> ERROR
   * per sync-state-machine.md; the cursor stays at its previous value). */
  setCursor(vaultId: Id, cursor: string): Promise<void>;

  /** Adds a mutation to the durable offline queue. Idempotent on
   * `mutation.mutationId`: enqueuing an id that is already queued updates
   * that entry in place rather than duplicating it, so a caller retrying
   * an edit reuses the queue slot exactly as it reuses the mutationId. */
  enqueueMutation(entry: QueuedMutation): Promise<void>;
  getQueuedMutation(mutationId: Id): Promise<QueuedMutation | null>;
  listQueuedMutations(): Promise<QueuedMutation[]>;
  /** Removes a mutation from the queue once it reaches a terminal state
   * (LOCAL_CLEAN after a 201, or CONFLICT once the caller has consumed the
   * Conflict object — the caller re-enqueues a fresh mutation to resolve
   * it, per sync-state-machine.md's CONFLICT --client decrypt+resolve-->
   * LOCAL_DIRTY transition). */
  dequeueMutation(mutationId: Id): Promise<void>;
}

/** Reference in-memory implementation. Not for production use (no actual
 * durability across process restarts) — exists so this package's own
 * tests can exercise the sync engine against a real LocalRepository
 * implementation rather than a mock, and so C01 has a documented minimal
 * example of what a real (e.g. IndexedDB-backed) implementation needs to
 * satisfy. */
export class InMemoryLocalRepository implements LocalRepository {
  private readonly items = new Map<string, ItemRecord>();
  private readonly cursors = new Map<Id, string>();
  private readonly queue = new Map<Id, QueuedMutation>();

  private key(vaultId: Id, itemId: Id): string {
    return `${vaultId}\0${itemId}`;
  }

  async getItem(vaultId: Id, itemId: Id): Promise<ItemRecord | null> {
    return this.items.get(this.key(vaultId, itemId)) ?? null;
  }

  async putItem(item: ItemRecord): Promise<void> {
    const existing = this.items.get(this.key(item.vaultId, item.itemId)) ?? null;
    assertMonotonicPut(existing, item);
    this.items.set(this.key(item.vaultId, item.itemId), item);
  }

  async listItems(vaultId: Id): Promise<ItemRecord[]> {
    return [...this.items.values()].filter((i) => i.vaultId === vaultId);
  }

  async getCursor(vaultId: Id): Promise<string | null> {
    return this.cursors.get(vaultId) ?? null;
  }

  async setCursor(vaultId: Id, cursor: string): Promise<void> {
    this.cursors.set(vaultId, cursor);
  }

  async enqueueMutation(entry: QueuedMutation): Promise<void> {
    this.queue.set(entry.mutation.mutationId, entry);
  }

  async getQueuedMutation(mutationId: Id): Promise<QueuedMutation | null> {
    return this.queue.get(mutationId) ?? null;
  }

  async listQueuedMutations(): Promise<QueuedMutation[]> {
    return [...this.queue.values()];
  }

  async dequeueMutation(mutationId: Id): Promise<void> {
    this.queue.delete(mutationId);
  }
}
