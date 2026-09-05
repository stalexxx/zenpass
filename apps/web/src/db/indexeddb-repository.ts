// Real, persistent, browser-native LocalRepository (packages/sdk's
// interface) backed by IndexedDB. Everything this stores is already
// ciphertext-and-metadata (`ItemRecord.ciphertext`/`Mutation.ciphertext`
// are `b64:`-prefixed opaque blobs per @pass/contracts) — this module adds
// no encryption of its own; it only needs to durably persist bytes it
// never interprets. Per packages/sdk/src/repository.ts's doc comments,
// "durable" means this interface's write call has resolved; IndexedDB
// transactions resolving `oncomplete` is exactly that durability boundary
// for a browser.
import { assertMonotonicPut } from "@zkpm/sdk";
import type {
  Id,
  ItemRecord,
  LocalRepository,
  Mutation,
  QueuedMutation,
} from "@zkpm/sdk";

const DB_NAME_PREFIX = "zkpm-vault";
const DB_VERSION = 1;
const ITEMS_STORE = "items";
const CURSORS_STORE = "cursors";
const QUEUE_STORE = "queue";

function openDatabase(dbName: string): Promise<IDBDatabase> {
  return new Promise((resolve, reject) => {
    const request = indexedDB.open(dbName, DB_VERSION);
    request.onupgradeneeded = () => {
      const db = request.result;
      if (!db.objectStoreNames.contains(ITEMS_STORE)) {
        const store = db.createObjectStore(ITEMS_STORE, { keyPath: ["vaultId", "itemId"] });
        store.createIndex("byVault", "vaultId", { unique: false });
      }
      if (!db.objectStoreNames.contains(CURSORS_STORE)) {
        db.createObjectStore(CURSORS_STORE, { keyPath: "vaultId" });
      }
      if (!db.objectStoreNames.contains(QUEUE_STORE)) {
        db.createObjectStore(QUEUE_STORE, { keyPath: "mutationId" });
      }
    };
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(request.error ?? new Error("IndexedDB open failed"));
    request.onblocked = () => reject(new Error("IndexedDB open blocked by another connection"));
  });
}

function reqToPromise<T>(request: IDBRequest<T>): Promise<T> {
  return new Promise((resolve, reject) => {
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(request.error ?? new Error("IndexedDB request failed"));
  });
}

/** Resolves only once the whole transaction has committed — not merely
 * once the individual request inside it succeeded — so a caller awaiting
 * this genuinely has durability, matching LocalRepository's contract. */
function txDone(tx: IDBTransaction): Promise<void> {
  return new Promise((resolve, reject) => {
    tx.oncomplete = () => resolve();
    tx.onerror = () => reject(tx.error ?? new Error("IndexedDB transaction failed"));
    tx.onabort = () => reject(tx.error ?? new Error("IndexedDB transaction aborted"));
  });
}

interface StoredQueueEntry {
  mutationId: Id;
  mutation: Mutation;
  state: QueuedMutation["state"];
  attempts: number;
  nextRetryAt?: number;
  lastError?: string;
}

export class IndexedDBLocalRepository implements LocalRepository {
  private dbPromise: Promise<IDBDatabase>;

  /** `namespace` scopes the database name (e.g. per-account) so multiple
   * accounts on the same browser profile never share one IndexedDB
   * database. */
  constructor(namespace: string) {
    this.dbPromise = openDatabase(`${DB_NAME_PREFIX}:${namespace}`);
  }

  private async db(): Promise<IDBDatabase> {
    return this.dbPromise;
  }

  async getItem(vaultId: Id, itemId: Id): Promise<ItemRecord | null> {
    const db = await this.db();
    const tx = db.transaction(ITEMS_STORE, "readonly");
    const result = await reqToPromise(tx.objectStore(ITEMS_STORE).get([vaultId, itemId]));
    return (result as ItemRecord | undefined) ?? null;
  }

  /** Inserts or replaces one server-confirmed ItemRecord, but only after
   * `assertMonotonicPut` (SEC-04) confirms `item` doesn't regress or
   * silently rewrite whatever is already stored for its `(vaultId,
   * itemId)` — a rejection throws before the transaction issues any write,
   * so a rejected record is never partially or fully persisted. */
  async putItem(item: ItemRecord): Promise<void> {
    const db = await this.db();
    const tx = db.transaction(ITEMS_STORE, "readwrite");
    const store = tx.objectStore(ITEMS_STORE);
    const existing = (await reqToPromise(store.get([item.vaultId, item.itemId]))) as ItemRecord | undefined;
    assertMonotonicPut(existing ?? null, item);
    store.put(item);
    await txDone(tx);
  }

  async listItems(vaultId: Id): Promise<ItemRecord[]> {
    const db = await this.db();
    const tx = db.transaction(ITEMS_STORE, "readonly");
    const index = tx.objectStore(ITEMS_STORE).index("byVault");
    const results = await reqToPromise(index.getAll(IDBKeyRange.only(vaultId)));
    return results as ItemRecord[];
  }

  async getCursor(vaultId: Id): Promise<string | null> {
    const db = await this.db();
    const tx = db.transaction(CURSORS_STORE, "readonly");
    const result = await reqToPromise(tx.objectStore(CURSORS_STORE).get(vaultId));
    return (result as { vaultId: Id; cursor: string } | undefined)?.cursor ?? null;
  }

  async setCursor(vaultId: Id, cursor: string): Promise<void> {
    const db = await this.db();
    const tx = db.transaction(CURSORS_STORE, "readwrite");
    tx.objectStore(CURSORS_STORE).put({ vaultId, cursor });
    await txDone(tx);
  }

  async enqueueMutation(entry: QueuedMutation): Promise<void> {
    const db = await this.db();
    const tx = db.transaction(QUEUE_STORE, "readwrite");
    const stored: StoredQueueEntry = {
      mutationId: entry.mutation.mutationId,
      mutation: entry.mutation,
      state: entry.state,
      attempts: entry.attempts,
      nextRetryAt: entry.nextRetryAt,
      lastError: entry.lastError,
    };
    tx.objectStore(QUEUE_STORE).put(stored);
    await txDone(tx);
  }

  async getQueuedMutation(mutationId: Id): Promise<QueuedMutation | null> {
    const db = await this.db();
    const tx = db.transaction(QUEUE_STORE, "readonly");
    const result = (await reqToPromise(tx.objectStore(QUEUE_STORE).get(mutationId))) as StoredQueueEntry | undefined;
    return result ? toQueuedMutation(result) : null;
  }

  async listQueuedMutations(): Promise<QueuedMutation[]> {
    const db = await this.db();
    const tx = db.transaction(QUEUE_STORE, "readonly");
    const results = (await reqToPromise(tx.objectStore(QUEUE_STORE).getAll())) as StoredQueueEntry[];
    return results.map(toQueuedMutation);
  }

  async dequeueMutation(mutationId: Id): Promise<void> {
    const db = await this.db();
    const tx = db.transaction(QUEUE_STORE, "readwrite");
    tx.objectStore(QUEUE_STORE).delete(mutationId);
    await txDone(tx);
  }

  /** Closes the underlying IndexedDB connection. Not part of
   * LocalRepository (that interface has no lifecycle method) — callers use
   * this only for test teardown / explicit account switch, never as part
   * of the lock flow (locking clears key handles, not local storage). */
  close(): void {
    this.dbPromise.then((db) => db.close()).catch(() => {});
  }
}

function toQueuedMutation(stored: StoredQueueEntry): QueuedMutation {
  return {
    mutation: stored.mutation,
    state: stored.state,
    attempts: stored.attempts,
    nextRetryAt: stored.nextRetryAt,
    lastError: stored.lastError,
  };
}

/** Permanently deletes a namespace's IndexedDB database (e.g. explicit
 * logout that also clears local data, or test teardown). */
export function deleteVaultDatabase(namespace: string): Promise<void> {
  return new Promise((resolve, reject) => {
    const request = indexedDB.deleteDatabase(`${DB_NAME_PREFIX}:${namespace}`);
    request.onsuccess = () => resolve();
    request.onerror = () => reject(request.error ?? new Error("IndexedDB delete failed"));
    request.onblocked = () => resolve(); // best-effort; a stuck connection elsewhere shouldn't hang teardown
  });
}
