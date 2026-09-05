// Client-side implementation of packages/contracts/sync-state-machine.md:
//
//   LOCAL_CLEAN --edit--> LOCAL_DIRTY --mutate(baseRevision)--> SYNCING
//   SYNCING --201--> LOCAL_CLEAN (replace local revision/cursor)
//   SYNCING --network error--> RETRYABLE (exponential backoff, same mutationId)
//   RETRYABLE --retry--> SYNCING
//   SYNCING --409--> CONFLICT (retain current and attempted opaque records)
//   CONFLICT --client decrypt+resolve--> LOCAL_DIRTY (new mutation, current revision as base)
//   LOCAL_CLEAN --pull(cursor)--> APPLYING
//   APPLYING --page valid--> LOCAL_CLEAN (advance cursor only after durable apply)
//   APPLYING --page invalid--> ERROR (do not advance cursor)
//
// This module implements the transitions explicitly (a real state machine,
// not ad hoc retry logic): each mutation carries its own state, moves
// through exactly these states, and a conflict is surfaced to the caller
// as a Conflict object rather than resolved here (resolving one requires
// decrypting `current`, which needs a key this package never holds).

import type { ApiClient } from "./http-client.ts";
import { HttpError, NetworkError } from "./http-client.ts";
import type { LocalRepository, QueuedMutation } from "./repository.ts";
import type { ChangePage, Conflict, Id, ItemRecord, Mutation } from "./types.ts";

export type MutationSyncState = "LOCAL_DIRTY" | "SYNCING" | "RETRYABLE" | "CONFLICT" | "LOCAL_CLEAN";

export interface BackoffOptions {
  baseMs: number;
  maxMs: number;
}

const DEFAULT_BACKOFF: BackoffOptions = { baseMs: 500, maxMs: 30_000 };

/** Exponential backoff delay for a RETRYABLE mutation's `attempts`-th
 * retry (0-indexed: the first retry after the first failure uses
 * `attempts === 1`). Deterministic and pure so it's directly testable;
 * callers add their own jitter if they want it. */
export function retryDelayMs(attempts: number, options: BackoffOptions = DEFAULT_BACKOFF): number {
  const raw = options.baseMs * 2 ** Math.max(0, attempts - 1);
  return Math.min(raw, options.maxMs);
}

export type PushOutcome =
  | { kind: "applied"; item: ItemRecord }
  | { kind: "conflict"; conflict: Conflict }
  | { kind: "retryable"; nextRetryAt: number; error: string };

export type PullOutcome =
  | { kind: "applied"; pagesApplied: number; itemsApplied: number; cursor: string | null }
  | { kind: "error"; error: string; itemsApplied: number };

/**
 * Drives one vault's push (offline queue + idempotent mutate) and pull
 * (cursor-driven change feed) sides of the state machine against a real
 * ApiClient and a LocalRepository. Holds no plaintext and performs no
 * cryptography — mutations already carry ciphertext by the time they
 * reach this class (encryption is the caller's job, upstream of
 * enqueueEdit).
 */
export class SyncEngine {
  constructor(
    private readonly api: ApiClient,
    private readonly repo: LocalRepository,
    private readonly backoff: BackoffOptions = DEFAULT_BACKOFF,
  ) {}

  /** LOCAL_CLEAN --edit--> LOCAL_DIRTY. Queues a mutation for sync,
   * durably, before any network call — this is what makes the queue
   * survive being offline: the mutation exists in the repository whether
   * or not `pushOne`/`pushAll` ever gets a chance to run before the
   * process exits. Enqueuing the same `mutationId` again (a caller-level
   * retry that didn't change the mutation) updates the existing queue
   * entry rather than creating a duplicate. */
  async enqueueEdit(mutation: Mutation): Promise<void> {
    await this.repo.enqueueMutation({ mutation, state: "LOCAL_DIRTY", attempts: 0 });
  }

  /** Attempts to sync every currently-queued mutation once each, in queue
   * order, skipping any still in their backoff window. Returns one
   * PushOutcome per mutation actually attempted. Does not loop/sleep
   * itself — a caller (a timer, a reconnect handler, or a test) decides
   * when to call this again; `RETRYABLE` entries carry `nextRetryAt` so
   * the caller knows when a retry is worth attempting. */
  async pushAll(now: number = Date.now()): Promise<Map<Id, PushOutcome>> {
    const results = new Map<Id, PushOutcome>();
    for (const entry of await this.repo.listQueuedMutations()) {
      if (entry.state === "CONFLICT") continue; // awaiting caller resolution
      if (entry.state === "RETRYABLE" && entry.nextRetryAt !== undefined && entry.nextRetryAt > now) {
        continue; // still in backoff window
      }
      results.set(entry.mutation.mutationId, await this.pushOne(entry));
    }
    return results;
  }

  /** SYNCING for one queued mutation, then the 201 / 409 / network-error
   * transition. `mutationId` is never regenerated here on any path,
   * including retries — reusing the id is what makes server-side replay
   * idempotency (B05) actually protect a retried mutation. */
  async pushOne(entry: QueuedMutation): Promise<PushOutcome> {
    const mutation = entry.mutation;
    await this.repo.enqueueMutation({ ...entry, state: "SYNCING" });
    try {
      const outcome = await this.api.mutateItem(mutation.vaultId, mutation);
      if (outcome.status === 201) {
        await this.repo.putItem(outcome.item);
        await this.repo.dequeueMutation(mutation.mutationId);
        return { kind: "applied", item: outcome.item };
      }
      // 409: retain current and attempted opaque records verbatim for the
      // caller to resolve (decrypt + re-mutate) — this engine does not
      // interpret or merge ciphertext.
      await this.repo.enqueueMutation({
        ...entry,
        state: "CONFLICT",
        attempts: entry.attempts,
      });
      return { kind: "conflict", conflict: outcome.conflict };
    } catch (e) {
      if (e instanceof HttpError) {
        // A definite non-2xx/409 server response (e.g. 400) is not part of
        // this state machine's RETRYABLE path — retrying an invalid
        // mutation forever would never succeed. Surface it as a thrown
        // error to the caller instead of silently queuing retries.
        await this.repo.enqueueMutation({ ...entry, state: "LOCAL_DIRTY" });
        throw e;
      }
      if (!(e instanceof NetworkError)) throw e;
      const attempts = entry.attempts + 1;
      const nextRetryAt = Date.now() + retryDelayMs(attempts, this.backoff);
      await this.repo.enqueueMutation({
        ...entry,
        state: "RETRYABLE",
        attempts,
        nextRetryAt,
        lastError: e.message,
      });
      return { kind: "retryable", nextRetryAt, error: e.message };
    }
  }

  /** CONFLICT --client decrypt+resolve--> LOCAL_DIRTY. The caller has
   * decrypted `conflict.current`, produced a new plaintext resolution, and
   * (upstream of this call) re-encrypted it into a fresh Mutation whose
   * `baseRevision` is `conflict.current.revision` and whose `mutationId`
   * is a *new* id (this is a new mutation, not a replay of the failed
   * one). This method just replaces the old queue entry with the new one. */
  async resolveConflict(oldMutationId: Id, resolution: Mutation): Promise<void> {
    await this.repo.dequeueMutation(oldMutationId);
    await this.enqueueEdit(resolution);
  }

  /**
   * LOCAL_CLEAN --pull(cursor)--> APPLYING --page valid--> LOCAL_CLEAN, or
   * --page invalid--> ERROR. Pages through `/vaults/{vaultId}/changes`
   * starting at the repository's last durably-applied cursor, applying
   * each record via `repo.putItem` before advancing the cursor for that
   * page — so a crash mid-page reprocesses the whole page next time
   * instead of skipping records, and a page that fails to apply leaves the
   * cursor untouched entirely.
   */
  async pull(vaultId: Id, maxPages = 100): Promise<PullOutcome> {
    let cursor = (await this.repo.getCursor(vaultId)) ?? undefined;
    let pagesApplied = 0;
    let itemsApplied = 0;
    for (let page = 0; page < maxPages; page += 1) {
      let result: ChangePage;
      try {
        result = await this.api.listChanges(vaultId, cursor);
      } catch (e) {
        return { kind: "error", error: e instanceof Error ? e.message : String(e), itemsApplied };
      }
      try {
        for (const change of result.changes) {
          // Vault-ownership check (SEC-04): the caller asked to pull
          // `vaultId`; a dishonest server including a record for a
          // different vault in this page must be rejected before it ever
          // reaches putItem or the cursor advances — putItem's own
          // revision/integrity checks (assertMonotonicPut) can't catch
          // this because they only compare records already keyed to the
          // same (vaultId, itemId).
          if (change.vaultId !== vaultId) {
            throw new Error(
              `pull rejected: server returned item ${change.itemId} for vault ${change.vaultId} ` +
                `while pulling vault ${vaultId}`,
            );
          }
          // Revision monotonicity / tombstone-integrity checks live inside
          // putItem itself (assertMonotonicPut, shared by every
          // LocalRepository implementation) so they protect every caller,
          // not just this loop. A rejection throws and is caught below —
          // a visible ERROR outcome, never a silent skip — leaving local
          // data and the cursor exactly where they were.
          await this.repo.putItem(change);
          itemsApplied += 1;
        }
      } catch (e) {
        // APPLYING --page invalid--> ERROR: do not advance the cursor past
        // a page that failed partway through applying.
        return { kind: "error", error: e instanceof Error ? e.message : String(e), itemsApplied };
      }
      // Cursor is advanced only now, after every record in the page above
      // has been durably applied via putItem.
      await this.repo.setCursor(vaultId, result.nextCursor ?? cursor ?? "");
      pagesApplied += 1;
      const madeProgress = result.changes.length > 0 && result.nextCursor !== cursor;
      cursor = result.nextCursor ?? cursor;
      if (!madeProgress) break; // caught up: server repeats the last cursor with no new changes
    }
    return { kind: "applied", pagesApplied, itemsApplied, cursor: cursor ?? null };
  }
}
