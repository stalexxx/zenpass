# sync/v1 state machine

```text
LOCAL_CLEAN --edit--> LOCAL_DIRTY --mutate(baseRevision)--> SYNCING
SYNCING --201--> LOCAL_CLEAN (replace local revision/cursor)
SYNCING --network error--> RETRYABLE (exponential backoff, same mutationId)
RETRYABLE --retry--> SYNCING
SYNCING --409--> CONFLICT (retain current and attempted opaque records)
CONFLICT --client decrypt+resolve--> LOCAL_DIRTY (new mutation, current revision as base)
LOCAL_CLEAN --pull(cursor)--> APPLYING
APPLYING --page valid--> LOCAL_CLEAN (advance cursor only after durable apply)
APPLYING --page invalid--> ERROR (do not advance cursor)
```

The server assigns a strictly increasing `revision` per item and an opaque, monotonic feed cursor. A mutation is idempotent by `mutationId`; replaying the same mutation returns the original result. A cursor is advanced only after all records in the page are durably applied. Tombstones remain in the feed for the retention period and are never silently converted to missing records.
