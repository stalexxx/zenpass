# ADR-0002: Encrypted optimistic synchronization

## Decision

Use per-item encrypted records, monotonic revisions, tombstones, opaque cursors, idempotent mutation IDs, and client-side conflict resolution. A conflict creates two ciphertext versions; only a client with vault keys can merge them.

## Consequences

The backend remains blind to content, while clients must provide an understandable conflict UI and retain enough history to prevent silent data loss.

