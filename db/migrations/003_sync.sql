-- B05: vault ownership, monotonic change sequence, and mutation
-- idempotency for the sync backend. Forward-only; 001 and 002 are
-- unchanged.

-- Nothing in 001/002 recorded which account owns a given vaultId. Vaults
-- are created implicitly on a client's first mutation into a vaultId with
-- no row here yet (there is no separate "create vault" endpoint in
-- sync-v1); ownership is first-write-wins and permanent thereafter.
CREATE TABLE IF NOT EXISTS vaults (
  vault_id varchar(128) PRIMARY KEY,
  account_id varchar(128) NOT NULL REFERENCES accounts(account_id),
  created_at timestamptz NOT NULL DEFAULT now()
);

-- Global monotonic sequence backing the opaque change-feed cursor
-- (sync-state-machine.md: "an opaque, monotonic feed cursor"). A single
-- sequence, not one per vault, keeps cursor encoding trivial; every feed
-- query still filters by vault_id, so ordering is only ever compared among
-- rows the caller is allowed to see.
CREATE SEQUENCE IF NOT EXISTS vault_change_sequence;

ALTER TABLE vault_items
  ADD COLUMN IF NOT EXISTS sequence bigint NOT NULL DEFAULT nextval('vault_change_sequence');

CREATE UNIQUE INDEX IF NOT EXISTS vault_items_sequence_key ON vault_items (sequence);
CREATE INDEX IF NOT EXISTS vault_items_vault_sequence_idx ON vault_items (vault_id, sequence);

-- Idempotency record for POST /vaults/{vaultId}/items: replaying the same
-- mutationId must return the exact original response, not reapply the
-- write or reject it as a fresh conflict (sync-state-machine.md). Scoped
-- per-account (composite primary key) so an accidental cross-account
-- mutationId collision can never return one account's stored response to
-- another account.
CREATE TABLE IF NOT EXISTS mutation_outcomes (
  account_id varchar(128) NOT NULL REFERENCES accounts(account_id),
  mutation_id varchar(128) NOT NULL,
  vault_id varchar(128) NOT NULL,
  status_code integer NOT NULL,
  response_body jsonb NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (account_id, mutation_id)
);
