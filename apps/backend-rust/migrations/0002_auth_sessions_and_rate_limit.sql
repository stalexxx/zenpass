-- B04 (ADR-0005 §2, §3): forward-only. No existing migration is altered.
-- Session-to-device binding, per ADR-0005: a session is initially
-- device-unbound; explicit device registration binds it; revoking a device
-- transactionally revokes every session bound to it (enforced in
-- application code, not by cascade, so a revoke stays auditable).
ALTER TABLE sessions ADD COLUMN device_id varchar(128) REFERENCES devices(device_id);

-- Durable, bounded login-throttling state (ADR-0005 §3): a fixed-window
-- counter keyed by account and operation scope. No IP address, password,
-- token, or OPAQUE message is stored here.
CREATE TABLE IF NOT EXISTS auth_rate_limits (
  account_id varchar(128) NOT NULL REFERENCES accounts(account_id),
  scope varchar(64) NOT NULL,
  window_start timestamptz NOT NULL,
  count integer NOT NULL DEFAULT 0,
  PRIMARY KEY (account_id, scope, window_start)
);
