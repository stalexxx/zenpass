-- Server stores authentication records and opaque encrypted material only.
CREATE TABLE IF NOT EXISTS accounts (
  account_id varchar(128) PRIMARY KEY,
  created_at timestamptz NOT NULL DEFAULT now(),
  deleted_at timestamptz
);
CREATE TABLE IF NOT EXISTS opaque_credentials (
  account_id varchar(128) PRIMARY KEY REFERENCES accounts(account_id),
  credential_record bytea NOT NULL,
  updated_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS sessions (
  session_id uuid PRIMARY KEY,
  account_id varchar(128) NOT NULL REFERENCES accounts(account_id),
  token_hash bytea NOT NULL UNIQUE,
  expires_at timestamptz NOT NULL,
  revoked_at timestamptz
);
CREATE TABLE IF NOT EXISTS devices (
  device_id varchar(128) PRIMARY KEY,
  account_id varchar(128) NOT NULL REFERENCES accounts(account_id),
  name varchar(128) NOT NULL,
  public_key bytea NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  last_seen_at timestamptz,
  revoked_at timestamptz
);
CREATE TABLE IF NOT EXISTS key_bundles (
  account_id varchar(128) PRIMARY KEY REFERENCES accounts(account_id),
  bundle bytea NOT NULL,
  version integer NOT NULL CHECK (version > 0),
  updated_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS vault_items (
  vault_id varchar(128) NOT NULL,
  item_id varchar(128) NOT NULL,
  ciphertext bytea NOT NULL,
  envelope_version varchar(64) NOT NULL CHECK (envelope_version = 'crypto-envelope/v1'),
  revision bigint NOT NULL CHECK (revision > 0),
  deleted boolean NOT NULL DEFAULT false,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (vault_id, item_id)
);
