export const FORMAT_VERSION = "crypto-envelope/v1";
export const FIXTURE_FORMAT_REVISION = "crypto-fixture/1";
export const ADAPTER_PROTOCOL_VERSION = "crypto-fixtures-adapter/1";
export const ADAPTER_ENV_VAR = "CRYPTO_FIXTURES_ADAPTER";

export const TYPED_ERRORS = [
  "InvalidEncoding",
  "UnsupportedVersion",
  "NonCanonicalCbor",
  "UnknownField",
  "InvalidContext",
  "InvalidNonce",
  "AuthenticationFailed",
  "InvalidKdfParameters",
  "KdfResourceLimit",
  "InvalidKeyLength",
  "InvalidRecoveryKit",
  "Locked",
  "Internal",
] as const;
export type TypedError = (typeof TYPED_ERRORS)[number];
export const TYPED_ERROR_SET: ReadonlySet<string> = new Set(TYPED_ERRORS);

export const RECORD_TYPES = [
  "account-wrap",
  "recovery-wrap",
  "vault-wrap",
  "item-wrap",
  "item-payload",
  "export-manifest",
] as const;
export type RecordType = (typeof RECORD_TYPES)[number];
export const RECORD_TYPE_SET: ReadonlySet<string> = new Set(RECORD_TYPES);

export const WRAP_KINDS = ["account-wrap", "recovery-wrap", "vault-wrap", "item-wrap"] as const;

export const OPERATIONS = ["canonical-cbor", "envelope", "aead", "wrap", "opaque"] as const;
export type Operation = (typeof OPERATIONS)[number];
export const OPERATION_SET: ReadonlySet<string> = new Set(OPERATIONS);

export const OUTCOMES = ["pass", "reject"] as const;
export type Outcome = (typeof OUTCOMES)[number];

export const TAMPER_RULE_XOR = "xor-0x01-at-offset";
export const TAMPER_RULE_TRUNCATE = "truncate-to-length";
