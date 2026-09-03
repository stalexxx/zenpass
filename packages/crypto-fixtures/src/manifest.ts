/** Explicit fixture manifest. This is schema metadata, not cryptographic code. */
export const MANIFEST = {
  "aad-item-payload.json": { operation: "canonical-cbor", required: ["id", "input", "canonicalCborHex", "nonCanonical"] },
  "kdf-parameters.json": { operation: "canonical-cbor", required: ["id", "parameters", "canonicalCborHex", "canonicalReject", "negative"] },
  "envelope-malformed.json": { operation: "envelope", required: ["id", "validEnvelopeShape", "reject"] },
  "aead-xchacha20poly1305.json": { operation: "aead", required: ["id", "key", "nonce", "plaintext", "aad", "ciphertextTag", "negative"] },
  "opaque-3dh-ristretto255.json": { operation: "opaque", required: ["id", "suite", "inputs", "outputs", "negative"] },
  "recovery-semantics.json": { operation: "structural-only", required: ["id", "recoveryKey", "recoveryWrappedAccountKey", "ciphertextIsPlaceholder"] },
} as const;
export type ManifestFile = keyof typeof MANIFEST;
