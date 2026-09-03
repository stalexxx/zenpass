import type { CryptoRequest, CryptoResponse } from "./protocol.ts";

export type { CryptoRequest, CryptoResponse } from "./protocol.ts";

/** Implemented by the generated WASM adapter; session values are opaque ids. */
export interface CryptoBackend {
  unlockItemSession(request: Extract<CryptoRequest, { type: "unlock-item-session" }>): number;
  sealItemPayload(session: number, accountId: string, vaultId: string, itemId: string, keyVersion: bigint, plaintext: Uint8Array): Uint8Array;
  openItemPayload(session: number, accountId: string, vaultId: string, itemId: string, keyVersion: bigint, envelope: Uint8Array): Uint8Array;
  inspectEnvelope(envelope: Uint8Array): { accountId: string; vaultId: string | null; itemId: string | null; recordKind: string; keyVersion: bigint };
  closeSession(session: number): void;
}

const errorCodes = new Set([
  "InvalidEncoding", "UnsupportedVersion", "NonCanonicalCbor", "UnknownField", "InvalidContext",
  "InvalidNonce", "AuthenticationFailed", "InvalidKdfParameters", "KdfResourceLimit", "InvalidKeyLength",
  "InvalidRecoveryKit", "Locked", "Internal",
]);
const MAX_ITEM_BYTES = 1024 * 1024;
const MAX_ENVELOPE_BYTES = MAX_ITEM_BYTES + 1024 + 16;

/**
 * Owns WASM capabilities on the Worker side.  Messages deliberately have no
 * raw-key field; `lock` closes every live session and clears the registry.
 */
export class CryptoWorkerHost {
  private sessions = new Set<number>();
  constructor(private readonly wasm: CryptoBackend) {}

  handle(message: unknown): CryptoResponse {
    if (!isRequest(message)) return { id: "", ok: false, error: "InvalidEncoding" };
    try {
      switch (message.type) {
        case "unlock-item-session": {
          try {
            const session = this.wasm.unlockItemSession(message);
            this.sessions.add(session);
            return { id: message.id, ok: true, type: "session", session };
          } finally {
            // This is the Worker-owned structured-clone buffer. It does not
            // erase caller/UI or JS-engine copies, which remain caller-owned.
            message.password.fill(0);
          }
        }
        case "seal-item-payload":
          if (!this.sessions.has(message.session)) return locked(message.id);
          return { id: message.id, ok: true, type: "bytes", bytes: this.wasm.sealItemPayload(message.session, message.accountId, message.vaultId, message.itemId, message.keyVersion, message.plaintext) };
        case "open-item-payload":
          if (!this.sessions.has(message.session)) return locked(message.id);
          return { id: message.id, ok: true, type: "bytes", bytes: this.wasm.openItemPayload(message.session, message.accountId, message.vaultId, message.itemId, message.keyVersion, message.envelope) };
        case "inspect-envelope":
          return { id: message.id, ok: true, type: "metadata", metadata: this.wasm.inspectEnvelope(message.envelope) };
        case "lock":
          return this.lock(message.id);
      }
    } catch (error) {
      return { id: message.id, ok: false, error: errorCode(error) };
    }
  }

  /** Best-effort close of every capability; a failing close cannot strand others. */
  dispose(): void {
    try {
      for (const session of this.sessions) {
        try { this.wasm.closeSession(session); } catch { /* continue closing */ }
      }
    } finally {
      this.sessions.clear();
    }
  }

  private lock(id: string): CryptoResponse {
    let failed = false;
    try {
      for (const session of this.sessions) {
        try { this.wasm.closeSession(session); } catch { failed = true; }
      }
    } finally {
      this.sessions.clear();
    }
    return failed ? { id, ok: false, error: "Internal" } : { id, ok: true, type: "locked" };
  }
}

function locked(id: string): CryptoResponse { return { id, ok: false, error: "Locked" }; }
function errorCode(error: unknown): CryptoResponse["error"] {
  if (typeof error === "string" && errorCodes.has(error)) return error as CryptoResponse["error"];
  return typeof error === "object" && error !== null && "code" in error && typeof error.code === "string" && errorCodes.has(error.code)
    ? error.code as CryptoResponse["error"] : "Internal";
}

function isRequest(value: unknown): value is CryptoRequest {
  if (typeof value !== "object" || value === null) return false;
  const request = value as Record<string, unknown>;
  if (typeof request.id !== "string" || typeof request.type !== "string") return false;
  const exact = (keys: string[]) => Object.keys(request).length === keys.length && keys.every((key) => key in request);
  const payload = (field: string, cap: number) => request[field] instanceof Uint8Array && request[field].byteLength <= cap;
  const context = () => typeof request.session === "number" && Number.isSafeInteger(request.session) && request.session >= 0 && typeof request.accountId === "string" && typeof request.vaultId === "string" && typeof request.itemId === "string" && typeof request.keyVersion === "bigint" && request.keyVersion > 0n;
  switch (request.type) {
    case "unlock-item-session": return exact(["id", "type", "password", "kdfParametersCbor", "reportedPhysicalMemoryKiB", "accountId", "vaultId", "itemId", "accountKeyVersion", "vaultKeyVersion", "itemKeyVersion", "wrappedAccountKey", "wrappedVaultKey", "wrappedItemKey"]) &&
      payload("password", MAX_ITEM_BYTES) && payload("kdfParametersCbor", 64 * 1024) && payload("wrappedAccountKey", 64 * 1024) && payload("wrappedVaultKey", 64 * 1024) && payload("wrappedItemKey", 64 * 1024) &&
      typeof request.reportedPhysicalMemoryKiB === "bigint" && request.reportedPhysicalMemoryKiB > 0n && typeof request.accountId === "string" && typeof request.vaultId === "string" && typeof request.itemId === "string" && typeof request.accountKeyVersion === "bigint" && request.accountKeyVersion > 0n && typeof request.vaultKeyVersion === "bigint" && request.vaultKeyVersion > 0n && typeof request.itemKeyVersion === "bigint" && request.itemKeyVersion > 0n;
    case "lock": return exact(["id", "type"]);
    case "inspect-envelope": return exact(["id", "type", "envelope"]) && payload("envelope", MAX_ENVELOPE_BYTES);
    case "seal-item-payload": return exact(["id", "type", "session", "accountId", "vaultId", "itemId", "keyVersion", "plaintext"]) && context() && payload("plaintext", MAX_ITEM_BYTES);
    case "open-item-payload": return exact(["id", "type", "session", "accountId", "vaultId", "itemId", "keyVersion", "envelope"]) && context() && payload("envelope", MAX_ENVELOPE_BYTES);
    default: return false;
  }
}
