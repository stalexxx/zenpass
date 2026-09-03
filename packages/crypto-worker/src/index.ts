import type { CryptoWasm } from "../../crypto-wasm/src/index.ts";
import type { CryptoRequest, CryptoResponse } from "./protocol.ts";

export type { CryptoRequest, CryptoResponse } from "./protocol.ts";

const errorCodes = new Set([
  "InvalidEncoding", "UnsupportedVersion", "NonCanonicalCbor", "UnknownField", "InvalidContext",
  "InvalidNonce", "AuthenticationFailed", "InvalidKdfParameters", "KdfResourceLimit", "InvalidKeyLength",
  "InvalidRecoveryKit", "Locked", "Internal",
]);

/**
 * Owns WASM capabilities on the Worker side.  Messages deliberately have no
 * raw-key field; `lock` closes every live session and clears the registry.
 */
export class CryptoWorkerHost {
  private sessions = new Set<number>();
  constructor(private readonly wasm: CryptoWasm) {}

  handle(message: unknown): CryptoResponse {
    if (!isRequest(message)) return { id: "", ok: false, error: "InvalidEncoding" };
    try {
      switch (message.type) {
        case "create-item-session": {
          const session = this.wasm.createItemSession();
          this.sessions.add(session);
          return { id: message.id, ok: true, type: "session", session };
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
          for (const session of this.sessions) this.wasm.closeSession(session);
          this.sessions.clear();
          return { id: message.id, ok: true, type: "locked" };
      }
    } catch (error) {
      return { id: message.id, ok: false, error: errorCode(error) };
    }
  }
}

function locked(id: string): CryptoResponse { return { id, ok: false, error: "Locked" }; }
function errorCode(error: unknown): CryptoResponse["error"] {
  return typeof error === "object" && error !== null && "code" in error && typeof error.code === "string" && errorCodes.has(error.code)
    ? error.code as CryptoResponse["error"] : "Internal";
}

function isRequest(value: unknown): value is CryptoRequest {
  if (typeof value !== "object" || value === null) return false;
  const request = value as Record<string, unknown>;
  if (typeof request.id !== "string" || typeof request.type !== "string") return false;
  const exact = (keys: string[]) => Object.keys(request).length === keys.length && keys.every((key) => key in request);
  const payload = (field: string) => request[field] instanceof Uint8Array;
  const context = () => typeof request.session === "number" && typeof request.accountId === "string" && typeof request.vaultId === "string" && typeof request.itemId === "string" && typeof request.keyVersion === "bigint";
  switch (request.type) {
    case "create-item-session": return exact(["id", "type"]);
    case "lock": return exact(["id", "type"]);
    case "inspect-envelope": return exact(["id", "type", "envelope"]) && payload("envelope");
    case "seal-item-payload": return exact(["id", "type", "session", "accountId", "vaultId", "itemId", "keyVersion", "plaintext"]) && context() && payload("plaintext");
    case "open-item-payload": return exact(["id", "type", "session", "accountId", "vaultId", "itemId", "keyVersion", "envelope"]) && context() && payload("envelope");
    default: return false;
  }
}
