/**
 * One-use, document-bound exact-origin fill capabilities (ADR-0011,
 * "Exact-origin authorization and cancellation").
 *
 * A capability is granted only by the trusted background after an accepted
 * offer, carries an unpredictable request ID, expires within 30 seconds,
 * and is bound to the session generation, tab, top document identity,
 * exact canonical HTTPS origin and form-action origin. Consumption is
 * single-use: any mismatch — lock generation change, navigation, tab or
 * document change, origin change, or expiry — fails closed. Unknown
 * capabilities are never re-issued.
 */

export interface FillCapabilityBinding {
  generation: number;
  tabId: number;
  documentId: string;
  origin: string;
  formActionOrigin: string;
}

export interface FillCapabilityContext {
  generation: number;
  tabId: number;
  documentId: string;
  origin: string;
  formActionOrigin: string;
}

export const MAX_CAPABILITY_LIFETIME_MS = 30_000;

export type CapabilityConsumeFailure =
  | "unknown"
  | "expired"
  | "generation-changed"
  | "tab-changed"
  | "document-changed"
  | "origin-changed"
  | "form-action-changed";

export type CapabilityConsumeResult = { ok: true } | { ok: false; reason: CapabilityConsumeFailure };

export type RandomBytes = (length: number) => Uint8Array;

function defaultRandomBytes(length: number): Uint8Array {
  const bytes = new Uint8Array(length);
  globalThis.crypto.getRandomValues(bytes);
  return bytes;
}

export class FillCapabilityStore {
  #randomBytes: RandomBytes;
  #capabilities = new Map<string, { binding: FillCapabilityBinding; grantedAt: number }>();

  constructor(randomBytes: RandomBytes = defaultRandomBytes) {
    this.#randomBytes = randomBytes;
  }

  /** Grants a new capability and returns its unpredictable request ID. */
  grant(binding: FillCapabilityBinding, now: number): string {
    const bytes = this.#randomBytes(16);
    const requestId = [...bytes].map((byte) => byte.toString(16).padStart(2, "0")).join("");
    this.#capabilities.set(requestId, { binding, grantedAt: now });
    return requestId;
  }

  /** Consumes a capability exactly once. The entry is removed whether the
   * check passes or fails; a second presentation is always `unknown`. */
  consume(requestId: unknown, current: FillCapabilityContext, now: number): CapabilityConsumeResult {
    if (typeof requestId !== "string" || requestId.length === 0 || requestId.length > 128) return { ok: false, reason: "unknown" };
    const entry = this.#capabilities.get(requestId);
    this.#capabilities.delete(requestId);
    if (!entry) return { ok: false, reason: "unknown" };
    if (now - entry.grantedAt > MAX_CAPABILITY_LIFETIME_MS) return { ok: false, reason: "expired" };
    const bound = entry.binding;
    if (bound.generation !== current.generation) return { ok: false, reason: "generation-changed" };
    if (bound.tabId !== current.tabId) return { ok: false, reason: "tab-changed" };
    if (bound.documentId !== current.documentId) return { ok: false, reason: "document-changed" };
    if (bound.origin !== current.origin) return { ok: false, reason: "origin-changed" };
    if (bound.formActionOrigin !== current.formActionOrigin) return { ok: false, reason: "form-action-changed" };
    return { ok: true };
  }

  /** Drops every outstanding capability (lock, popup close, eviction). */
  invalidateAll(): void {
    this.#capabilities.clear();
  }
}
