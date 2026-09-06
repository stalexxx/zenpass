import { matchOrigin, parseOrigin } from "../../domain/src/origin.ts";

/** Metadata only. Credentials and TOTP seeds never cross this boundary. */
export interface LoginCandidate {
  id: string;
  title: string;
  origin: string;
}

export interface PageRequest {
  pageUrl: string;
  /** The content script must mark only the top-level document as trusted. */
  isTopFrame: boolean;
  /** A form that submits anywhere other than this origin is not fillable. */
  formAction?: string;
  usernameVisible: boolean;
  passwordVisible: boolean;
}

export type RefusalReason =
  | "locked"
  | "not-top-frame"
  | "not-https"
  | "invalid-page"
  | "cross-origin-form"
  | "hidden-field"
  | "no-exact-origin-match"
  | "confirmation-required"
  | "stale-capability"
  | "document-targeting-unsupported"
  | "unlock-unavailable"
  | "not-found";

export type FillDecision =
  | { allowed: true; candidates: LoginCandidate[] }
  | { allowed: false; reason: RefusalReason };

/**
 * T05/T06 policy. This intentionally has no permissive fallback: a page,
 * frame, form action, or candidate that cannot be proven safe is refused.
 */
export function decideFill(request: PageRequest, candidates: readonly LoginCandidate[]): FillDecision {
  if (!request.isTopFrame) return { allowed: false, reason: "not-top-frame" };
  const page = parseOrigin(request.pageUrl);
  if (!page) return { allowed: false, reason: "invalid-page" };
  if (page.scheme !== "https:") return { allowed: false, reason: "not-https" };
  if (!request.usernameVisible || !request.passwordVisible) {
    return { allowed: false, reason: "hidden-field" };
  }
  if (request.formAction && !matchOrigin(request.pageUrl, request.formAction).matches) {
    return { allowed: false, reason: "cross-origin-form" };
  }
  const exact = candidates.filter((candidate) => matchOrigin(candidate.origin, request.pageUrl).matches);
  return exact.length > 0
    ? { allowed: true, candidates: exact }
    : { allowed: false, reason: "no-exact-origin-match" };
}

/** A fill always requires a fresh, user-originated popup confirmation. */
export function confirmFill(userGesture: boolean): { allowed: true } | { allowed: false; reason: RefusalReason } {
  return userGesture ? { allowed: true } : { allowed: false, reason: "confirmation-required" };
}

/** Fill fields for one selected candidate: username/password, plus an
 * optionally freshly-computed current TOTP code for a totp-login item. */
export interface FillFields {
  username: string;
  password: string;
  totp?: string;
}

/**
 * Candidate/field source for the background, implemented by
 * `apps/extension/src/vault-manager.ts` (C04-EXT2) using the background's
 * private `CryptoWorkerHost`/WASM adapter. Never satisfiable from a
 * content script or page.
 */
export interface VaultCandidateSource {
  /** Exact-origin candidate membership is decided by the background. */
  candidatesFor(pageOrigin: string): readonly LoginCandidate[];
  /** Returns the fill fields for one selected candidate, or null. A TOTP
   * code (when present) is computed fresh at call time, so this may be
   * asynchronous; callers must `await` the result either way. */
  fieldsFor(itemId: string, pageOrigin: string): FillFields | null | Promise<FillFields | null>;
}

/** Non-secret item metadata for the popup's save/browse list. */
export interface ItemSummary {
  itemId: string;
  title: string;
  type: "login" | "note" | "totp-login";
  username?: string;
  url?: string;
}

/** Popup-entered fields for a create/edit (ADR-0011 D3's "manual popup
 * save/update"). Byte-array fields are decoded from the bounded
 * JSON-compatible integer-byte-array encoding used for runtime messaging
 * before this shape is constructed; string fields are plain bounded text. */
export interface SaveItemInput {
  itemId?: string;
  title: string;
  type: "login" | "note" | "totp-login";
  username?: string;
  password?: string;
  url?: string;
  notes?: string;
  totpSecret?: string;
}

export type SaveItemResult =
  | { ok: true; itemId: string }
  | { ok: false; reason: "validation"; problems: readonly string[] }
  | { ok: false; reason: "conflict" }
  | { ok: false; reason: "locked" }
  | { ok: false; reason: "network" };

export interface TotpDisplay {
  code: string;
  secondsRemaining: number;
}

export type UnlockResult =
  | { ok: true }
  | { ok: false; reason: "unlock-failed" };

/**
 * Extends `VaultCandidateSource` with the independent-unlock, save/update,
 * TOTP, and lifecycle operations C04-EXT2 wires up (ADR-0011 D1/D3/D5/D6).
 * Optional beyond the base interface so existing fixtures/tests that only
 * exercise fill/candidate selection are unaffected; `background.ts` refuses
 * with `unlock-unavailable` when a given method is absent.
 */
export interface VaultManager extends VaultCandidateSource {
  unlock(accountId: string, apiOrigin: string, password: Uint8Array): Promise<UnlockResult>;
  /** Purely local lock: disposes the host session and clears the item
   * cache/bearer token in memory, without attempting any network call.
   * Used for every non-explicit-logout lock event (explicit lock, popup
   * close, timeout, eviction/restart, auth failure). Safe to call while
   * already locked. */
  lock(): void;
  /** Attempts server-side session revocation, but always clears local
   * state in `finally` regardless of whether that attempt succeeds. */
  logout(): Promise<void>;
  isUnlocked(): boolean;
  listItems(): readonly ItemSummary[];
  saveItem(input: SaveItemInput): Promise<SaveItemResult>;
  getTotp(itemId: string): Promise<TotpDisplay | null>;
  /** Performs (or reuses, within the 30s window) the fresh authenticated
   * check ADR-0011 D5 requires before every candidate/secret display, fill,
   * TOTP generation and mutation. Returns false (and locks the session via
   * the manager's configured failure callback) on network failure or 401. */
  checkFresh(): Promise<boolean>;
}

export { parseContentMessage, parsePopupMessage, type ValidatedContentMessage, type ValidatedPopupMessage } from "./schema.ts";
export { trustedContentSender, trustedPopupSender, type RuntimeSender, type TrustedContentSender } from "./sender.ts";
export {
  FillCapabilityStore,
  MAX_CAPABILITY_LIFETIME_MS,
  type CapabilityConsumeFailure,
  type CapabilityConsumeResult,
  type FillCapabilityBinding,
  type FillCapabilityContext,
  type RandomBytes,
} from "./capability.ts";
export { SessionStateMachine, POPUP_INACTIVITY_LIMIT_MS, type LockReason } from "./session-state.ts";
export { computeTotp, secondsRemaining, base32Decode, type TotpAlgorithm, type TotpOptions } from "./totp.ts";
export { isByteArray, toByteArray, fromByteArray, clearNumberArray, stringToByteArray, byteArrayToString, MAX_SECRET_BYTES } from "./bytes.ts";
