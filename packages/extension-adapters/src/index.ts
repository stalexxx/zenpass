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
  | "unlock-unavailable";

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

/**
 * Candidate/field source for the background. Until C04-G1 lands the
 * independent OPAQUE unlock and key-bundle opening, no production
 * implementation exists: the extension stays locked and refuses offers.
 * This interface is the seam G1 will implement inside the trusted
 * background; it must never be satisfiable from a content script or page.
 */
export interface VaultCandidateSource {
  /** Exact-origin candidate membership is decided by the background. */
  candidatesFor(pageOrigin: string): readonly LoginCandidate[];
  /** Returns the fill fields for one selected candidate, or null. */
  fieldsFor(itemId: string, pageOrigin: string): { username: string; password: string; totp?: string } | null;
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
