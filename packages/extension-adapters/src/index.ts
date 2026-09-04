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
  | "confirmation-required";

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
