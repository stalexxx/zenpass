import type { LoginCandidate, RefusalReason } from "../../../packages/extension-adapters/src/index.ts";

/**
 * ADR-0011 D3 boundary. Content scripts may send only bounded, non-secret
 * offer metadata for the current top document, or cancel it. The legacy
 * `fill` and credential-bearing `save-submitted` messages are removed;
 * pages cannot choose an item, assert a gesture, or transport submitted
 * credentials through the extension.
 */
export type ContentToBackground =
  | { type: "offer"; request: { pageUrl: string; isTopFrame: boolean; formAction?: string; usernameVisible: boolean; passwordVisible: boolean } }
  | { type: "cancel-offer" };

/** Popup is the only selection surface and never receives secret fields. */
export type PopupToBackground =
  | { type: "get-state" }
  | { type: "request-candidates" }
  | { type: "fill-selected"; requestId: string; itemId: string }
  | { type: "lock" };

export type BackgroundToContent =
  | { type: "offer-available" }
  | { type: "refused"; reason: RefusalReason }
  | { type: "fill"; origin: string; username: string; password: string; totp?: string }
  | { type: "locked" };

export type BackgroundToPopup =
  | { type: "state"; locked: boolean; unlockAvailable: false }
  | { type: "candidates"; requestId: string; candidates: LoginCandidate[] }
  | { type: "refused"; reason: RefusalReason }
  | { type: "locked" };
