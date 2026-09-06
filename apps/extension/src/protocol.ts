import type { ItemSummary, LoginCandidate, RefusalReason, SaveItemResult, TotpDisplay } from "../../../packages/extension-adapters/src/index.ts";

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

/**
 * Popup is the only selection *and* independent-unlock/save/TOTP surface
 * (ADR-0011 D1/D3/D5/D6). Every secret byte buffer crossing this boundary
 * (unlock password, save/update password/notes/TOTP secret) uses the
 * bounded JSON-compatible integer-byte-array encoding (`apps/extension/src
 * /bytes.ts`) — Chrome's runtime messaging is JSON, not structured clone.
 */
export type PopupToBackground =
  | { type: "get-state" }
  | { type: "request-candidates" }
  | { type: "fill-selected"; requestId: string; itemId: string }
  | { type: "lock" }
  | { type: "unlock"; accountId: string; apiOrigin: string; password: number[] }
  | { type: "logout" }
  | { type: "list-items" }
  | {
      type: "save-item";
      itemId?: string;
      title: string;
      itemType: "login" | "note" | "totp-login";
      username?: string;
      password?: number[];
      url?: string;
      notes?: number[];
      totpSecret?: number[];
    }
  | { type: "get-totp"; itemId: string };

export type BackgroundToContent =
  | { type: "offer-available" }
  | { type: "refused"; reason: RefusalReason }
  | { type: "fill"; origin: string; username: string; password: string; totp?: string }
  | { type: "locked" };

export type BackgroundToPopup =
  | { type: "state"; locked: boolean; unlockAvailable: boolean; savedAccount: { accountId: string; apiOrigin: string } | null }
  | { type: "candidates"; requestId: string; candidates: LoginCandidate[] }
  | { type: "refused"; reason: RefusalReason }
  | { type: "unlock-failed" }
  | { type: "unlocked" }
  | { type: "items"; items: ItemSummary[] }
  | { type: "saved"; itemId: string }
  | { type: "save-failed"; reason: Extract<SaveItemResult, { ok: false }>["reason"]; problems?: readonly string[] }
  | { type: "totp"; code: string; secondsRemaining: number }
  | { type: "locked" };
