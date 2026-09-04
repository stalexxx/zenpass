import type { LoginCandidate, PageRequest, RefusalReason } from "../../../packages/extension-adapters/src/index.ts";

export type ContentToBackground =
  | { type: "offer"; request: PageRequest }
  | { type: "fill"; request: PageRequest; itemId: string; userGesture: boolean }
  | { type: "save-submitted"; origin: string; username: string; password: string }
  | { type: "lock" };

export type BackgroundToContent =
  | { type: "offer-available" }
  | { type: "refused"; reason: RefusalReason }
  | { type: "fill"; username: string; password: string; totp?: string }
  | { type: "saved" }
  | { type: "locked" };

/** Popup is an extension-controlled surface; candidates never go to a page. */
export type PopupToBackground =
  | { type: "get-offer" }
  | { type: "fill-selected"; itemId: string; userGesture: boolean }
  | { type: "lock" };

export type BackgroundToPopup =
  | { type: "candidates"; candidates: LoginCandidate[] }
  | { type: "refused"; reason: RefusalReason }
  | { type: "locked" };
