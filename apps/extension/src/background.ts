import { confirmFill, decideFill, type LoginCandidate, type PageRequest } from "../../../packages/extension-adapters/src/index.ts";
import type { BackgroundToContent, BackgroundToPopup, ContentToBackground, PopupToBackground } from "./protocol.ts";

export interface UnlockedLogin extends LoginCandidate {
  username: string;
  password: string;
  /** Already-derived code; generation remains in the approved client crypto layer. */
  totp?: string;
}

/** Background-only volatile vault. It is deliberately never written to storage. */
export class ExtensionSession {
  #logins: UnlockedLogin[] = [];

  unlock(logins: readonly UnlockedLogin[]): void { this.#logins = [...logins]; }
  lock(): void {
    for (const login of this.#logins) {
      // Best effort: immutable strings cannot be zeroized by JavaScript.
      login.username = "";
      login.password = "";
      login.totp = undefined;
    }
    this.#logins = [];
  }
  get locked(): boolean { return this.#logins.length === 0; }

  offer(request: PageRequest): { response: BackgroundToContent; candidates: LoginCandidate[] } {
    if (this.locked) return { response: { type: "refused", reason: "locked" }, candidates: [] };
    const decision = decideFill(request, this.#logins);
    return decision.allowed
      ? { response: { type: "offer-available" }, candidates: decision.candidates }
      : { response: { type: "refused", reason: decision.reason }, candidates: [] };
  }

  fill(request: PageRequest, itemId: string, userGesture: boolean): BackgroundToContent {
    if (this.locked) return { type: "refused", reason: "locked" };
    const decision = decideFill(request, this.#logins);
    if (!decision.allowed) return { type: "refused", reason: decision.reason };
    if (!confirmFill(userGesture).allowed) return { type: "refused", reason: "confirmation-required" };
    const login = this.#logins.find((entry) => entry.id === itemId && decision.candidates.some((candidate) => candidate.id === itemId));
    return login ? { type: "fill", username: login.username, password: login.password, ...(login.totp ? { totp: login.totp } : {}) } : { type: "refused", reason: "no-exact-origin-match" };
  }
}

const session = new ExtensionSession();

type Sender = { tab?: { id?: number } };
type Runtime = { runtime: { onMessage: { addListener(listener: (message: ContentToBackground | PopupToBackground, sender: Sender) => BackgroundToContent | BackgroundToPopup | Promise<BackgroundToContent | BackgroundToPopup>): void } }; tabs: { sendMessage(tabId: number, message: BackgroundToContent): Promise<void> } };
/** WebExtension API is intentionally structural for Chrome/Firefox compatibility. */
declare const browser: Runtime | undefined;
declare const chrome: Runtime | undefined;
const runtime = typeof browser !== "undefined" ? browser : typeof chrome !== "undefined" ? chrome : undefined;
let pendingOffer: { tabId: number; request: PageRequest; candidates: LoginCandidate[] } | null = null;
runtime?.runtime.onMessage.addListener(async (message, sender) => {
  if (message.type === "lock") {
    session.lock();
    pendingOffer = null;
    return { type: "locked" };
  }
  if (message.type === "offer") {
    const offer = session.offer(message.request);
    const tabId = sender.tab?.id;
    pendingOffer = offer.response.type === "offer-available" && typeof tabId === "number"
      ? { tabId, request: message.request, candidates: offer.candidates } : null;
    return offer.response;
  }
  if (message.type === "get-offer") {
    return pendingOffer ? { type: "candidates", candidates: pendingOffer.candidates } : { type: "locked" };
  }
  if (message.type === "fill-selected") {
    if (!pendingOffer) return { type: "locked" };
    const offer = pendingOffer;
    const response = session.fill(offer.request, message.itemId, message.userGesture);
    pendingOffer = null;
    if (response.type !== "fill") return response;
    await runtime?.tabs.sendMessage(offer.tabId, response);
    return { type: "locked" };
  }
  if (message.type === "fill") return session.fill(message.request, message.itemId, message.userGesture);
  // Saving is intentionally not implemented without a user-visible vault UI
  // and encryption callback; do not retain submitted credentials here.
  if (message.type === "save-submitted") return { type: "refused", reason: "locked" };
  return { type: "locked" };
});
