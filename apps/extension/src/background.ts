import { confirmFill, decideFill, type LoginCandidate, type PageRequest } from "../../../packages/extension-adapters/src/index.ts";
import type { BackgroundToContent, ContentToBackground } from "./protocol.ts";

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

  offer(request: PageRequest): BackgroundToContent {
    if (this.locked) return { type: "refused", reason: "locked" };
    const decision = decideFill(request, this.#logins);
    return decision.allowed ? { type: "candidates", candidates: decision.candidates } : { type: "refused", reason: decision.reason };
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

/** WebExtension API is intentionally structural for Chrome/Firefox compatibility. */
declare const browser: { runtime: { onMessage: { addListener(listener: (message: ContentToBackground) => BackgroundToContent | Promise<BackgroundToContent>): void } } } | undefined;
declare const chrome: typeof browser | undefined;
const runtime = typeof browser !== "undefined" ? browser : typeof chrome !== "undefined" ? chrome : undefined;
runtime?.runtime.onMessage.addListener((message) => {
  if (message.type === "lock") {
    session.lock();
    return { type: "locked" };
  }
  if (message.type === "offer") return session.offer(message.request);
  if (message.type === "fill") return session.fill(message.request, message.itemId, message.userGesture);
  // Saving is intentionally not implemented without a user-visible vault UI
  // and encryption callback; do not retain submitted credentials here.
  if (message.type === "save-submitted") return { type: "refused", reason: "locked" };
  return { type: "locked" };
});
