import {
  decideFill,
  FillCapabilityStore,
  parseContentMessage,
  parsePopupMessage,
  SessionStateMachine,
  trustedContentSender,
  trustedPopupSender,
  type LoginCandidate,
  type RefusalReason,
  type RuntimeSender,
  type VaultCandidateSource,
} from "../../../packages/extension-adapters/src/index.ts";
import type { BackgroundToContent, BackgroundToPopup } from "./protocol.ts";

/**
 * Trusted background policy core (ADR-0011 D1–D5).
 *
 * Authority is separated by validated sender identity, not by message
 * shape: content messages are honored only from this extension's top-frame
 * HTTPS document, popup messages only from the exact popup document, and
 * every message passes a strict schema before handling. Vault candidate
 * membership and fill fields come exclusively from a background-owned
 * `VaultCandidateSource`; until C04-G1 merges the independent unlock, no
 * such source exists, so the session stays locked and every offer is
 * refused. Nothing here persists state or logs message contents.
 */
export class BackgroundPolicy {
  readonly session: SessionStateMachine;
  readonly #capabilities: FillCapabilityStore;
  readonly #ownExtensionId: string;
  readonly #popupUrl: string;
  readonly #now: () => number;
  readonly #getActiveTab: () => Promise<{ tabId: number; origin: string } | null>;
  readonly #sendToDocument: (tabId: number, documentId: string, message: BackgroundToContent) => Promise<boolean>;
  readonly #vault: VaultCandidateSource | null;
  #pendingOffer: { tabId: number; origin: string; documentId: string; formActionOrigin: string; candidates: readonly LoginCandidate[] } | null = null;

  constructor(options: {
    ownExtensionId: string;
    popupUrl: string;
    now?: () => number;
    randomBytes?: (length: number) => Uint8Array;
    getActiveTab: () => Promise<{ tabId: number; origin: string } | null>;
    sendToDocument: (tabId: number, documentId: string, message: BackgroundToContent) => Promise<boolean>;
    /** Production wiring passes null until C04-G1 provides real unlock. */
    vault?: VaultCandidateSource | null;
  }) {
    this.#ownExtensionId = options.ownExtensionId;
    this.#popupUrl = options.popupUrl;
    this.#now = options.now ?? (() => Date.now());
    this.session = new SessionStateMachine(this.#now);
    this.#capabilities = new FillCapabilityStore(options.randomBytes);
    this.#getActiveTab = options.getActiveTab;
    this.#sendToDocument = options.sendToDocument;
    this.#vault = options.vault ?? null;
  }

  /** Every lock event invalidates offers and one-use capabilities. */
  lock(): void {
    this.session.lock("explicit");
    this.#capabilities.invalidateAll();
    this.#pendingOffer = null;
  }

  lockFromPopupClose(): void {
    this.session.lock("popup-closed");
    this.#capabilities.invalidateAll();
    this.#pendingOffer = null;
  }

  handleContentMessage(message: unknown, sender: RuntimeSender | undefined): BackgroundToContent {
    this.session.ensureActive();
    const trusted = trustedContentSender(sender, this.#ownExtensionId);
    if (!trusted) return { type: "locked" };
    const parsed = parseContentMessage(message);
    if (!parsed) return { type: "refused", reason: "locked" };
    if (parsed.type === "cancel-offer") {
      if (this.#pendingOffer?.tabId === trusted.tabId) this.#pendingOffer = null;
      return { type: "locked" };
    }
    if (this.session.locked || !this.#vault) return { type: "refused", reason: "locked" };
    // The browser-provided sender URL is authoritative; a page-supplied
    // pageUrl from a different document is hostile metadata and refused.
    if (parsed.request.pageUrl !== trusted.url) return { type: "refused", reason: "invalid-page" };
    const decision = decideFill(parsed.request, this.#vault.candidatesFor(trusted.origin));
    if (!decision.allowed) return { type: "refused", reason: decision.reason };
    if (trusted.documentId === null) {
      // Cannot prove the top document identity on this build: no fill
      // capability is granted, so a later selection cannot deliver fields.
      this.#pendingOffer = null;
      return { type: "refused", reason: "document-targeting-unsupported" };
    }
    this.#pendingOffer = {
      tabId: trusted.tabId,
      origin: trusted.origin,
      documentId: trusted.documentId,
      formActionOrigin: parsed.request.formAction ?? trusted.origin,
      candidates: decision.candidates,
    };
    return { type: "offer-available" };
  }

  handlePopupMessage(message: unknown, sender: RuntimeSender | undefined): BackgroundToPopup {
    this.session.ensureActive();
    if (!trustedPopupSender(sender, this.#ownExtensionId, this.#popupUrl)) return { type: "locked" };
    const parsed = parsePopupMessage(message);
    if (!parsed) return { type: "locked" };
    this.session.noteTrustedPopupActivity();
    if (parsed.type === "get-state") {
      return { type: "state", locked: this.session.locked, unlockAvailable: false };
    }
    if (parsed.type === "lock") {
      this.lock();
      return { type: "locked" };
    }
    if (parsed.type === "request-candidates") {
      return this.#requestCandidates();
    }
    return this.#fillSelected(parsed.requestId, parsed.itemId);
  }

  #requestCandidates(): BackgroundToPopup {
    if (this.session.locked || !this.#vault) return { type: "locked" };
    const offer = this.#pendingOffer;
    if (!offer) return { type: "refused", reason: "no-exact-origin-match" };
    const requestId = this.#capabilities.grant(
      { generation: this.session.generation, tabId: offer.tabId, documentId: offer.documentId, origin: offer.origin, formActionOrigin: offer.formActionOrigin },
      this.#now(),
    );
    return { type: "candidates", requestId, candidates: [...offer.candidates] };
  }

  async #fillSelected(requestId: string, itemId: string): Promise<BackgroundToPopup> {
    if (this.session.locked || !this.#vault) return { type: "locked" };
    const offer = this.#pendingOffer;
    if (!offer) return { type: "refused", reason: "stale-capability" };
    if (!offer.candidates.some((candidate) => candidate.id === itemId)) {
      return { type: "refused", reason: "no-exact-origin-match" };
    }
    const generationBefore = this.session.generation;
    const active = await this.#getActiveTab();
    // A lock during the await invalidates the whole attempt.
    if (this.session.locked || this.session.generation !== generationBefore) {
      return { type: "refused", reason: "stale-capability" };
    }
    // Tab switch or navigation away from the bound exact origin fails closed.
    if (!active || active.tabId !== offer.tabId || active.origin !== offer.origin) {
      this.#capabilities.consume(requestId, { generation: -1, tabId: -1, documentId: "", origin: "", formActionOrigin: "" }, this.#now());
      return { type: "refused", reason: "stale-capability" };
    }
    const consumed = this.#capabilities.consume(
      requestId,
      { generation: this.session.generation, tabId: offer.tabId, documentId: offer.documentId, origin: offer.origin, formActionOrigin: offer.formActionOrigin },
      this.#now(),
    );
    if (!consumed.ok) return { type: "refused", reason: "stale-capability" };
    const fields = this.#vault.fieldsFor(itemId, offer.origin);
    if (fields === null) return { type: "refused", reason: "no-exact-origin-match" };
    const generationAtRelease = this.session.generation;
    let delivered = false;
    try {
      delivered = await this.#sendToDocument(offer.tabId, offer.documentId, {
        type: "fill",
        origin: offer.origin,
        username: fields.username,
        password: fields.password,
        ...(fields.totp ? { totp: fields.totp } : {}),
      });
    } catch {
      delivered = false;
    }
    this.#pendingOffer = null;
    if (this.session.generation !== generationAtRelease) {
      this.lock();
      return { type: "refused", reason: "stale-capability" };
    }
    return delivered ? { type: "locked" } : { type: "refused", reason: "document-targeting-unsupported" };
  }
}

/** Wiring for the real extension runtime (Chrome MV3 / Firefox MV2). */
type Browser = {
  runtime: { id: string; getURL(path: string): string; onMessage: { addListener(listener: (message: unknown, sender: RuntimeSender, sendResponse: (response: unknown) => void) => unknown): void }; onConnect: { addListener(listener: (port: { sender?: RuntimeSender; onDisconnect: { addListener(listener: () => void): void } }) => void): void } };
  tabs: { query(query: Record<string, unknown>): Promise<{ id?: number; url?: string }[]>; sendMessage(tabId: number, message: unknown, options: { documentId: string }, callback: (response: unknown) => void): void };
};

declare const browser: Browser | undefined;
declare const chrome: Browser | undefined;
const runtimeApi = typeof browser !== "undefined" ? browser : typeof chrome !== "undefined" ? chrome : undefined;

if (runtimeApi) {
  const popupUrl = () => runtimeApi.runtime.getURL("popup.html");
  const policy = new BackgroundPolicy({
    ownExtensionId: runtimeApi.runtime.id,
    popupUrl: popupUrl(),
    getActiveTab: async () => {
      const tabs = await runtimeApi.tabs.query({ active: true, currentWindow: true });
      const tab = tabs[0];
      if (typeof tab?.id !== "number" || typeof tab.url !== "string") return null;
      let origin: string;
      try {
        origin = new URL(tab.url).origin;
      } catch {
        return null;
      }
      return { tabId: tab.id, origin };
    },
    sendToDocument: (tabId, documentId, message) =>
      new Promise((resolve) => {
        try {
          runtimeApi.tabs.sendMessage(tabId, message, { documentId }, () => resolve(true));
        } catch {
          resolve(false);
        }
      }),
    vault: null,
  });
  runtimeApi.runtime.onConnect.addListener((port) => {
    if (!trustedPopupSender(port.sender, runtimeApi.runtime.id, popupUrl())) return;
    port.onDisconnect.addListener(() => policy.lockFromPopupClose());
  });
  runtimeApi.runtime.onMessage.addListener((message, sender, sendResponse) => {
    // Popup and content senders are dispatched through disjoint validated
    // paths; a popup sender never carries a content tab identity.
    const result = sender.tab === undefined && sender.url === popupUrl()
      ? policy.handlePopupMessage(message, sender)
      : policy.handleContentMessage(message, sender);
    if (result !== undefined && typeof (result as { then?: unknown }).then === "function") {
      (result as Promise<unknown>)
        .then((value) => sendResponse(value))
        .catch(() => sendResponse({ type: "locked" }));
      return true;
    }
    sendResponse(result);
    return false;
  });
}
