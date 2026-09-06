import {
  byteArrayToString,
  clearNumberArray,
  decideFill,
  fromByteArray,
  FillCapabilityStore,
  parseContentMessage,
  parsePopupMessage,
  SessionStateMachine,
  trustedContentSender,
  trustedPopupSender,
  type LoginCandidate,
  type RuntimeSender,
  type ValidatedPopupMessage,
  type VaultCandidateSource,
  type VaultManager,
} from "../../../packages/extension-adapters/src/index.ts";
import { createAssociationStorage, createInMemoryAssociationStorage, type AssociationStorage, type SavedAccount } from "./storage.ts";
import { ExtensionVaultManager } from "./vault-manager.ts";
import type { BackgroundToContent, BackgroundToPopup } from "./protocol.ts";

/** The subset of `VaultManager` this policy is willing to use, layered on
 * top of the base `VaultCandidateSource` fill/candidate seam so existing
 * content-fill tests can keep passing a minimal fake that implements only
 * `candidatesFor`/`fieldsFor`. */
type ExtensionVault = VaultCandidateSource & Partial<Omit<VaultManager, keyof VaultCandidateSource>>;

interface PendingOffer {
  tabId: number;
  origin: string;
  documentId: string;
  formActionOrigin: string;
  candidates: readonly LoginCandidate[];
}

/**
 * Trusted background policy core (ADR-0011 D1–D6).
 *
 * Authority is separated by validated sender identity, not by message
 * shape: content messages are honored only from this extension's top-frame
 * HTTPS document, popup messages only from the exact popup document, and
 * every message passes a strict schema before handling. Vault candidate
 * membership, fill fields, independent unlock, save/update, and TOTP all
 * come exclusively from a background-owned `VaultManager`
 * (`apps/extension/src/vault-manager.ts`), never satisfiable from a
 * content script or page. Nothing here persists vault state or logs
 * message contents — the only thing ever persisted is the non-secret
 * accountId/apiOrigin association (`apps/extension/src/storage.ts`).
 */
export class BackgroundPolicy {
  readonly session: SessionStateMachine;
  readonly #capabilities: FillCapabilityStore;
  readonly #ownExtensionId: string;
  readonly #popupUrl: string;
  readonly #now: () => number;
  readonly #getActiveTab: () => Promise<{ tabId: number; origin: string } | null>;
  readonly #sendToDocument: (tabId: number, documentId: string, message: BackgroundToContent) => Promise<boolean>;
  readonly #vault: ExtensionVault | null;
  readonly #associationStorage: AssociationStorage;
  #savedAccount: SavedAccount | null | undefined = undefined;
  #pendingOffer: PendingOffer | null = null;

  constructor(options: {
    ownExtensionId: string;
    popupUrl: string;
    now?: () => number;
    randomBytes?: (length: number) => Uint8Array;
    getActiveTab: () => Promise<{ tabId: number; origin: string } | null>;
    sendToDocument: (tabId: number, documentId: string, message: BackgroundToContent) => Promise<boolean>;
    /** Real production wiring passes an `ExtensionVaultManager`; tests may
     * pass a minimal fake implementing only `candidatesFor`/`fieldsFor`. */
    vault?: ExtensionVault | null;
    associationStorage?: AssociationStorage;
  }) {
    this.#ownExtensionId = options.ownExtensionId;
    this.#popupUrl = options.popupUrl;
    this.#now = options.now ?? (() => Date.now());
    this.session = new SessionStateMachine(this.#now);
    this.#capabilities = new FillCapabilityStore(options.randomBytes);
    this.#getActiveTab = options.getActiveTab;
    this.#sendToDocument = options.sendToDocument;
    this.#vault = options.vault ?? null;
    this.#associationStorage = options.associationStorage ?? createInMemoryAssociationStorage();
  }

  /** Every lock event invalidates offers and one-use capabilities, and
   * best-effort disposes the vault manager's own internal session/host/
   * item cache (a no-op if it is already locked). */
  lock(): void {
    this.session.lock("explicit");
    this.#capabilities.invalidateAll();
    this.#pendingOffer = null;
    this.#vault?.lock?.();
  }

  lockFromPopupClose(): void {
    this.session.lock("popup-closed");
    this.#capabilities.invalidateAll();
    this.#pendingOffer = null;
    this.#vault?.lock?.();
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

  async handlePopupMessage(message: unknown, sender: RuntimeSender | undefined): Promise<BackgroundToPopup> {
    this.session.ensureActive();
    if (!trustedPopupSender(sender, this.#ownExtensionId, this.#popupUrl)) return { type: "locked" };
    const parsed = parsePopupMessage(message);
    if (!parsed) return { type: "locked" };
    this.session.noteTrustedPopupActivity();
    switch (parsed.type) {
      case "get-state":
        return this.#getState();
      case "lock":
        this.lock();
        return { type: "locked" };
      case "logout":
        return this.#logout();
      case "request-candidates":
        return this.#requestCandidates();
      case "list-items":
        return this.#listItems();
      case "get-totp":
        return this.#getTotp(parsed.itemId);
      case "unlock":
        return this.#unlock(parsed.accountId, parsed.apiOrigin, parsed.password);
      case "save-item":
        return this.#saveItem(parsed);
      case "fill-selected":
        return this.#fillSelected(parsed.requestId, parsed.itemId);
    }
  }

  async #getState(): Promise<BackgroundToPopup> {
    if (this.#savedAccount === undefined) {
      this.#savedAccount = await this.#associationStorage.get().catch(() => null);
    }
    return {
      type: "state",
      locked: this.session.locked,
      unlockAvailable: this.#vault !== null && typeof this.#vault.unlock === "function",
      savedAccount: this.#savedAccount,
    };
  }

  async #unlock(accountId: string, apiOrigin: string, passwordBytes: number[]): Promise<BackgroundToPopup> {
    if (!this.#vault?.unlock) return { type: "refused", reason: "unlock-unavailable" };
    // Re-unlocking (e.g. switching accounts) first runs a full lock cycle
    // so outstanding offers/capabilities from any prior session never
    // survive into the new one.
    if (!this.session.locked) this.lock();
    const password = fromByteArray(passwordBytes);
    try {
      const result = await this.#vault.unlock(accountId, apiOrigin, password);
      if (!result.ok) return { type: "unlock-failed" };
      this.session.markUnlocked();
      this.#savedAccount = { accountId, apiOrigin };
      await this.#associationStorage.set(this.#savedAccount).catch(() => {});
      return { type: "unlocked" };
    } catch {
      return { type: "unlock-failed" };
    } finally {
      clearNumberArray(passwordBytes);
    }
  }

  async #logout(): Promise<BackgroundToPopup> {
    if (this.#vault?.logout) {
      try { await this.#vault.logout(); } catch { /* best-effort server revocation only */ }
    }
    this.session.lock("explicit");
    this.#capabilities.invalidateAll();
    this.#pendingOffer = null;
    return { type: "locked" };
  }

  #requestCandidates(): BackgroundToPopup | Promise<BackgroundToPopup> {
    if (this.session.locked || !this.#vault) return { type: "locked" };
    const offer = this.#pendingOffer;
    if (!offer) return { type: "refused", reason: "no-exact-origin-match" };
    if (!this.#vault.checkFresh) return this.#grantCandidates(offer);
    return this.#requestCandidatesFresh(offer);
  }

  async #requestCandidatesFresh(offer: PendingOffer): Promise<BackgroundToPopup> {
    const fresh = await this.#vault!.checkFresh!();
    if (!fresh || this.session.locked) return { type: "locked" };
    if (this.#pendingOffer !== offer) return { type: "refused", reason: "no-exact-origin-match" };
    return this.#grantCandidates(offer);
  }

  #grantCandidates(offer: PendingOffer): BackgroundToPopup {
    const requestId = this.#capabilities.grant(
      { generation: this.session.generation, tabId: offer.tabId, documentId: offer.documentId, origin: offer.origin, formActionOrigin: offer.formActionOrigin },
      this.#now(),
    );
    return { type: "candidates", requestId, candidates: [...offer.candidates] };
  }

  async #listItems(): Promise<BackgroundToPopup> {
    if (this.session.locked || !this.#vault?.listItems) return { type: "refused", reason: "unlock-unavailable" };
    if (this.#vault.checkFresh && !(await this.#vault.checkFresh())) return { type: "locked" };
    if (this.session.locked) return { type: "locked" };
    return { type: "items", items: [...this.#vault.listItems()] };
  }

  async #getTotp(itemId: string): Promise<BackgroundToPopup> {
    if (this.session.locked || !this.#vault?.getTotp) return { type: "refused", reason: "unlock-unavailable" };
    const totp = await this.#vault.getTotp(itemId);
    if (this.session.locked) return { type: "locked" };
    if (!totp) return { type: "refused", reason: "not-found" };
    return { type: "totp", code: totp.code, secondsRemaining: totp.secondsRemaining };
  }

  async #saveItem(parsed: Extract<ValidatedPopupMessage, { type: "save-item" }>): Promise<BackgroundToPopup> {
    if (this.session.locked || !this.#vault?.saveItem) return { type: "refused", reason: "unlock-unavailable" };
    try {
      const result = await this.#vault.saveItem({
        itemId: parsed.itemId,
        title: parsed.title,
        type: parsed.itemType,
        username: parsed.username,
        password: parsed.password ? byteArrayToString(parsed.password) : undefined,
        url: parsed.url,
        notes: parsed.notes ? byteArrayToString(parsed.notes) : undefined,
        totpSecret: parsed.totpSecret ? byteArrayToString(parsed.totpSecret) : undefined,
      });
      if (this.session.locked) return { type: "locked" };
      if (result.ok) return { type: "saved", itemId: result.itemId };
      if (result.reason === "locked") return { type: "locked" };
      return result.reason === "validation"
        ? { type: "save-failed", reason: "validation", problems: result.problems }
        : { type: "save-failed", reason: result.reason };
    } finally {
      if (parsed.password) clearNumberArray(parsed.password);
      if (parsed.notes) clearNumberArray(parsed.notes);
      if (parsed.totpSecret) clearNumberArray(parsed.totpSecret);
    }
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
    const fields = await this.#vault.fieldsFor(itemId, offer.origin);
    if (this.session.generation !== generationBefore) return { type: "refused", reason: "stale-capability" };
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
  storage?: { local: { get(keys: string[]): Promise<Record<string, unknown>>; set(items: Record<string, unknown>): Promise<void>; remove(keys: string[]): Promise<void> } };
};

declare const browser: Browser | undefined;
declare const chrome: Browser | undefined;
const runtimeApi = typeof browser !== "undefined" ? browser : typeof chrome !== "undefined" ? chrome : undefined;

if (runtimeApi) {
  const popupUrl = () => runtimeApi.runtime.getURL("popup.html");
  const isFirefox = typeof browser !== "undefined";
  let policy: BackgroundPolicy | undefined;
  // A static import: this module has no side effects until `.unlock()` is
  // actually called (creating the real WASM backend/OPAQUE client happens
  // lazily inside that method), so there is no cost to importing it eagerly
  // here — and a dynamic `import()` used previously introduced a real bug
  // (a proxy object standing in for the not-yet-resolved module, racing
  // against the extension's own top-level script re-evaluation during
  // load/reload) that could silently report "unlock unavailable" instead
  // of ever reaching the real manager.
  const vaultManager = new ExtensionVaultManager({
    deviceName: `Browser extension (${isFirefox ? "Firefox" : "Chrome"})`,
    onAuthFailure: () => policy?.lock(),
  });

  policy = new BackgroundPolicy({
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
    vault: vaultManager,
    associationStorage: runtimeApi.storage ? createAssociationStorage(runtimeApi.storage.local) : undefined,
  });
  runtimeApi.runtime.onConnect.addListener((port) => {
    if (!trustedPopupSender(port.sender, runtimeApi.runtime.id, popupUrl())) return;
    port.onDisconnect.addListener(() => policy!.lockFromPopupClose());
  });
  runtimeApi.runtime.onMessage.addListener((message, sender, sendResponse) => {
    // Popup and content senders are dispatched through disjoint validated
    // paths; a popup sender never carries a content tab identity.
    const result = sender.tab === undefined && sender.url === popupUrl()
      ? policy!.handlePopupMessage(message, sender)
      : policy!.handleContentMessage(message, sender);
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
