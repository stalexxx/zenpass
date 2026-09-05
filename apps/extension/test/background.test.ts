import { describe, expect, test } from "bun:test";
import { BackgroundPolicy } from "../src/background.ts";
import type { LoginCandidate, VaultCandidateSource } from "../../../../packages/extension-adapters/src/index.ts";

/**
 * Boundary tests for the trusted background. Placeholder field values in
 * the fake vault are empty strings: no real or realistic secret is fixed
 * here, and no production unlock path exists.
 */
const ownId = "ext-id";
const popupUrl = `chrome-extension://${ownId}/popup.html`;
const pageUrl = "https://example.test/login";
const contentSender = { id: ownId, url: pageUrl, tab: { id: 7 }, frameId: 0, documentId: "doc-1" };
const popupSender = { id: ownId, url: popupUrl };
const offerMessage = { type: "offer", request: { pageUrl, isTopFrame: true, formAction: "https://example.test/session", usernameVisible: true, passwordVisible: true } };

function fakeVault(candidates: LoginCandidate[]): VaultCandidateSource {
  return {
    candidatesFor: (origin) => candidates.filter((c) => c.origin === origin),
    fieldsFor: (itemId) => (itemId === "entry" ? { username: "", password: "" } : null),
  };
}

function policy(vault: VaultCandidateSource | null = fakeVault([{ id: "entry", title: "Entry", origin: "https://example.test" }])) {
  const sent: { tabId: number; documentId: string; message: unknown }[] = [];
  let active: { tabId: number; origin: string } | null = { tabId: 7, origin: "https://example.test" };
  const p = new BackgroundPolicy({
    ownExtensionId: ownId,
    popupUrl,
    now: () => 1_000,
    randomBytes: () => new Uint8Array(16).fill(0xcd),
    getActiveTab: async () => active,
    sendToDocument: async (tabId, documentId, message) => {
      sent.push({ tabId, documentId, message });
      return true;
    },
    vault,
  });
  // Tests exercise the capability flow through the C04-G1 unlock seam;
  // production has no caller for markUnlocked until that merge.
  if (vault) p.session.markUnlocked();
  return { p, sent, setActive: (value: typeof active) => { active = value; } };
}

describe("production default: locked, no vault source", () => {
  test("every content offer is refused and no candidates exist", () => {
    const { p } = policy(null);
    expect(p.handleContentMessage(offerMessage, contentSender)).toEqual({ type: "refused", reason: "locked" });
    expect(p.handlePopupMessage({ type: "request-candidates" }, popupSender)).toEqual({ type: "locked" });
    expect(p.handlePopupMessage({ type: "get-state" }, popupSender)).toEqual({ type: "state", locked: true, unlockAvailable: false });
  });
});

describe("content authority", () => {
  test("a content script cannot fill, save, enumerate, or select", () => {
    const { p } = policy();
    expect(p.handleContentMessage({ type: "fill", request: offerMessage.request, itemId: "entry", userGesture: true }, contentSender)).toEqual({ type: "refused", reason: "locked" });
    expect(p.handleContentMessage({ type: "save-submitted", origin: "https://example.test", username: "u", password: "p" }, contentSender)).toEqual({ type: "refused", reason: "locked" });
    expect(p.handleContentMessage({ type: "get-offer" }, contentSender)).toEqual({ type: "refused", reason: "locked" });
    expect(p.handleContentMessage({ type: "fill-selected", requestId: "r", itemId: "entry" }, contentSender)).toEqual({ type: "refused", reason: "locked" });
  });

  test("untrusted senders and spoofed page URLs are ignored", () => {
    const { p } = policy();
    expect(p.handleContentMessage(offerMessage, { ...contentSender, id: "other" })).toEqual({ type: "locked" });
    expect(p.handleContentMessage(offerMessage, { ...contentSender, frameId: 2 })).toEqual({ type: "locked" });
    expect(p.handleContentMessage({ ...offerMessage, request: { ...offerMessage.request, pageUrl: "https://evil.invalid/login" } }, contentSender)).toEqual({ type: "refused", reason: "invalid-page" });
  });

  test("no browser document identity means no fill capability", () => {
    const { p } = policy();
    expect(p.handleContentMessage(offerMessage, { ...contentSender, documentId: undefined })).toEqual({ type: "refused", reason: "document-targeting-unsupported" });
  });
});

describe("popup-only selection with one-use capabilities", () => {
  test("full flow grants, consumes once, and targets the exact document", async () => {
    const { p, sent } = policy();
    expect(p.handleContentMessage(offerMessage, contentSender)).toEqual({ type: "offer-available" });
    const response = p.handlePopupMessage({ type: "request-candidates" }, popupSender);
    expect(response.type).toBe("candidates");
    const requestId = (response as { requestId: string }).requestId;
    expect(await p.handlePopupMessage({ type: "fill-selected", requestId, itemId: "entry" }, popupSender)).toEqual({ type: "locked" });
    expect(sent).toEqual([{ tabId: 7, documentId: "doc-1", message: { type: "fill", origin: "https://example.test", username: "", password: "" } }]);
    // Replay of the same capability is refused.
    expect(await p.handlePopupMessage({ type: "fill-selected", requestId, itemId: "entry" }, popupSender)).toEqual({ type: "refused", reason: "stale-capability" });
  });

  test("tab switch or navigation between grant and selection fails closed", async () => {
    const { p, sent, setActive } = policy();
    p.handleContentMessage(offerMessage, contentSender);
    const requestId = (p.handlePopupMessage({ type: "request-candidates" }, popupSender) as { requestId: string }).requestId;
    setActive({ tabId: 8, origin: "https://example.test" });
    expect(await p.handlePopupMessage({ type: "fill-selected", requestId, itemId: "entry" }, popupSender)).toEqual({ type: "refused", reason: "stale-capability" });
    setActive(null);
    expect(p.handlePopupMessage({ type: "request-candidates" }, popupSender)).toEqual({ type: "locked" });
    expect(sent).toHaveLength(0);
  });

  test("a forged or unknown capability never delivers fields", async () => {
    const { p, sent } = policy();
    p.handleContentMessage(offerMessage, contentSender);
    expect(await p.handlePopupMessage({ type: "fill-selected", requestId: "forged", itemId: "entry" }, popupSender)).toEqual({ type: "refused", reason: "stale-capability" });
    expect(await p.handlePopupMessage({ type: "fill-selected", requestId: "forged", itemId: "not-a-candidate" }, popupSender)).toEqual({ type: "refused", reason: "no-exact-origin-match" });
    expect(sent).toHaveLength(0);
  });
});

describe("lock lifecycle", () => {
  test("popup close locks and invalidates outstanding capabilities", async () => {
    const { p, sent } = policy();
    p.handleContentMessage(offerMessage, contentSender);
    const requestId = (p.handlePopupMessage({ type: "request-candidates" }, popupSender) as { requestId: string }).requestId;
    p.lockFromPopupClose();
    expect(p.session.locked).toBe(true);
    expect(await p.handlePopupMessage({ type: "fill-selected", requestId, itemId: "entry" }, popupSender)).toEqual({ type: "locked" });
    expect(p.handleContentMessage(offerMessage, contentSender)).toEqual({ type: "refused", reason: "locked" });
    expect(sent).toHaveLength(0);
  });

  test("a late async response cannot deliver after a lock during the await", async () => {
    const { p, sent } = policy();
    p.handleContentMessage(offerMessage, contentSender);
    const requestId = (p.handlePopupMessage({ type: "request-candidates" }, popupSender) as { requestId: string }).requestId;
    const pending = p.handlePopupMessage({ type: "fill-selected", requestId, itemId: "entry" }, popupSender);
    p.lockFromPopupClose();
    expect(await pending).toEqual({ type: "refused", reason: "stale-capability" });
    expect(sent).toHaveLength(0);
  });

  test("a message with a popup-shaped payload from a content sender has no popup authority", () => {
    const { p } = policy();
    expect(p.handleContentMessage({ type: "get-state" }, contentSender)).toEqual({ type: "refused", reason: "locked" });
    expect(p.handlePopupMessage({ type: "offer", request: offerMessage.request }, popupSender)).toEqual({ type: "locked" });
  });
});
