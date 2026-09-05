import { describe, expect, test } from "bun:test";
import { FillCapabilityStore, parseContentMessage, parsePopupMessage, trustedContentSender, trustedPopupSender, SessionStateMachine, POPUP_INACTIVITY_LIMIT_MS, MAX_CAPABILITY_LIFETIME_MS, confirmFill, decideFill } from "../src/index.ts";

const candidate = { id: "item", title: "Entry", origin: "https://example.test" };
const safe = { pageUrl: "https://example.test/login", isTopFrame: true, formAction: "https://example.test/session", usernameVisible: true, passwordVisible: true };

test("offers only an exact HTTPS top-frame origin", () => {
  expect(decideFill(safe, [candidate])).toEqual({ allowed: true, candidates: [candidate] });
  expect(decideFill({ ...safe, pageUrl: "http://example.test" }, [candidate])).toEqual({ allowed: false, reason: "not-https" });
  expect(decideFill({ ...safe, pageUrl: "https://login.example.test", formAction: "https://login.example.test/session" }, [candidate])).toEqual({ allowed: false, reason: "no-exact-origin-match" });
  expect(decideFill({ ...safe, pageUrl: "https://example.test.attacker.invalid", formAction: "https://example.test.attacker.invalid/session" }, [candidate])).toEqual({ allowed: false, reason: "no-exact-origin-match" });
  expect(decideFill({ ...safe, isTopFrame: false }, [candidate])).toEqual({ allowed: false, reason: "not-top-frame" });
  expect(decideFill({ ...safe, passwordVisible: false }, [candidate])).toEqual({ allowed: false, reason: "hidden-field" });
  expect(decideFill({ ...safe, formAction: "https://attacker.invalid/collect" }, [candidate])).toEqual({ allowed: false, reason: "cross-origin-form" });
});

test("never treats a programmatic request as confirmation", () => {
  expect(confirmFill(false)).toEqual({ allowed: false, reason: "confirmation-required" });
  expect(confirmFill(true)).toEqual({ allowed: true });
});


const ownId = "ext-id";
const pageUrl = "https://example.test/login";
const offer = (overrides: Record<string, unknown> = {}) => ({
  type: "offer",
  request: { pageUrl, isTopFrame: true, formAction: "https://example.test/session", usernameVisible: true, passwordVisible: true, ...overrides },
});

describe("parseContentMessage", () => {
  test("accepts only bounded non-secret offer metadata or cancellation", () => {
    expect(parseContentMessage(offer())).toEqual({ type: "offer", request: { pageUrl, isTopFrame: true, formAction: "https://example.test/session", usernameVisible: true, passwordVisible: true } });
    expect(parseContentMessage({ type: "cancel-offer" })).toEqual({ type: "cancel-offer" });
  });

  test("rejects removed credential-bearing and selection messages", () => {
    expect(parseContentMessage({ type: "fill", request: {}, itemId: "x", userGesture: true })).toBeNull();
    expect(parseContentMessage({ type: "save-submitted", origin: "https://example.test", username: "u", password: "p" })).toBeNull();
    expect(parseContentMessage({ type: "get-offer" })).toBeNull();
    expect(parseContentMessage({ type: "fill-selected", itemId: "x" })).toBeNull();
  });

  test("rejects unknown fields, wrong types, and oversized strings", () => {
    expect(parseContentMessage({ ...offer(), extra: 1 })).toBeNull();
    expect(parseContentMessage(offer({ pageUrl: "x".repeat(4097) }))).toBeNull();
    expect(parseContentMessage(offer({ isTopFrame: "yes" }))).toBeNull();
    expect(parseContentMessage(offer({ formAction: "" }))).toBeNull();
    expect(parseContentMessage({ type: "offer", request: "not-an-object" })).toBeNull();
    expect(parseContentMessage(null)).toBeNull();
    expect(parseContentMessage(["offer"])).toBeNull();
  });
});

describe("parsePopupMessage", () => {
  test("accepts the four approved popup actions only", () => {
    expect(parsePopupMessage({ type: "get-state" })).toEqual({ type: "get-state" });
    expect(parsePopupMessage({ type: "request-candidates" })).toEqual({ type: "request-candidates" });
    expect(parsePopupMessage({ type: "lock" })).toEqual({ type: "lock" });
    expect(parsePopupMessage({ type: "fill-selected", requestId: "r", itemId: "i" })).toEqual({ type: "fill-selected", requestId: "r", itemId: "i" });
  });

  test("rejects unknown fields and injected payloads", () => {
    expect(parsePopupMessage({ type: "fill-selected", requestId: "r", itemId: "i", userGesture: true })).toBeNull();
    expect(parsePopupMessage({ type: "fill-selected", requestId: "", itemId: "i" })).toBeNull();
    expect(parsePopupMessage({ type: "unlock", password: "x" })).toBeNull();
    expect(parsePopupMessage({ type: "get-state", tabId: 3 })).toBeNull();
  });
});

describe("sender authority", () => {
  const popupUrl = `chrome-extension://${ownId}/popup.html`;

  test("content senders must be this extension in the top frame of an HTTPS tab", () => {
    expect(trustedContentSender({ id: ownId, url: pageUrl, tab: { id: 7 }, frameId: 0, documentId: "doc-1" }, ownId)).toEqual({ tabId: 7, url: pageUrl, origin: "https://example.test", documentId: "doc-1" });
    expect(trustedContentSender({ id: "other", url: pageUrl, tab: { id: 7 }, frameId: 0 }, ownId)).toBeNull();
    expect(trustedContentSender({ id: ownId, url: pageUrl, tab: { id: 7 }, frameId: 3 }, ownId)).toBeNull();
    expect(trustedContentSender({ id: ownId, url: pageUrl, frameId: 0 }, ownId)).toBeNull();
    expect(trustedContentSender({ id: ownId, url: "http://example.test/login", tab: { id: 7 }, frameId: 0 }, ownId)).toBeNull();
    expect(trustedContentSender({ id: ownId, tab: { id: 7 }, frameId: 0 }, ownId)).toBeNull();
    expect(trustedContentSender(undefined, ownId)).toBeNull();
  });

  test("popup senders must be this extension at the exact popup URL without a tab", () => {
    expect(trustedPopupSender({ id: ownId, url: popupUrl }, ownId, popupUrl)).toEqual({ url: popupUrl });
    expect(trustedPopupSender({ id: ownId, url: popupUrl, tab: { id: 7 } }, ownId, popupUrl)).toBeNull();
    expect(trustedPopupSender({ id: ownId, url: `chrome-extension://${ownId}/popup.html?x=1` }, ownId, popupUrl)).toBeNull();
    expect(trustedPopupSender({ id: ownId, url: "https://evil.invalid/popup.html" }, ownId, popupUrl)).toBeNull();
  });
});

describe("FillCapabilityStore", () => {
  const binding = { generation: 2, tabId: 7, documentId: "doc-1", origin: "https://example.test", formActionOrigin: "https://example.test" };
  const context = { ...binding };
  const deterministic = () => new Uint8Array(16).fill(0xab);
  const store = () => new FillCapabilityStore(deterministic);

  test("a valid capability is consumed exactly once", () => {
    const s = store();
    const id = s.grant(binding, 1_000);
    expect(s.consume(id, context, 1_000)).toEqual({ ok: true });
    expect(s.consume(id, context, 1_000)).toEqual({ ok: false, reason: "unknown" });
    expect(s.consume("missing", context, 1_000)).toEqual({ ok: false, reason: "unknown" });
  });

  test("expiry, generation, tab, document, and origin changes fail closed", () => {
    const s = store();
    const id = s.grant(binding, 1_000);
    expect(s.consume(id, context, 1_000 + MAX_CAPABILITY_LIFETIME_MS + 1)).toEqual({ ok: false, reason: "expired" });
    const id2 = s.grant(binding, 1_000);
    expect(s.consume(id2, { ...context, generation: 3 }, 1_000)).toEqual({ ok: false, reason: "generation-changed" });
    const id3 = s.grant(binding, 1_000);
    expect(s.consume(id3, { ...context, tabId: 8 }, 1_000)).toEqual({ ok: false, reason: "tab-changed" });
    const id4 = s.grant(binding, 1_000);
    expect(s.consume(id4, { ...context, documentId: "doc-2" }, 1_000)).toEqual({ ok: false, reason: "document-changed" });
    const id5 = s.grant(binding, 1_000);
    expect(s.consume(id5, { ...context, origin: "https://example.test.evil.invalid" }, 1_000)).toEqual({ ok: false, reason: "origin-changed" });
  });

  test("invalidateAll drops every outstanding capability", () => {
    const s = store();
    const id = s.grant(binding, 1_000);
    s.invalidateAll();
    expect(s.consume(id, context, 1_000)).toEqual({ ok: false, reason: "unknown" });
  });
});

describe("SessionStateMachine", () => {
  test("starts locked and lock increments the generation", () => {
    const s = new SessionStateMachine();
    expect(s.locked).toBe(true);
    const before = s.generation;
    s.markUnlocked();
    expect(s.locked).toBe(false);
    s.lock("explicit");
    expect(s.locked).toBe(true);
    expect(s.generation).toBe(before + 1);
    s.lock("popup-closed");
    expect(s.generation).toBe(before + 2);
  });

  test("only trusted popup activity extends the deadline; expiry fails closed", () => {
    let now = 10_000;
    const s = new SessionStateMachine(() => now);
    s.markUnlocked();
    now += POPUP_INACTIVITY_LIMIT_MS - 1;
    s.noteTrustedPopupActivity();
    now += POPUP_INACTIVITY_LIMIT_MS - 1;
    s.ensureActive();
    expect(s.locked).toBe(false);
    now += 2;
    s.ensureActive();
    expect(s.locked).toBe(true);
    expect(s.lastLockReason).toBe("timeout");
  });
});
