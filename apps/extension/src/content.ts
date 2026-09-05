import type { BackgroundToContent, ContentToBackground } from "./protocol.ts";

declare const browser: { runtime: { sendMessage(message: ContentToBackground): Promise<BackgroundToContent> } } | undefined;
declare const chrome: { runtime: { sendMessage(message: ContentToBackground, callback: (response: BackgroundToContent) => void): void } } | undefined;

function send(message: ContentToBackground): Promise<BackgroundToContent> {
  if (typeof browser !== "undefined") return browser.runtime.sendMessage(message);
  return new Promise((resolve) => chrome?.runtime.sendMessage(message, resolve));
}

function visible(input: HTMLInputElement | null): input is HTMLInputElement {
  if (!input || input.type === "hidden" || input.disabled || input.readOnly) return false;
  const style = getComputedStyle(input);
  return style.display !== "none" && style.visibility !== "hidden" && input.getClientRects().length > 0;
}

function passwordInput(form: HTMLFormElement): HTMLInputElement | null {
  return [...form.querySelectorAll<HTMLInputElement>('input[type="password"]')].find(visible) ?? null;
}

function usernameInput(form: HTMLFormElement): HTMLInputElement | null {
  return [...form.querySelectorAll<HTMLInputElement>('input[autocomplete="username"], input[type="email"], input[type="text"]')].find(visible) ?? null;
}

/**
 * Bounded, non-secret offer metadata only (ADR-0011 "Page → content" and
 * "Content → background" rows). No field values, no credentials, and no
 * submit capture ever leave the page through this script.
 */
function offerMetadata(form: HTMLFormElement) {
  const password = passwordInput(form);
  const username = usernameInput(form);
  return {
    pageUrl: location.href,
    isTopFrame: window.top === window,
    formAction: form.action || location.href,
    usernameVisible: Boolean(username),
    passwordVisible: Boolean(password),
  };
}

function setValue(input: HTMLInputElement, value: string): void {
  const setter = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, "value")?.set;
  setter?.call(input, value);
  input.dispatchEvent(new Event("input", { bubbles: true }));
  input.dispatchEvent(new Event("change", { bubbles: true }));
}

let activeForm: HTMLFormElement | null = null;

document.addEventListener("focusin", (event) => {
  const target = event.target;
  if (!(target instanceof HTMLInputElement)) return;
  const form = target.form;
  if (form && passwordInput(form)) {
    activeForm = form;
    void send({ type: "offer", request: offerMetadata(form) }).catch(() => undefined);
  }
});

// Navigation invalidates any pending offer; cancel it immediately.
window.addEventListener("pagehide", () => {
  void send({ type: "cancel-offer" }).catch(() => undefined);
});

const inboundRuntime = typeof browser !== "undefined" ? browser : typeof chrome !== "undefined" ? chrome : undefined;
if (inboundRuntime) {
  // Values arrive only from the trusted background, targeted at this exact
  // document via a one-use capability. The bound origin, top frame,
  // HTTPS scheme, visible/enabled/editable fields, and same-origin form
  // action are all rechecked immediately before assignment.
  (inboundRuntime as unknown as { runtime: { onMessage: { addListener(listener: (message: BackgroundToContent) => void): void } } }).runtime.onMessage.addListener((message) => {
    if (message.type !== "fill" || !activeForm) return;
    if (window.top !== window || location.origin !== message.origin || location.protocol !== "https:") return;
    const form = activeForm;
    if (!form.action || new URL(form.action, location.href).origin !== location.origin) return;
    const username = usernameInput(form);
    const password = passwordInput(form);
    if (username && password && !username.disabled && !password.disabled && !username.readOnly && !password.readOnly) {
      setValue(username, message.username);
      setValue(password, message.password);
    }
  });
}
