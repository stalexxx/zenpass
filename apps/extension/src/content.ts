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

function requestFor(form: HTMLFormElement) {
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

/**
 * The UI that chooses a candidate lives in the extension popup. Content code
 * receives values only after that explicit selection is forwarded as a click.
 */
export async function fillSelected(form: HTMLFormElement, itemId: string, userGesture: boolean): Promise<boolean> {
  const username = usernameInput(form);
  const password = passwordInput(form);
  if (!username || !password) return false;
  const response = await send({ type: "fill", request: requestFor(form), itemId, userGesture });
  if (response.type !== "fill") return false;
  setValue(username, response.username);
  setValue(password, response.password);
  return true;
}

/** Offer metadata only; no field values leave the background before selection. */
export async function requestCandidates(form: HTMLFormElement): Promise<BackgroundToContent> {
  return send({ type: "offer", request: requestFor(form) });
}

let activeForm: HTMLFormElement | null = null;
document.addEventListener("focusin", (event) => {
  const target = event.target;
  if (!(target instanceof HTMLInputElement)) return;
  const form = target.form;
  if (form && passwordInput(form)) {
    activeForm = form;
    void requestCandidates(form);
  }
});

const inboundRuntime = typeof browser !== "undefined" ? browser : typeof chrome !== "undefined" ? chrome : undefined;
if (inboundRuntime) {
  // Values arrive only from the extension background after a popup click.
  (inboundRuntime as unknown as { runtime: { onMessage: { addListener(listener: (message: BackgroundToContent) => void): void } } }).runtime.onMessage.addListener((message) => {
    if (message.type !== "fill" || !activeForm) return;
    const username = usernameInput(activeForm);
    const password = passwordInput(activeForm);
    if (username && password) { setValue(username, message.username); setValue(password, message.password); }
  });
}

document.addEventListener("submit", (event) => {
  const form = event.target;
  if (!(form instanceof HTMLFormElement) || window.top !== window) return;
  const username = usernameInput(form);
  const password = passwordInput(form);
  if (!username || !password) return;
  // The background refuses to retain this until a future encrypted, visible
  // save/update flow exists. This message creates no persistence by itself.
  void send({ type: "save-submitted", origin: location.origin, username: username.value, password: password.value });
});
