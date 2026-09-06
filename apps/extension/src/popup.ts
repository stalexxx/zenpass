import { stringToByteArray, clearNumberArray } from "../../../packages/extension-adapters/src/index.ts";
import type { BackgroundToPopup, PopupToBackground } from "./protocol.ts";

declare const browser: { runtime: { sendMessage(message: unknown): Promise<unknown>; connect?: (connectInfo?: { name?: string }) => { disconnect(): void } } } | undefined;
declare const chrome: { runtime: { sendMessage(message: unknown, callback: (response: unknown) => void): void; connect?: (connectInfo?: { name?: string }) => { disconnect(): void } } } | undefined;

function send(message: PopupToBackground): Promise<BackgroundToPopup> {
  if (typeof browser !== "undefined") return browser.runtime.sendMessage(message) as Promise<BackgroundToPopup>;
  return new Promise((resolve) => chrome?.runtime.sendMessage(message, resolve as (response: unknown) => void));
}

// A live port lets the background treat popup close as a lock event. The
// port name must be passed as `{ name }` (an object) — a bare string
// argument is `chrome.runtime.connect`'s *targetExtensionId* overload, and
// throws synchronously ("Invalid extension id") for anything that isn't a
// real 32-character extension id, which previously aborted this entire
// module's top-level execution (including the `get-state` request below)
// before it ever ran.
const connectApi = typeof browser !== "undefined" ? browser.runtime : typeof chrome !== "undefined" ? chrome.runtime : undefined;
try {
  connectApi?.connect?.({ name: "zkpm-popup" });
} catch {
  // A connect failure must never prevent the rest of the popup (state,
  // unlock, save, TOTP) from working — popup-close-locks is defense in
  // depth, not the only lock trigger.
}

const status = document.querySelector<HTMLElement>("#status");
const unlockForm = document.querySelector<HTMLFormElement>("#unlock-form");
const accountIdInput = document.querySelector<HTMLInputElement>("#accountId");
const apiOriginInput = document.querySelector<HTMLInputElement>("#apiOrigin");
const masterPasswordInput = document.querySelector<HTMLInputElement>("#masterPassword");
const choices = document.querySelector<HTMLElement>("#choices");
const unlockedPanel = document.querySelector<HTMLElement>("#unlocked-panel");
const itemsSection = document.querySelector<HTMLElement>("#items");
const saveForm = document.querySelector<HTMLFormElement>("#save-form");
const saveItemIdInput = document.querySelector<HTMLInputElement>("#save-itemId");
const saveTitleInput = document.querySelector<HTMLInputElement>("#save-title");
const saveTypeSelect = document.querySelector<HTMLSelectElement>("#save-type");
const saveUsernameInput = document.querySelector<HTMLInputElement>("#save-username");
const savePasswordInput = document.querySelector<HTMLInputElement>("#save-password");
const saveUrlInput = document.querySelector<HTMLInputElement>("#save-url");
const saveNotesInput = document.querySelector<HTMLTextAreaElement>("#save-notes");
const saveTotpInput = document.querySelector<HTMLInputElement>("#save-totp");
const totpDisplay = document.querySelector<HTMLElement>("#totp-display");
const lockButton = document.querySelector<HTMLButtonElement>("#lock");
const logoutButton = document.querySelector<HTMLButtonElement>("#logout");

function setStatus(text: string): void {
  if (status) status.textContent = text;
}

function resetSaveForm(): void {
  saveForm?.reset();
  if (saveItemIdInput) saveItemIdInput.value = "";
}

async function refreshItems(): Promise<void> {
  const response = await send({ type: "list-items" });
  if (response.type !== "items") {
    if (itemsSection) itemsSection.replaceChildren();
    return;
  }
  itemsSection?.replaceChildren(
    ...response.items.map((item) => {
      const row = document.createElement("div");
      const label = document.createElement("span");
      label.textContent = `${item.title}${item.username ? ` (${item.username})` : ""}`;
      row.appendChild(label);

      const editButton = document.createElement("button");
      editButton.type = "button";
      editButton.textContent = "Edit";
      editButton.addEventListener("click", () => {
        if (saveItemIdInput) saveItemIdInput.value = item.itemId;
        if (saveTitleInput) saveTitleInput.value = item.title;
        if (saveTypeSelect) saveTypeSelect.value = item.type;
        if (saveUsernameInput) saveUsernameInput.value = item.username ?? "";
        if (saveUrlInput) saveUrlInput.value = item.url ?? "";
        if (savePasswordInput) savePasswordInput.value = "";
        if (saveNotesInput) saveNotesInput.value = "";
        if (saveTotpInput) saveTotpInput.value = "";
      });
      row.appendChild(editButton);

      if (item.type === "totp-login") {
        const totpButton = document.createElement("button");
        totpButton.type = "button";
        totpButton.textContent = "Show TOTP";
        totpButton.addEventListener("click", async () => {
          const totpResponse = await send({ type: "get-totp", itemId: item.itemId });
          if (totpDisplay) {
            totpDisplay.textContent = totpResponse.type === "totp"
              ? `${totpResponse.code} (expires in ${totpResponse.secondsRemaining}s)`
              : "Unavailable.";
          }
        });
        row.appendChild(totpButton);
      }
      return row;
    }),
  );
}

function showLocked(): void {
  if (unlockForm) unlockForm.hidden = false;
  if (unlockedPanel) unlockedPanel.hidden = true;
  choices?.replaceChildren();
  if (totpDisplay) totpDisplay.textContent = "";
}

async function showUnlocked(): Promise<void> {
  if (unlockForm) unlockForm.hidden = true;
  if (unlockedPanel) unlockedPanel.hidden = false;
  await refreshItems();
}

function showState(response: BackgroundToPopup): void {
  if (response.type === "state") {
    if (response.locked) {
      setStatus(response.unlockAvailable ? "Locked. Enter your account, API origin, and master password to unlock." : "Locked. Independent unlock is not available in this build.");
      if (response.savedAccount && accountIdInput && apiOriginInput) {
        accountIdInput.value = response.savedAccount.accountId;
        apiOriginInput.value = response.savedAccount.apiOrigin;
      }
      showLocked();
    } else {
      setStatus("Unlocked.");
      void showUnlocked();
    }
    return;
  }
  if (response.type === "candidates") {
    if (!response.candidates.length) {
      setStatus("No safe login offer on this page.");
      return;
    }
    const requestId = response.requestId;
    setStatus("Select a login to fill.");
    choices?.replaceChildren(...response.candidates.map((candidate) => {
      const button = document.createElement("button");
      button.type = "button";
      button.textContent = candidate.title;
      button.addEventListener("click", async () => {
        // This popup click is the trusted selection source; the
        // background validates the one-use capability before any fill.
        await send({ type: "fill-selected", requestId, itemId: candidate.id });
        window.close();
      });
      return button;
    }));
    return;
  }
  if (response.type === "locked") {
    setStatus("Locked.");
    showLocked();
    return;
  }
  if (response.type === "refused") setStatus("Locked.");
}

void send({ type: "get-state" }).then(showState).catch(() => setStatus("Extension unavailable."));
void send({ type: "request-candidates" }).then(showState).catch(() => {});

lockButton?.addEventListener("click", async () => {
  await send({ type: "lock" });
  setStatus("Locked");
  showLocked();
});

logoutButton?.addEventListener("click", async () => {
  await send({ type: "logout" });
  setStatus("Locked");
  showLocked();
});

unlockForm?.addEventListener("submit", async (event) => {
  event.preventDefault();
  const accountId = accountIdInput?.value ?? "";
  const apiOrigin = apiOriginInput?.value ?? "";
  const password = stringToByteArray(masterPasswordInput?.value ?? "");
  if (masterPasswordInput) masterPasswordInput.value = "";
  try {
    const response = await send({ type: "unlock", accountId, apiOrigin, password });
    if (response.type === "unlocked") {
      setStatus("Unlocked.");
      await showUnlocked();
    } else {
      setStatus("Could not unlock. Check your account ID, API origin, and password.");
    }
  } finally {
    clearNumberArray(password);
  }
});

saveForm?.addEventListener("submit", async (event) => {
  event.preventDefault();
  const itemId = saveItemIdInput?.value || undefined;
  const title = saveTitleInput?.value ?? "";
  const itemType = (saveTypeSelect?.value ?? "login") as "login" | "note" | "totp-login";
  const username = saveUsernameInput?.value || undefined;
  const url = saveUrlInput?.value || undefined;
  const passwordValue = savePasswordInput?.value ?? "";
  const notesValue = saveNotesInput?.value ?? "";
  const totpValue = saveTotpInput?.value ?? "";
  const password = passwordValue.length > 0 ? stringToByteArray(passwordValue) : undefined;
  const notes = notesValue.length > 0 ? stringToByteArray(notesValue) : undefined;
  const totpSecret = totpValue.length > 0 ? stringToByteArray(totpValue) : undefined;
  if (savePasswordInput) savePasswordInput.value = "";
  if (saveNotesInput) saveNotesInput.value = "";
  if (saveTotpInput) saveTotpInput.value = "";
  try {
    const response = await send({ type: "save-item", itemId, title, itemType, username, password, url, notes, totpSecret });
    if (response.type === "saved") {
      setStatus("Saved.");
      resetSaveForm();
      await refreshItems();
    } else if (response.type === "save-failed") {
      setStatus(response.reason === "validation" && response.problems ? response.problems.join(" ") : `Could not save (${response.reason}).`);
    } else if (response.type === "locked") {
      setStatus("Locked.");
      showLocked();
    }
  } finally {
    if (password) clearNumberArray(password);
    if (notes) clearNumberArray(notes);
    if (totpSecret) clearNumberArray(totpSecret);
  }
});
