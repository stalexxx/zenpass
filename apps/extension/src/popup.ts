declare const browser: { runtime: { sendMessage(message: unknown): Promise<unknown>; connect?: (name: string) => { disconnect(): void } } } | undefined;
declare const chrome: { runtime: { sendMessage(message: unknown, callback: (response: unknown) => void): void; connect?: (name: string) => { disconnect(): void } } } | undefined;

function send(message: unknown): Promise<unknown> {
  if (typeof browser !== "undefined") return browser.runtime.sendMessage(message);
  return new Promise((resolve) => chrome?.runtime.sendMessage(message, resolve));
}

const status = document.querySelector<HTMLElement>("#status");
// A live port lets the background treat popup close as a lock event.
const connectApi = typeof browser !== "undefined" ? browser.runtime : typeof chrome !== "undefined" ? chrome.runtime : undefined;
connectApi?.connect?.("zkpm-popup");
const lock = document.querySelector<HTMLButtonElement>("#lock");
const choices = document.querySelector<HTMLElement>("#choices");

function setStatus(text: string): void {
  if (status) status.textContent = text;
}

function showState(response: unknown): void {
  if (typeof response !== "object" || response === null || !("type" in response)) return;
  const message = response as { type: string; locked?: boolean; unlockAvailable?: boolean };
  if (message.type === "state") {
    // Locked by default: independent unlock arrives with the C04-G1
    // API/SDK methods; this build deliberately offers no mocked path.
    setStatus(message.locked
      ? "Locked. Independent unlock is not available in this build."
      : "Unlocked.");
    return;
  }
  if (message.type === "candidates") {
    const candidates = (response as { candidates?: { id: string; title: string }[] }).candidates;
    if (!candidates?.length) {
      setStatus("No safe login offer on this page.");
      return;
    }
    const requestId = (response as { requestId: string }).requestId;
    setStatus("Select a login to fill.");
    choices?.replaceChildren(...candidates.map((candidate) => {
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
  if (message.type === "locked" || message.type === "refused") setStatus("Locked.");
}

void send({ type: "get-state" }).then(showState).catch(() => setStatus("Extension unavailable."));
lock?.addEventListener("click", async () => {
  await send({ type: "lock" });
  setStatus("Locked");
});
