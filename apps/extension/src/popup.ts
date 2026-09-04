declare const browser: { runtime: { sendMessage(message: unknown): Promise<unknown> } } | undefined;
declare const chrome: { runtime: { sendMessage(message: unknown, callback: (response: unknown) => void): void } } | undefined;

function send(message: unknown): Promise<unknown> {
  if (typeof browser !== "undefined") return browser.runtime.sendMessage(message);
  return new Promise((resolve) => chrome?.runtime.sendMessage(message, resolve));
}

const status = document.querySelector<HTMLElement>("#status");
const lock = document.querySelector<HTMLButtonElement>("#lock");
const choices = document.querySelector<HTMLElement>("#choices");

function showCandidates(response: unknown): void {
  if (!choices || !status || typeof response !== "object" || response === null || !("type" in response)) return;
  const message = response as { type: string; candidates?: { id: string; title: string }[] };
  if (message.type !== "candidates" || !message.candidates?.length) {
    status.textContent = "No safe login offer on this page.";
    return;
  }
  status.textContent = "Select a login to fill.";
  choices.replaceChildren(...message.candidates.map((candidate) => {
    const button = document.createElement("button");
    button.type = "button";
    button.textContent = candidate.title;
    button.addEventListener("click", async () => {
      // This click is the fresh user gesture required by the background.
      await send({ type: "fill-selected", itemId: candidate.id, userGesture: true });
      window.close();
    });
    return button;
  }));
}

void send({ type: "get-offer" }).then(showCandidates).catch(() => {
  if (status) status.textContent = "Extension unavailable.";
});
lock?.addEventListener("click", async () => {
  await send({ type: "lock" });
  if (status) status.textContent = "Locked";
});
