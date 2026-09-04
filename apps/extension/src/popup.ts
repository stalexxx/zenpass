declare const browser: { runtime: { sendMessage(message: unknown): Promise<unknown> } } | undefined;
declare const chrome: { runtime: { sendMessage(message: unknown, callback: (response: unknown) => void): void } } | undefined;

function send(message: unknown): Promise<unknown> {
  if (typeof browser !== "undefined") return browser.runtime.sendMessage(message);
  return new Promise((resolve) => chrome?.runtime.sendMessage(message, resolve));
}

const status = document.querySelector<HTMLElement>("#status");
const lock = document.querySelector<HTMLButtonElement>("#lock");
lock?.addEventListener("click", async () => {
  await send({ type: "lock" });
  if (status) status.textContent = "Locked";
});
