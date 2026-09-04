import { h, mount } from "../lib/dom.ts";
import type { AppContext } from "../lib/context.ts";
import type { Device } from "@zkpm/sdk";
import { getOrCreateAccountId } from "../crypto/account-id.ts";

export function renderDevices(root: HTMLElement, ctx: AppContext): void {
  let devices: Device[] = [];
  let error = "";
  let revokeTarget: string | null = null;

  async function load(): Promise<void> {
    try {
      devices = await ctx.api.listDevices();
      error = "";
    } catch {
      error = "Could not load devices (are you online and logged in?).";
    }
    render();
  }

  function render(): void {
    mount(
      root,
      h(
        "div",
        { class: "panel" },
        h("h1", {}, "Devices"),
        h("button", { type: "button", onclick: () => ctx.navigate({ name: "vault" }) }, "Back to vault"),
        error ? h("p", { class: "error", role: "alert" }, error) : null,
        h("table", {},
          h("thead", {}, h("tr", {}, h("th", {}, "Name"), h("th", {}, "Last seen"), h("th", {}, "Status"), h("th", {}, ""))),
          h("tbody", {}, ...devices.map((d) =>
            h("tr", {},
              h("td", {}, d.name),
              h("td", {}, d.lastSeenAt ?? "never"),
              h("td", {}, d.revokedAt ? "revoked" : "active"),
              h("td", {}, d.revokedAt ? null : h("button", {
                type: "button", class: "danger",
                onclick: () => { revokeTarget = d.deviceId; render(); },
              }, "Revoke")),
            ),
          )),
        ),
        revokeTarget ? revokeConfirm(revokeTarget) : null,
      ),
    );
  }

  function revokeConfirm(deviceId: string): HTMLElement {
    return h(
      "form",
      {
        class: "panel",
        onsubmit: async (e: Event) => {
          e.preventDefault();
          const form = e.currentTarget as HTMLFormElement;
          const input = form.elements.namedItem("password") as HTMLInputElement;
          const passwordBytes = new TextEncoder().encode(input.value);
          input.value = "";
          try {
            await ctx.auth.login(getOrCreateAccountId(), passwordBytes);
            await ctx.api.revokeDevice(deviceId);
            revokeTarget = null;
            ctx.announcer.status("Device revoked.");
            await load();
          } catch {
            error = "Could not revoke device (re-authentication failed).";
            ctx.announcer.error(error);
            render();
          } finally {
            passwordBytes.fill(0);
          }
        },
      },
      h("h2", {}, "Re-enter your master password to revoke this device"),
      h("label", { for: "password" }, "Master password"),
      h("input", { id: "password", name: "password", type: "password", required: true, autocomplete: "current-password" }),
      h("div", { class: "toolbar" },
        h("button", { type: "submit", class: "danger" }, "Revoke device"),
        h("button", { type: "button", onclick: () => { revokeTarget = null; render(); } }, "Cancel"),
      ),
    );
  }

  render();
  load();
}
