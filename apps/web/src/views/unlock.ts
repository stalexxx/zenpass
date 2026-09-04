import { h, mount } from "../lib/dom.ts";
import type { AppContext } from "../lib/context.ts";
import { getOrCreateAccountId, getDisplayEmail } from "../crypto/account-id.ts";
import { loadAccountBundle } from "../vault/account-bundle.ts";

const REPORTED_PHYSICAL_MEMORY_KIB = 262_144n;

export function renderUnlock(root: HTMLElement, ctx: AppContext): void {
  const accountId = getOrCreateAccountId();
  const bundle = loadAccountBundle(accountId);
  if (!bundle) {
    ctx.navigate({ name: "onboarding" });
    return;
  }
  const email = getDisplayEmail();
  let error = "";

  function render(): void {
    mount(
      root,
      h(
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
              // Local unlock never requires the network (docs/ux/flows.md:
              // "Offline unlock uses only the local encrypted snapshot and
              // wrapped key bundle").
              await ctx.vault.unlockWithPassword(bundle, passwordBytes.slice());
              ctx.announcer.status("Vault unlocked.");
              ctx.resetInactivityTimer();
              // Best-effort, non-blocking: establish (or refresh) an
              // authenticated API session for sync. Offline/failed login
              // does not block local vault access.
              ctx.auth.login(accountId, passwordBytes).catch(() => {
                ctx.announcer.status("Unlocked offline. Sync will resume when a connection is available.");
              });
              ctx.navigate({ name: "vault" });
            } catch {
              error = "Incorrect password.";
              ctx.announcer.error(error);
              render();
            } finally {
              passwordBytes.fill(0);
            }
          },
        },
        h("h1", {}, "Unlock your vault"),
        email ? h("p", { class: "hint" }, `Signed in as ${email}`) : null,
        error ? h("p", { class: "error", role: "alert" }, error) : null,
        h("label", { for: "password" }, "Master password"),
        h("input", { id: "password", name: "password", type: "password", required: true, autocomplete: "current-password", autofocus: true }),
        h("button", { type: "submit" }, "Unlock"),
      ),
    );
  }

  render();
}
