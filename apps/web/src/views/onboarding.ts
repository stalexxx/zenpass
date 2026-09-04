import { h, mount } from "../lib/dom.ts";
import type { AppContext } from "../lib/context.ts";
import { getOrCreateAccountId, setDisplayEmail } from "../crypto/account-id.ts";
import { saveAccountBundle, type AccountBundle } from "../vault/account-bundle.ts";
import { fromProvisionalHex, PROVISIONAL_LABEL, toProvisionalHex } from "../crypto/recovery-display.ts";

const REPORTED_PHYSICAL_MEMORY_KIB = 262_144n; // Conservative fixed value (256MB); real detection is out of C01's scope.

export function renderOnboarding(root: HTMLElement, ctx: AppContext): void {
  let step: "form" | "reveal" | "confirm" = "form";
  let email = "";
  let password: Uint8Array | null = null;
  let recoveryHex = "";
  let bundle: AccountBundle | null = null;
  let error = "";

  function view(): HTMLElement {
    if (step === "form") return formView();
    if (step === "reveal") return revealView();
    return confirmView();
  }

  function formView(): HTMLElement {
    return h(
      "form",
      {
        class: "panel",
        onsubmit: async (e: Event) => {
          e.preventDefault();
          const form = e.currentTarget as HTMLFormElement;
          const emailInput = form.elements.namedItem("email") as HTMLInputElement;
          const passwordInput = form.elements.namedItem("password") as HTMLInputElement;
          const confirmInput = form.elements.namedItem("passwordConfirm") as HTMLInputElement;
          if (passwordInput.value.length < 12) {
            error = "Master password must be at least 12 characters.";
            rerender();
            return;
          }
          if (passwordInput.value !== confirmInput.value) {
            error = "Passwords do not match.";
            rerender();
            return;
          }
          email = emailInput.value;
          const passwordBytes = new TextEncoder().encode(passwordInput.value);
          passwordInput.value = "";
          confirmInput.value = "";
          try {
            ctx.announcer.status("Creating your account...");
            const accountId = getOrCreateAccountId();
            await ctx.auth.register(accountId, passwordBytes.slice());
            const vaultId = crypto.randomUUID();
            const setup = await ctx.crypto.createAccountSetup({
              password: passwordBytes,
              reportedPhysicalMemoryKiB: REPORTED_PHYSICAL_MEMORY_KIB,
              accountId,
              vaultId,
              itemId: "vault-key",
            });
            bundle = {
              accountId: setup.accountId,
              vaultId: setup.vaultId,
              itemId: setup.itemId,
              kdfParametersCbor: setup.kdfParametersCbor,
              wrappedAccountKey: setup.wrappedAccountKey,
              wrappedVaultKey: setup.wrappedVaultKey,
              wrappedItemKey: setup.wrappedItemKey,
              wrappedRecoveryKey: setup.wrappedRecoveryKey,
            };
            recoveryHex = toProvisionalHex(setup.recoveryKey);
            setup.recoveryKey.fill(0);
            password = passwordBytes;
            // The setup call opened a live session under the password
            // wrapper (mirroring create_item_session_for_setup); this
            // onboarding flow does its own explicit confirm-time open via
            // the recovery key next, so close this one now rather than
            // leaving two sessions live.
            await ctx.crypto.lock();
            error = "";
            step = "reveal";
          } catch (e) {
            error = e instanceof Error ? e.message : String(e);
            ctx.announcer.error(error);
          }
          rerender();
        },
      },
      h("h1", {}, "Create your vault"),
      h("p", {}, "Your master password never leaves this device. We cannot recover it for you."),
      error ? h("p", { class: "error", role: "alert" }, error) : null,
      h("label", { for: "email" }, "Email (local label only — not sent to the server)"),
      h("input", { id: "email", name: "email", type: "email", required: true, autocomplete: "email" }),
      h("label", { for: "password" }, "Master password"),
      h("input", { id: "password", name: "password", type: "password", required: true, autocomplete: "new-password", "aria-describedby": "pw-help" }),
      h("p", { id: "pw-help", class: "hint" }, "At least 12 characters. This is the only password you'll ever need to remember."),
      h("label", { for: "passwordConfirm" }, "Confirm master password"),
      h("input", { id: "passwordConfirm", name: "passwordConfirm", type: "password", required: true, autocomplete: "new-password" }),
      h("button", { type: "submit" }, "Create vault"),
    );
  }

  function revealView(): HTMLElement {
    return h(
      "div",
      { class: "panel" },
      h("h1", {}, "Save your recovery key"),
      h("p", { class: "warning" }, "Support cannot recover a lost master password without this recovery key. If you lose both, your data is permanently unrecoverable."),
      h("p", { class: "hint" }, PROVISIONAL_LABEL),
      h("pre", { class: "recovery-key", "aria-label": "Recovery key" }, recoveryHex),
      h("button", {
        type: "button",
        onclick: () => {
          step = "confirm";
          error = "";
          rerender();
        },
      }, "I've saved it — continue"),
    );
  }

  function confirmView(): HTMLElement {
    return h(
      "form",
      {
        class: "panel",
        onsubmit: async (e: Event) => {
          e.preventDefault();
          const form = e.currentTarget as HTMLFormElement;
          const input = form.elements.namedItem("recoveryConfirm") as HTMLInputElement;
          if (!bundle || !password) return;
          try {
            const entered = fromProvisionalHex(input.value);
            // Real confirmation, not a checkbox: actually open the
            // recovery-wrapped account key with what the user typed, via
            // the Worker (ADR-0008's unlock_item_session_with_recovery).
            await ctx.vault.unlockWithRecovery(
              { ...bundle, wrappedAccountKey: bundle.wrappedRecoveryKey },
              entered,
            );
            entered.fill(0);
            saveAccountBundle(bundle);
            setDisplayEmail(email);
            await ctx.vault.lock(); // drop the recovery-opened session
            await ctx.vault.unlockWithPassword(bundle, password);
            password.fill(0);
            ctx.announcer.status("Vault created and unlocked.");
            ctx.navigate({ name: "vault" });
          } catch {
            error = "That doesn't match the recovery key shown. Please re-check and try again.";
            ctx.announcer.error(error);
            rerender();
          }
        },
      },
      h("h1", {}, "Confirm your recovery key"),
      h("p", {}, "Re-enter the recovery key exactly as shown on the previous screen."),
      error ? h("p", { class: "error", role: "alert" }, error) : null,
      h("label", { for: "recoveryConfirm" }, "Recovery key"),
      h("input", { id: "recoveryConfirm", name: "recoveryConfirm", type: "text", required: true, autocomplete: "off", spellcheck: false }),
      h("button", { type: "submit" }, "Confirm and open my vault"),
      h("button", {
        type: "button",
        onclick: () => { step = "reveal"; rerender(); },
      }, "Show it again"),
    );
  }

  function rerender(): void {
    mount(root, view());
  }

  rerender();
}
