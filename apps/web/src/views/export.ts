import { h, mount } from "../lib/dom.ts";
import type { AppContext } from "../lib/context.ts";
import { getOrCreateAccountId } from "../crypto/account-id.ts";

/** Builds the encrypted export payload: raw ItemRecords (still
 * ciphertext), never decrypted. This is the *default* and always-safe
 * export path — no gate needed, since nothing plaintext ever leaves
 * memory. */
async function buildEncryptedExport(ctx: AppContext): Promise<string> {
  const bundle = ctx.vault.accountBundle;
  if (!bundle) throw new Error("vault is locked");
  const items = await ctx.repo.listItems(bundle.vaultId);
  return JSON.stringify({ format: "zkpm-encrypted-export/v1", vaultId: bundle.vaultId, items }, null, 2);
}

/** Builds the plaintext export payload by decrypting every item in
 * memory, right before this function returns the string — never persisted
 * partway, never logged. Callers must have already gated this behind
 * re-authentication and an explicit second confirmation (see the export
 * view below); this function itself does not enforce that, by design (the
 * view owns the UX-level gate, and unit tests exercise this function and
 * the gate independently). */
function buildPlaintextExport(ctx: AppContext): string {
  const rows = ctx.vault.list()
    .map((entry) => ctx.vault.getItemData(entry.itemId))
    .filter((data): data is NonNullable<typeof data> => data !== null);
  return JSON.stringify({ format: "zkpm-plaintext-export/v1", items: rows }, null, 2);
}

function download(filename: string, content: string): void {
  const blob = new Blob([content], { type: "application/json" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  a.click();
  URL.revokeObjectURL(url);
}

export function renderExport(root: HTMLElement, ctx: AppContext): void {
  let stage: "menu" | "confirm-plaintext" | "reauth" = "menu";
  let reauthError = "";

  function render(): void {
    mount(root, view());
  }

  function view(): HTMLElement {
    if (stage === "menu") return menu();
    if (stage === "confirm-plaintext") return confirmPlaintext();
    return reauth();
  }

  function menu(): HTMLElement {
    return h(
      "div",
      { class: "panel" },
      h("h1", {}, "Export"),
      h("button", { type: "button", onclick: () => ctx.navigate({ name: "vault" }) }, "Back to vault"),
      h("p", {}, "Encrypted export is safe to store anywhere — it contains only ciphertext."),
      h("button", {
        type: "button",
        onclick: async () => {
          const json = await buildEncryptedExport(ctx);
          download("vault-export-encrypted.json", json);
          ctx.announcer.status("Encrypted export downloaded.");
        },
      }, "Download encrypted export"),
      h("hr"),
      h("p", { class: "warning" }, "Plaintext export writes every password and secret to a file in the clear. Anyone with that file can read your vault."),
      h("button", { type: "button", class: "danger", onclick: () => { stage = "confirm-plaintext"; render(); } }, "Export as plaintext..."),
    );
  }

  function confirmPlaintext(): HTMLElement {
    let typed = "";
    return h(
      "form",
      {
        class: "panel",
        onsubmit: (e: Event) => {
          e.preventDefault();
          if (typed !== "EXPORT PLAINTEXT") return;
          stage = "reauth";
          render();
        },
      },
      h("h1", {}, "Confirm plaintext export"),
      h("p", { class: "warning" }, 'This writes unencrypted passwords, notes, and TOTP secrets to a file on disk. Type "EXPORT PLAINTEXT" to confirm you understand the risk.'),
      h("input", {
        required: true, "aria-label": "Type EXPORT PLAINTEXT to confirm",
        oninput: (e: Event) => { typed = (e.target as HTMLInputElement).value; },
      }),
      h("div", { class: "toolbar" },
        h("button", { type: "submit", class: "danger" }, "Continue"),
        h("button", { type: "button", onclick: () => { stage = "menu"; render(); } }, "Cancel"),
      ),
    );
  }

  function reauth(): HTMLElement {
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
            // Re-authentication per docs/ux/flows.md: plaintext export
            // requires re-entering the master password against the live
            // OPAQUE login, not just re-using the already-unlocked
            // session.
            await ctx.auth.login(getOrCreateAccountId(), passwordBytes);
            const json = buildPlaintextExport(ctx);
            download("vault-export-PLAINTEXT.json", json);
            ctx.announcer.status("Plaintext export downloaded.");
            stage = "menu";
            render();
          } catch {
            reauthError = "Re-authentication failed.";
            ctx.announcer.error(reauthError);
            render();
          } finally {
            passwordBytes.fill(0);
          }
        },
      },
      h("h1", {}, "Re-enter your master password"),
      reauthError ? h("p", { class: "error", role: "alert" }, reauthError) : null,
      h("label", { for: "password" }, "Master password"),
      h("input", { id: "password", name: "password", type: "password", required: true, autocomplete: "current-password" }),
      h("div", { class: "toolbar" },
        h("button", { type: "submit", class: "danger" }, "Export plaintext now"),
        h("button", { type: "button", onclick: () => { stage = "menu"; render(); } }, "Cancel"),
      ),
    );
  }

  render();
}

export { buildEncryptedExport, buildPlaintextExport };
