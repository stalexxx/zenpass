import { h, mount, clear } from "../lib/dom.ts";
import type { AppContext } from "../lib/context.ts";
import type { VaultItemData, ItemType } from "../vault/item-codec.ts";
import { generatePassword, DEFAULT_GENERATOR_OPTIONS, type GeneratorOptions } from "../crypto/generator.ts";
import { computeTotp, secondsRemaining } from "../crypto/totp.ts";
import { itemMatchesPageOrigin } from "@zkpm/domain";

export function renderVault(root: HTMLElement, ctx: AppContext, initialItemId?: string): void {
  let query = "";
  let selected: string | null = initialItemId ?? null;
  let mode: "view" | "edit" | "new" | "delete" = initialItemId ? "view" : "new";
  let totpTimer: ReturnType<typeof setInterval> | null = null;
  let deleteConfirmText = "";

  function stopTotpTimer(): void {
    if (totpTimer !== null) { clearInterval(totpTimer); totpTimer = null; }
  }

  function render(): void {
    stopTotpTimer();
    const list = ctx.vault.search(query);
    const layout = h(
      "div",
      { class: "vault-layout" },
      h(
        "nav",
        { class: "vault-sidebar", "aria-label": "Vault items" },
        h("div", { class: "toolbar" },
          h("button", { type: "button", onclick: () => { mode = "new"; selected = null; render(); } }, "+ New item"),
          h("button", { type: "button", onclick: async () => { await ctx.vault.lock(); ctx.navigate({ name: "unlock" }); } }, "Lock"),
        ),
        h("label", { for: "search", class: "sr-only" }, "Search items"),
        h("input", {
          id: "search", type: "search", placeholder: "Search...", value: query,
          oninput: (e: Event) => { query = (e.target as HTMLInputElement).value; render(); },
        }),
        h("ul", { class: "item-list" }, ...list.map((entry) =>
          h("li", {},
            h("button", {
              type: "button",
              class: entry.itemId === selected ? "item-row selected" : "item-row",
              "aria-current": entry.itemId === selected,
              onclick: () => { selected = entry.itemId; mode = "view"; render(); },
            }, h("span", { class: "item-title" }, entry.title), h("span", { class: "item-type" }, entry.type)),
          ),
        )),
        list.length === 0 ? h("p", { class: "hint" }, "No items match.") : null,
        h("div", { class: "toolbar" },
          h("button", { type: "button", onclick: () => ctx.navigate({ name: "import" }) }, "Import"),
          h("button", { type: "button", onclick: () => ctx.navigate({ name: "export" }) }, "Export"),
          h("button", { type: "button", onclick: () => ctx.navigate({ name: "devices" }) }, "Devices"),
        ),
      ),
      h("section", { class: "vault-detail", "aria-live": "off" }, detailView()),
    );
    mount(root, layout);
  }

  function detailView(): HTMLElement {
    if (mode === "new") return itemForm(null);
    if (!selected) return h("p", { class: "hint" }, "Select an item, or create a new one.");
    const data = ctx.vault.getItemData(selected);
    if (!data) return h("p", { class: "hint" }, "Item not found.");
    if (mode === "edit") return itemForm(selected);
    if (mode === "delete") return deleteConfirmView(selected, data);
    return itemView(selected, data);
  }

  // Delete confirmation is its own mode with text confirmation
  // (docs/ux/flows.md: "text confirmation, not color-only cues").
  function deleteConfirmView(itemId: string, data: VaultItemData): HTMLElement {
    return h(
      "form",
      {
        class: "panel",
        onsubmit: async (e: Event) => {
          e.preventDefault();
          if (deleteConfirmText !== data.title) return;
          const mutationId = await ctx.vault.deleteItem(itemId);
          selected = null;
          mode = "view";
          deleteConfirmText = "";
          ctx.announcer.status("Item deleted.");
          render();
          offerUndo(mutationId, itemId, data.title);
        },
      },
      h("h1", {}, "Delete this item?"),
      h("p", { class: "warning" }, `This cannot be undone once synced. Type the item's title ("${data.title}") to confirm.`),
      h("label", { for: "deleteConfirm" }, "Item title"),
      h("input", {
        id: "deleteConfirm", required: true,
        oninput: (e: Event) => { deleteConfirmText = (e.target as HTMLInputElement).value; },
      }),
      h("div", { class: "toolbar" },
        h("button", { type: "submit", class: "danger" }, "Delete permanently"),
        h("button", { type: "button", onclick: () => { mode = "view"; deleteConfirmText = ""; render(); } }, "Cancel"),
      ),
    );
  }

  function itemView(itemId: string, data: VaultItemData): HTMLElement {
    const originNote = data.url && typeof location !== "undefined"
      ? h("p", { class: "hint" }, itemMatchesPageOrigin([data.url], location.origin)
          ? "This page's origin matches this item."
          : "This item's URL does not match the current page origin (autofill would be refused here).")
      : null;
    const totpBlock = data.type === "totp-login" && data.totpSecret ? totpDisplay(data.totpSecret) : null;
    return h(
      "article",
      {},
      h("div", { class: "toolbar" },
        h("h1", {}, data.title),
        h("button", { type: "button", onclick: () => { mode = "edit"; render(); } }, "Edit"),
      ),
      data.username ? field("Username", data.username, true) : null,
      data.password ? field("Password", data.password, true, true) : null,
      totpBlock,
      data.url ? field("URL", data.url) : null,
      originNote,
      data.notes ? h("div", {}, h("h2", {}, "Notes"), h("p", { class: "notes" }, data.notes)) : null,
      h("div", { class: "toolbar" },
        h("button", { type: "button", class: "danger", onclick: () => { mode = "delete"; render(); } }, "Delete"),
      ),
    );
  }

  function field(label: string, value: string, copyable = false, secret = false): HTMLElement {
    return h(
      "div",
      { class: "field" },
      h("span", { class: "field-label" }, label),
      h("span", { class: secret ? "field-value secret" : "field-value" }, secret ? "••••••••" : value),
      copyable ? h("button", {
        type: "button",
        onclick: async () => {
          await ctx.vault.copyToClipboard(value);
          ctx.announcer.status(`${label} copied. It will be cleared from the clipboard automatically.`);
        },
      }, `Copy ${label.toLowerCase()}`) : null,
    );
  }

  function totpDisplay(secret: string): HTMLElement {
    const codeEl = h("span", { class: "totp-code", "aria-live": "polite" }, "------");
    const secondsEl = h("span", { class: "totp-seconds" }, "");
    const wrap = h("div", { class: "field" }, h("span", { class: "field-label" }, "TOTP code"), codeEl, secondsEl,
      h("button", { type: "button", onclick: async () => {
        await ctx.vault.copyToClipboard(codeEl.textContent ?? "");
        ctx.announcer.status("TOTP code copied. It will be cleared from the clipboard automatically.");
      } }, "Copy code"));
    const update = async () => {
      try {
        codeEl.textContent = await computeTotp(secret);
        secondsEl.textContent = ` (${secondsRemaining()}s)`;
      } catch {
        codeEl.textContent = "invalid secret";
      }
    };
    update();
    totpTimer = setInterval(update, 1000);
    return wrap;
  }

  function itemForm(itemId: string | null): HTMLElement {
    const existing = itemId ? ctx.vault.getItemData(itemId) : null;
    const data: VaultItemData = existing ?? { type: "login", title: "" };
    let error = "";
    let genOptions: GeneratorOptions = { ...DEFAULT_GENERATOR_OPTIONS };

    const typeSelect = h("select", { id: "type", name: "type" },
      h("option", { value: "login", selected: data.type === "login" }, "Login"),
      h("option", { value: "note", selected: data.type === "note" }, "Secure note"),
      h("option", { value: "totp-login", selected: data.type === "totp-login" }, "TOTP login"),
    ) as HTMLSelectElement;

    const passwordInput = h("input", { id: "password", name: "password", type: "text", value: data.password ?? "" }) as HTMLInputElement;

    const form = h(
      "form",
      {
        class: "item-form",
        onsubmit: async (e: Event) => {
          e.preventDefault();
          const f = e.currentTarget as HTMLFormElement;
          const get = (name: string) => (f.elements.namedItem(name) as HTMLInputElement | HTMLTextAreaElement | null)?.value ?? "";
          const next: VaultItemData = {
            type: (get("type") as ItemType) || "login",
            title: get("title"),
            username: get("username") || undefined,
            password: get("password") || undefined,
            url: get("url") || undefined,
            notes: get("notes") || undefined,
            totpSecret: get("totpSecret") || undefined,
          };
          try {
            const id = await ctx.vault.saveItem(next, itemId ?? undefined);
            selected = id;
            mode = "view";
            ctx.announcer.status("Item saved.");
            render();
          } catch (err) {
            error = err instanceof Error ? err.message : String(err);
            ctx.announcer.error(error);
            renderForm();
          }
        },
      },
    );

    function renderForm(): void {
      clear(form);
      form.append(
        h("h1", {}, itemId ? "Edit item" : "New item"),
        error ? h("p", { class: "error", role: "alert" }, error) : null,
        h("label", { for: "type" }, "Type"),
        typeSelect,
        h("label", { for: "title" }, "Title"),
        h("input", { id: "title", name: "title", required: true, value: data.title }),
        h("label", { for: "username" }, "Username"),
        h("input", { id: "username", name: "username", value: data.username ?? "" }),
        h("label", { for: "password" }, "Password"),
        h("div", { class: "password-row" },
          passwordInput,
          h("button", { type: "button", onclick: () => { passwordInput.value = generatePassword(genOptions); } }, "Generate"),
        ),
        generatorPanel(genOptions, (opts) => { genOptions = opts; }),
        h("label", { for: "url" }, "URL"),
        h("input", { id: "url", name: "url", type: "url", value: data.url ?? "" }),
        h("label", { for: "totpSecret" }, "TOTP secret (base32, only for TOTP login)"),
        h("input", { id: "totpSecret", name: "totpSecret", value: data.totpSecret ?? "" }),
        h("label", { for: "notes" }, "Notes"),
        h("textarea", { id: "notes", name: "notes" }, data.notes ?? ""),
        h("div", { class: "toolbar" },
          h("button", { type: "submit" }, "Save"),
          h("button", { type: "button", onclick: () => { mode = itemId ? "view" : "new"; if (!itemId) selected = null; render(); } }, "Cancel"),
        ),
      );
    }
    renderForm();
    return form;
  }

  function generatorPanel(opts: GeneratorOptions, onChange: (opts: GeneratorOptions) => void): HTMLElement {
    let current = { ...opts };
    const lengthInput = h("input", { type: "number", min: 4, max: 128, value: current.length, "aria-label": "Password length" }) as HTMLInputElement;
    const classes: { key: keyof GeneratorOptions; label: string }[] = [
      { key: "upper", label: "Uppercase" }, { key: "lower", label: "Lowercase" },
      { key: "digits", label: "Digits" }, { key: "symbols", label: "Symbols" },
    ];
    lengthInput.addEventListener("change", () => { current = { ...current, length: Number(lengthInput.value) || 12 }; onChange(current); });
    return h("fieldset", { class: "generator" },
      h("legend", {}, "Password generator options"),
      h("label", {}, "Length ", lengthInput),
      ...classes.map(({ key, label }) => {
        const cb = h("input", { type: "checkbox", checked: current[key] as boolean }) as HTMLInputElement;
        cb.addEventListener("change", () => { current = { ...current, [key]: cb.checked }; onChange(current); });
        return h("label", {}, cb, ` ${label}`);
      }),
    );
  }

  function offerUndo(mutationId: string, itemId: string, title: string): void {
    ctx.announcer.status(`"${title}" deleted. Undo available while still unsynced.`);
    const banner = h("div", { class: "undo-banner", role: "status" },
      `Deleted "${title}". `,
      h("button", {
        type: "button",
        onclick: async () => {
          const undone = await ctx.vault.undoDeleteIfLocal(mutationId, itemId);
          banner.remove();
          if (undone) { ctx.announcer.status("Delete undone."); render(); }
          else ctx.announcer.error("Too late to undo — it already synced.");
        },
      }, "Undo"),
    );
    root.prepend(banner);
    setTimeout(() => banner.remove(), 15_000);
  }

  render();
}
