import { h, mount } from "../lib/dom.ts";
import type { AppContext } from "../lib/context.ts";
import type { Conflict } from "@zkpm/sdk";
import type { DecryptedConflict } from "../vault/vault-session.ts";

/** Renders a field-level comparison of one already-decrypted conflict.
 * SyncEngine never decrypts; VaultSession.decryptConflict does that using
 * the still-open session, and this view just displays the result. */
export function renderConflicts(root: HTMLElement, ctx: AppContext, conflicts: Conflict[]): void {
  let index = 0;
  let decrypted: DecryptedConflict | null = null;
  let error = "";

  async function loadCurrent(): Promise<void> {
    if (index >= conflicts.length) { decrypted = null; return; }
    try {
      decrypted = await ctx.vault.decryptConflict(conflicts[index]);
      error = "";
    } catch {
      error = "Could not decrypt this conflict.";
      decrypted = null;
    }
  }

  function fieldRow(label: string, a?: string, b?: string): HTMLElement {
    const changed = a !== b;
    return h("tr", { class: changed ? "diff-changed" : undefined },
      h("th", {}, label),
      h("td", {}, a ?? h("em", {}, "(empty)")),
      h("td", {}, b ?? h("em", {}, "(empty)")),
    );
  }

  async function render(): Promise<void> {
    if (conflicts.length === 0) {
      mount(root, h("div", { class: "panel" }, h("h1", {}, "Conflicts"), h("p", {}, "No conflicts."), backButton()));
      return;
    }
    await loadCurrent();
    if (!decrypted) {
      mount(root, h("div", { class: "panel" }, h("h1", {}, "Conflicts"), error ? h("p", { class: "error", role: "alert" }, error) : null, backButton()));
      return;
    }
    const { current, attempted } = decrypted;
    mount(
      root,
      h(
        "div",
        { class: "panel" },
        h("h1", {}, `Conflict ${index + 1} of ${conflicts.length}`),
        h("p", { class: "hint" }, `Server version updated ${current.updatedAt} (revision ${current.revision}). Your change was based on revision ${attempted.baseRevision}.`),
        h("table", { class: "diff-table" },
          h("thead", {}, h("tr", {}, h("th", {}, "Field"), h("th", {}, "Current (server)"), h("th", {}, "Your change"))),
          h("tbody", {},
            fieldRow("Title", current.data.title, attempted.data.title),
            fieldRow("Username", current.data.username, attempted.data.username),
            fieldRow("Password", current.data.password ? "••••••••" : undefined, attempted.data.password ? "••••••••" : undefined),
            fieldRow("URL", current.data.url, attempted.data.url),
            fieldRow("Notes", current.data.notes, attempted.data.notes),
          ),
        ),
        h("div", { class: "toolbar" },
          h("button", { type: "button", onclick: async () => { await ctx.vault.resolveConflict(conflicts[index], current.data); next(); } }, "Keep server version"),
          h("button", { type: "button", onclick: async () => { await ctx.vault.resolveConflict(conflicts[index], attempted.data); next(); } }, "Keep my version"),
        ),
        backButton(),
      ),
    );
  }

  function next(): void {
    index += 1;
    render();
  }

  function backButton(): HTMLElement {
    return h("button", { type: "button", onclick: () => ctx.navigate({ name: "vault" }) }, "Back to vault");
  }

  render();
}
