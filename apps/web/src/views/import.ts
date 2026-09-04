import { h, mount, clear } from "../lib/dom.ts";
import type { AppContext } from "../lib/context.ts";
import { normalizeCsv, normalizeBitwardenJson, normalizeOnePasswordCsv, normalizeEnpassJson, ImportSizeError } from "@zkpm/importers";
import type { NormalizedItem, NormalizeResult } from "@zkpm/domain";

type Format = "csv" | "bitwarden" | "1password" | "enpass";

export function renderImport(root: HTMLElement, ctx: AppContext): void {
  let format: Format = "csv";
  let result: NormalizeResult | null = null;
  let fileError = "";
  let imported = 0;

  function normalize(text: string): NormalizeResult {
    switch (format) {
      case "csv": return normalizeCsv(text);
      case "bitwarden": return normalizeBitwardenJson(text);
      case "1password": return normalizeOnePasswordCsv(text);
      case "enpass": return normalizeEnpassJson(text);
    }
  }

  function render(): void {
    const panel = h(
      "div",
      { class: "panel" },
      h("h1", {}, "Import"),
      h("button", { type: "button", onclick: () => ctx.navigate({ name: "vault" }) }, "Back to vault"),
      h("label", { for: "format" }, "Source format"),
      h("select", {
        id: "format", value: format,
        onchange: (e: Event) => { format = (e.target as HTMLSelectElement).value as Format; result = null; render(); },
      },
        h("option", { value: "csv" }, "Generic CSV"),
        h("option", { value: "bitwarden" }, "Bitwarden (JSON)"),
        h("option", { value: "1password" }, "1Password (CSV)"),
        h("option", { value: "enpass" }, "Enpass (JSON)"),
      ),
      h("label", { for: "file" }, "Export file"),
      h("input", {
        id: "file", type: "file", accept: ".csv,.json,.txt",
        onchange: async (e: Event) => {
          const file = (e.target as HTMLInputElement).files?.[0];
          if (!file) return;
          try {
            const text = await file.text();
            result = normalize(text);
            fileError = "";
          } catch (err) {
            result = null;
            fileError = err instanceof ImportSizeError ? err.message : "Could not parse this file.";
          }
          render();
        },
      }),
      fileError ? h("p", { class: "error", role: "alert" }, fileError) : null,
      result ? previewSection(result) : null,
    );
    mount(root, panel);
  }

  function previewSection(res: NormalizeResult): HTMLElement {
    return h(
      "div",
      {},
      h("h2", {}, `Preview: ${res.items.length} item(s) found`),
      res.issues.length > 0
        ? h("details", {},
            h("summary", {}, `${res.issues.length} warning(s) — unsupported or truncated fields`),
            h("ul", {}, ...res.issues.map((i) => h("li", {}, `Row ${i.index}: ${i.reason}`))),
          )
        : null,
      h("table", { class: "preview-table" },
        h("thead", {}, h("tr", {}, h("th", {}, "Title"), h("th", {}, "Username"), h("th", {}, "URL"), h("th", {}, "Has password"), h("th", {}, "Has TOTP"))),
        h("tbody", {}, ...res.items.slice(0, 50).map((item) =>
          h("tr", {}, h("td", {}, item.title), h("td", {}, item.username ?? ""), h("td", {}, item.url ?? ""),
            h("td", {}, item.password ? "yes" : "no"), h("td", {}, item.totp ? "yes" : "no")),
        )),
      ),
      res.items.length > 50 ? h("p", { class: "hint" }, `...and ${res.items.length - 50} more.`) : null,
      h("button", {
        type: "button",
        onclick: async () => {
          imported = 0;
          let failed = 0;
          for (const item of res.items) {
            try {
              await ctx.vault.saveItem(toVaultData(item));
              imported += 1;
            } catch {
              failed += 1;
            }
          }
          ctx.announcer.status(
            failed > 0 ? `Imported ${imported} item(s); ${failed} could not be saved.` : `Imported ${imported} item(s).`,
          );
          ctx.navigate({ name: "vault" });
        },
      }, `Import ${res.items.length} item(s)`),
    );
  }

  function toVaultData(item: NormalizedItem) {
    const type: "login" | "totp-login" | "note" = item.totp ? "totp-login" : item.username || item.password ? "login" : "note";
    return {
      type,
      title: item.title,
      username: item.username,
      password: item.password,
      url: item.url,
      notes: item.notes,
      totpSecret: item.totp?.secret,
    };
  }

  render();
}
