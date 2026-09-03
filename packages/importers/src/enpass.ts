import type { NormalizedItem, NormalizeIssue, NormalizeResult } from "@zkpm/domain";
import { assertInputSize, boundField, MAX_ITEMS } from "./limits.ts";

// Enpass's JSON export shape (Enpass -> Settings -> Export -> "As JSON"),
// documented at https://www.enpass.io/docs/export-items-from-enpass/ :
//   { folders: [...], items: [{
//       title, subtitle, note, category,
//       fields: [{ label, value, type, ... }]
//   }] }
// Field `type` values relevant here: "username", "password", "url" (and
// Enpass's own "totp"). A field's `type` is what drives mapping, not its
// (localizable, user-editable) `label`.

interface EnpassField {
  label?: unknown;
  value?: unknown;
  type?: unknown;
}

interface EnpassItem {
  title?: unknown;
  note?: unknown;
  fields?: unknown;
}

interface EnpassExport {
  items?: unknown;
}

function str(value: unknown): string | undefined {
  const { value: v } = boundField(value);
  return v;
}

export function normalizeEnpassJson(input: string): NormalizeResult {
  assertInputSize(input);
  const issues: NormalizeIssue[] = [];
  const items: NormalizedItem[] = [];

  let doc: EnpassExport;
  try {
    doc = JSON.parse(input) as EnpassExport;
  } catch (e) {
    issues.push({ index: 0, reason: `invalid JSON: ${e instanceof Error ? e.message : String(e)}` });
    return { items, issues };
  }
  if (typeof doc !== "object" || doc === null || !Array.isArray(doc.items)) {
    issues.push({ index: 0, reason: "expected an Enpass export object with an 'items' array" });
    return { items, issues };
  }

  const rawItems = doc.items as unknown[];
  for (let idx = 0; idx < rawItems.length; idx += 1) {
    if (items.length >= MAX_ITEMS) {
      issues.push({ index: idx, reason: `dropped: exceeds max item limit of ${MAX_ITEMS}` });
      continue;
    }
    const raw = rawItems[idx];
    if (typeof raw !== "object" || raw === null) {
      issues.push({ index: idx, reason: "item is not an object; skipped" });
      continue;
    }
    const it = raw as EnpassItem;
    const title = str(it.title);
    if (!title) {
      issues.push({ index: idx, reason: "item has no title; skipped" });
      continue;
    }
    let username: string | undefined;
    let url: string | undefined;
    const otherUrls: string[] = [];
    let password: string | undefined;
    let totpSecret: string | undefined;
    if (Array.isArray(it.fields)) {
      for (const f of it.fields as EnpassField[]) {
        if (!f || typeof f !== "object") continue;
        const type = typeof f.type === "string" ? f.type.toLowerCase() : undefined;
        const value = str(f.value);
        if (!type || value === undefined) continue;
        if (type === "username" && username === undefined) username = value;
        else if (type === "password" && password === undefined) password = value;
        else if (type === "url") {
          if (url === undefined) url = value;
          else otherUrls.push(value);
        } else if (type === "totp" && totpSecret === undefined) totpSecret = value;
      }
    }
    items.push({
      title,
      username,
      password,
      url,
      otherUrls: otherUrls.length > 0 ? otherUrls : undefined,
      notes: str(it.note),
      totp: totpSecret ? { secret: totpSecret } : undefined,
      source: "enpass",
    });
  }
  return { items, issues };
}
