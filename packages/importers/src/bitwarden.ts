import type { NormalizedItem, NormalizeIssue, NormalizeResult } from "@zkpm/domain";
import { assertInputSize, boundField, MAX_ITEMS } from "./limits.ts";

// Bitwarden's unencrypted JSON export shape (documented at
// https://bitwarden.com/help/condition-bitwarden-import/ and produced by
// "Export vault" -> ".json"):
//   { folders: [{ id, name }], items: [{
//       id, folderId, type, name, notes,
//       login?: { username, password, totp, uris?: [{ uri }] },
//       fields?: [{ name, value, type }]
//   }] }
// type: 1 = login, 2 = secure note, 3 = card, 4 = identity. Only login
// items carry credential data; other types are normalized as
// title/notes-only records so nothing is silently dropped from the
// export, but no fabricated username/password is invented for them.

interface BitwardenLogin {
  username?: unknown;
  password?: unknown;
  totp?: unknown;
  uris?: unknown;
}

interface BitwardenItem {
  name?: unknown;
  notes?: unknown;
  folderId?: unknown;
  login?: BitwardenLogin;
}

interface BitwardenFolder {
  id?: unknown;
  name?: unknown;
}

interface BitwardenExport {
  folders?: unknown;
  items?: unknown;
}

function str(value: unknown): string | undefined {
  const { value: v } = boundField(value);
  return v;
}

export function normalizeBitwardenJson(input: string): NormalizeResult {
  assertInputSize(input);
  const issues: NormalizeIssue[] = [];
  const items: NormalizedItem[] = [];

  let doc: BitwardenExport;
  try {
    doc = JSON.parse(input) as BitwardenExport;
  } catch (e) {
    issues.push({ index: 0, reason: `invalid JSON: ${e instanceof Error ? e.message : String(e)}` });
    return { items, issues };
  }
  if (typeof doc !== "object" || doc === null || !Array.isArray(doc.items)) {
    issues.push({ index: 0, reason: "expected a Bitwarden export object with an 'items' array" });
    return { items, issues };
  }

  const folderNameById = new Map<string, string>();
  if (Array.isArray(doc.folders)) {
    for (const f of doc.folders as BitwardenFolder[]) {
      if (f && typeof f === "object" && typeof f.id === "string" && typeof f.name === "string") {
        folderNameById.set(f.id, f.name);
      }
    }
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
    const it = raw as BitwardenItem;
    const title = str(it.name);
    if (!title) {
      issues.push({ index: idx, reason: "item has no name; skipped" });
      continue;
    }
    const login = it.login && typeof it.login === "object" ? it.login : undefined;
    let url: string | undefined;
    let otherUrls: string[] | undefined;
    if (login && Array.isArray(login.uris)) {
      const uris = (login.uris as Array<{ uri?: unknown }>)
        .map((u) => (u && typeof u === "object" ? str(u.uri) : undefined))
        .filter((u): u is string => typeof u === "string");
      if (uris.length > 0) {
        [url, ...otherUrls] = uris;
        if (otherUrls.length === 0) otherUrls = undefined;
      }
    }
    const folderId = typeof it.folderId === "string" ? it.folderId : undefined;
    items.push({
      title,
      username: login ? str(login.username) : undefined,
      password: login ? str(login.password) : undefined,
      url,
      otherUrls,
      notes: str(it.notes),
      totp: login && str(login.totp) ? { secret: str(login.totp) as string } : undefined,
      folder: folderId ? folderNameById.get(folderId) : undefined,
      source: "bitwarden",
    });
  }
  return { items, issues };
}
