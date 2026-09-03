import type { NormalizedItem, NormalizeIssue, NormalizeResult } from "@zkpm/domain";
import { assertInputSize, boundField, MAX_ITEMS } from "./limits.ts";
import { parseCsv } from "./csv-parser.ts";

const HEADER_ALIASES: Record<string, keyof MappedRow> = {
  title: "title",
  name: "title",
  itemname: "title",
  username: "username",
  user: "username",
  login: "username",
  email: "username",
  password: "password",
  pass: "password",
  pwd: "password",
  url: "url",
  website: "url",
  uri: "url",
  site: "url",
  notes: "notes",
  note: "notes",
  comments: "notes",
  totp: "totp",
  otp: "totp",
  "otp secret": "totp",
  folder: "folder",
  group: "folder",
};

interface MappedRow {
  title?: string;
  username?: string;
  password?: string;
  url?: string;
  notes?: string;
  totp?: string;
  folder?: string;
}

function normalizeHeader(h: string): string {
  return h.trim().toLowerCase().replace(/[_-]+/g, " ").replace(/\s+/g, " ");
}

/** Normalizes a generic CSV export (title/username/password/url/notes/totp
 * columns, in any order, matched case-insensitively against common
 * aliases) into NormalizedItems. Rows this parser cannot map to at least a
 * title are reported as issues, not silently dropped. */
export function normalizeCsv(input: string): NormalizeResult {
  assertInputSize(input);
  const rows = parseCsv(input);
  const issues: NormalizeIssue[] = [];
  const items: NormalizedItem[] = [];

  if (rows.length === 0) return { items, issues };

  const header = rows[0].map(normalizeHeader);
  const columnRoles: (keyof MappedRow | undefined)[] = header.map((h) => HEADER_ALIASES[h]);
  if (!columnRoles.includes("title") && !columnRoles.includes("username")) {
    // No recognizable header at all: nothing to safely map. Report once
    // and return no items rather than guessing positionally (guessing
    // wrong could silently mislabel a password column as a username).
    issues.push({ index: 0, reason: "no recognizable header row (title/username/password/url column)" });
    return { items, issues };
  }

  for (let r = 1; r < rows.length; r += 1) {
    if (items.length >= MAX_ITEMS) {
      issues.push({ index: r, reason: `dropped: exceeds max item limit of ${MAX_ITEMS}` });
      continue;
    }
    const row = rows[r];
    const mapped: MappedRow = {};
    for (let c = 0; c < header.length; c += 1) {
      const role = columnRoles[c];
      if (!role) continue;
      const raw = row[c];
      if (raw === undefined) continue;
      const { value, truncated } = boundField(raw);
      if (value !== undefined) mapped[role] = value;
      if (truncated) issues.push({ index: r, reason: `field '${role}' truncated to size limit` });
    }
    const title = mapped.title ?? mapped.username ?? mapped.url;
    if (!title) {
      issues.push({ index: r, reason: "row has no title, username, or url; skipped" });
      continue;
    }
    items.push({
      title,
      username: mapped.username,
      password: mapped.password,
      url: mapped.url,
      notes: mapped.notes,
      totp: mapped.totp ? { secret: mapped.totp } : undefined,
      folder: mapped.folder,
      source: "csv",
    });
  }
  return { items, issues };
}
