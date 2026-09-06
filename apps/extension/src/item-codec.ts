// Plaintext-shaped vault item content and its wire encoding as the JSON
// payload sealed inside an ItemRecord's ciphertext. Mirrors
// apps/web/src/vault/item-codec.ts field-for-field so items created by
// either client are readable by the other (the plaintext payload format
// is not a frozen contract file, but its wire shape must still match
// byte-for-byte with what actually gets sealed/opened) — apps/web is a
// forbidden path for this task, so this is a deliberate mirror, not a
// shared import, matching the existing account-bundle-codec.ts precedent
// of mirroring a shape across a language/runtime (here, a task-boundary)
// split. This module only ever touches plaintext bytes transiently, on
// the way into/out of the background's private CryptoWorkerHost.
export type ItemType = "login" | "note" | "totp-login";

export interface VaultItemData {
  type: ItemType;
  title: string;
  username?: string;
  password?: string;
  url?: string;
  notes?: string;
  /** Raw base32 TOTP secret, present only for type "totp-login". */
  totpSecret?: string;
}

export function encodeItemData(data: VaultItemData): Uint8Array {
  return new TextEncoder().encode(JSON.stringify(data));
}

export function decodeItemData(bytes: Uint8Array): VaultItemData {
  const parsed = JSON.parse(new TextDecoder().decode(bytes));
  if (typeof parsed !== "object" || parsed === null || typeof parsed.title !== "string" || typeof parsed.type !== "string") {
    throw new Error("malformed vault item payload");
  }
  return parsed as VaultItemData;
}

/** Local input validation, mirroring apps/web's rules so the same item is
 * accepted or rejected identically by either client. */
export function validateItemData(data: VaultItemData): string[] {
  const problems: string[] = [];
  if (!data.title || data.title.trim().length === 0) problems.push("Title is required.");
  if (data.title && data.title.length > 500) problems.push("Title is too long.");
  if (data.type === "login" || data.type === "totp-login") {
    if (!data.username && !data.password) problems.push("A login needs a username or a password.");
  }
  if (data.type === "totp-login" && !data.totpSecret) {
    problems.push("A TOTP login needs a secret.");
  }
  if (data.notes && data.notes.length > 100_000) problems.push("Notes are too long.");
  return problems;
}
