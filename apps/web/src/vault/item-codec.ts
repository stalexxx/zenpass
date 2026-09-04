// Plaintext-shaped vault item content and its wire encoding as the JSON
// payload sealed inside an ItemRecord's ciphertext. This module only ever
// touches plaintext bytes in memory transiently, on the way into
// `CryptoWorkerClient.sealItemPayload` or straight out of
// `openItemPayload` — it never persists, logs, or transmits a
// `VaultItemData` itself.
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

/** Local input validation (docs/ux/flows.md: "Save validates required
 * fields locally"). Returns a list of human-readable problems; empty means
 * valid. Deliberately conservative: title is always required, and a login
 * needs at least a username or password so an empty item isn't silently
 * saved as a blank login. */
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
