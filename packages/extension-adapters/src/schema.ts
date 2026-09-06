import { isByteArray, MAX_SECRET_BYTES } from "./bytes.ts";
import type { PageRequest } from "./index.ts";

/**
 * Strict, fail-closed validators for extension runtime messages
 * (ADR-0011, "Content → background" and "Popup → background" rows).
 *
 * Chrome runtime messaging is JSON-serialized, so every message must be
 * treated as untrusted structured input. Validators reject unknown fields,
 * wrong types, oversized strings, and non-plain objects instead of
 * normalizing hostile input. Nothing here trusts caller-supplied gestures,
 * candidate lists, tokens, or field values.
 */

const MAX_URL_LENGTH = 4096;
const MAX_ID_LENGTH = 128;

function isPlainObject(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function hasExactKeys(value: Record<string, unknown>, required: readonly string[], optional: readonly string[] = []): boolean {
  const allowed = new Set([...required, ...optional]);
  for (const key of Object.keys(value)) {
    if (!allowed.has(key)) return false;
  }
  for (const key of required) {
    if (!(key in value)) return false;
  }
  return true;
}

function boundedString(value: unknown, maxLength: number): value is string {
  return typeof value === "string" && value.length > 0 && value.length <= maxLength;
}

export type ValidatedContentMessage =
  | { type: "offer"; request: PageRequest }
  | { type: "cancel-offer" };

/** Validates a message claiming to come from a content script. Only bounded,
 * non-secret offer metadata for the current top document (or cancellation)
 * is accepted; every other shape — including any legacy `fill`,
 * `save-submitted`, `get-offer`, or `fill-selected` — is rejected. */
export function parseContentMessage(message: unknown): ValidatedContentMessage | null {
  if (!isPlainObject(message) || typeof message.type !== "string") return null;
  if (message.type === "cancel-offer") {
    return hasExactKeys(message, ["type"]) ? { type: "cancel-offer" } : null;
  }
  if (message.type !== "offer") return null;
  if (!hasExactKeys(message, ["type", "request"])) return null;
  const request = message.request;
  if (!isPlainObject(request)) return null;
  if (!hasExactKeys(request, ["pageUrl", "isTopFrame", "usernameVisible", "passwordVisible"], ["formAction"])) return null;
  if (!boundedString(request.pageUrl, MAX_URL_LENGTH)) return null;
  if ("formAction" in request && !boundedString(request.formAction, MAX_URL_LENGTH)) return null;
  if (typeof request.isTopFrame !== "boolean") return null;
  if (typeof request.usernameVisible !== "boolean") return null;
  if (typeof request.passwordVisible !== "boolean") return null;
  return { type: "offer", request: request as unknown as PageRequest };
}

const MAX_ACCOUNT_ID_LENGTH = 256;
const MAX_ORIGIN_LENGTH = 512;
const MAX_TITLE_LENGTH = 500;
const MAX_USERNAME_LENGTH = 1024;
const MAX_NOTES_BYTES = 128 * 1024;
const ITEM_TYPES = new Set(["login", "note", "totp-login"]);

export type ValidatedPopupMessage =
  | { type: "get-state" }
  | { type: "request-candidates" }
  | { type: "fill-selected"; requestId: string; itemId: string }
  | { type: "lock" }
  | { type: "logout" }
  | { type: "list-items" }
  | { type: "get-totp"; itemId: string }
  | { type: "unlock"; accountId: string; apiOrigin: string; password: number[] }
  | {
      type: "save-item";
      title: string;
      itemType: "login" | "note" | "totp-login";
      itemId?: string;
      username?: string;
      password?: number[];
      url?: string;
      notes?: number[];
      totpSecret?: number[];
    };

/** Validates a message claiming to come from the extension popup. The popup
 * may ask for state, request candidates for its bound tab, select a
 * background-issued capability, lock, log out, list/save vault items,
 * request the current TOTP code, or independently unlock. No token,
 * candidate list, or field value beyond what the user just entered may
 * arrive here — every schema below rejects unknown fields and out-of-range
 * types/lengths rather than normalizing hostile input. */
export function parsePopupMessage(message: unknown): ValidatedPopupMessage | null {
  if (!isPlainObject(message) || typeof message.type !== "string") return null;
  if (
    message.type === "get-state" || message.type === "request-candidates" || message.type === "lock" ||
    message.type === "logout" || message.type === "list-items"
  ) {
    return hasExactKeys(message, ["type"]) ? { type: message.type } : null;
  }
  if (message.type === "fill-selected") {
    if (!hasExactKeys(message, ["type", "requestId", "itemId"])) return null;
    if (!boundedString(message.requestId, MAX_ID_LENGTH) || !boundedString(message.itemId, MAX_ID_LENGTH)) return null;
    return { type: "fill-selected", requestId: message.requestId, itemId: message.itemId };
  }
  if (message.type === "get-totp") {
    if (!hasExactKeys(message, ["type", "itemId"])) return null;
    if (!boundedString(message.itemId, MAX_ID_LENGTH)) return null;
    return { type: "get-totp", itemId: message.itemId };
  }
  if (message.type === "unlock") {
    if (!hasExactKeys(message, ["type", "accountId", "apiOrigin", "password"])) return null;
    if (!boundedString(message.accountId, MAX_ACCOUNT_ID_LENGTH)) return null;
    if (!boundedString(message.apiOrigin, MAX_ORIGIN_LENGTH)) return null;
    if (!isByteArray(message.password) || message.password.length === 0) return null;
    return { type: "unlock", accountId: message.accountId, apiOrigin: message.apiOrigin, password: message.password };
  }
  if (message.type === "save-item") {
    if (!hasExactKeys(message, ["type", "title", "itemType"], ["itemId", "username", "password", "url", "notes", "totpSecret"])) return null;
    if (!boundedString(message.title, MAX_TITLE_LENGTH)) return null;
    if (typeof message.itemType !== "string" || !ITEM_TYPES.has(message.itemType)) return null;
    if ("itemId" in message && !boundedString(message.itemId, MAX_ID_LENGTH)) return null;
    if ("username" in message && !boundedString(message.username, MAX_USERNAME_LENGTH)) return null;
    if ("url" in message && !boundedString(message.url, MAX_URL_LENGTH)) return null;
    if ("password" in message && !isByteArray(message.password)) return null;
    if ("notes" in message && !isByteArray(message.notes, MAX_NOTES_BYTES)) return null;
    if ("totpSecret" in message && !isByteArray(message.totpSecret)) return null;
    const result: ValidatedPopupMessage = {
      type: "save-item",
      title: message.title,
      itemType: message.itemType as "login" | "note" | "totp-login",
    };
    if ("itemId" in message) (result as { itemId?: string }).itemId = message.itemId as string;
    if ("username" in message) (result as { username?: string }).username = message.username as string;
    if ("password" in message) (result as { password?: number[] }).password = message.password as number[];
    if ("url" in message) (result as { url?: string }).url = message.url as string;
    if ("notes" in message) (result as { notes?: number[] }).notes = message.notes as number[];
    if ("totpSecret" in message) (result as { totpSecret?: number[] }).totpSecret = message.totpSecret as number[];
    return result;
  }
  return null;
}
