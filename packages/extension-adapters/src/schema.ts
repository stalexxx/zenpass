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

export type ValidatedPopupMessage =
  | { type: "get-state" }
  | { type: "request-candidates" }
  | { type: "fill-selected"; requestId: string; itemId: string }
  | { type: "lock" };

/** Validates a message claiming to come from the extension popup. The popup
 * may ask for state, request candidates for its bound tab, select a
 * background-issued capability, or lock. No credential, token, origin, or
 * candidate list may arrive here. */
export function parsePopupMessage(message: unknown): ValidatedPopupMessage | null {
  if (!isPlainObject(message) || typeof message.type !== "string") return null;
  if (message.type === "get-state" || message.type === "request-candidates" || message.type === "lock") {
    return hasExactKeys(message, ["type"]) ? { type: message.type } : null;
  }
  if (message.type === "fill-selected") {
    if (!hasExactKeys(message, ["type", "requestId", "itemId"])) return null;
    if (!boundedString(message.requestId, MAX_ID_LENGTH) || !boundedString(message.itemId, MAX_ID_LENGTH)) return null;
    return { type: "fill-selected", requestId: message.requestId, itemId: message.itemId };
  }
  return null;
}
