// The backend's `accounts` table (per apps/backend, B02/B04/B05) is keyed
// by an opaque accountId the client controls entirely — there is no
// email/username concept server-side. This module owns that client-only
// decision: the accountId is a random, non-secret, client-generated
// identifier (not derived from the user's email or password), persisted
// locally so the same browser profile can find its own account again.
//
// This is *not* a login/lookup mechanism across devices — see the
// completion report's Known limitations: without a server-side
// email->accountId directory (out of scope; would be a contract change),
// a user restoring a session on a fresh browser profile must already know
// their accountId (surfaced in the UI as a copyable value) or recreate
// association via the recovery kit. Non-secret: safe to log/display,
// unlike everything else this app handles.

const STORAGE_KEY = "zkpm.accountId.v1";

function randomAccountId(): string {
  const bytes = new Uint8Array(16);
  crypto.getRandomValues(bytes);
  return Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
}

/** Returns this browser profile's stable client-generated accountId,
 * creating and persisting one on first use. Safe to persist in
 * localStorage: it is an opaque identifier, not a secret. */
export function getOrCreateAccountId(storage: Storage = localStorage): string {
  const existing = storage.getItem(STORAGE_KEY);
  if (existing) return existing;
  const created = randomAccountId();
  storage.setItem(STORAGE_KEY, created);
  return created;
}

/** Associates a display email with the local accountId purely for this
 * browser's own UI (e.g. "signed in as ..."); never sent anywhere the
 * accountId itself isn't already going, and never used as a lookup key. */
const EMAIL_KEY = "zkpm.accountEmail.v1";
export function setDisplayEmail(email: string, storage: Storage = localStorage): void {
  storage.setItem(EMAIL_KEY, email);
}
export function getDisplayEmail(storage: Storage = localStorage): string | null {
  return storage.getItem(EMAIL_KEY);
}
