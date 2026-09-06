# Browser extension

Chrome and Firefox packages are emitted to `dist/chrome/` and `dist/firefox/`.
They use separate MV3/MV2 manifests, no remote code, and only `activeTab`,
`storage`, and HTTPS host access. `storage` holds exactly one non-secret
value — the accountId/apiOrigin association (`src/storage.ts`) — so the
popup can prefill those two fields on next use; it is never used for
credentials, TOTP values, wrapped key bundles, or any decrypted vault data.

## Independent unlock, save/update, and TOTP (ADR-0011 C04-EXT2)

The popup is the only unlock/save/TOTP surface. Unlocking performs an
independent OPAQUE login (`packages/sdk`'s `AuthClient`) against a
popup-entered accountId and an explicitly confirmed HTTPS API origin
(`src/origin.ts` rejects URL credentials, query/fragment configuration, and
any origin sourced from a page/content message), enrolls this login as its
own named device via G2's `bearer-session-v1` branch, fetches and opens the
account's key bundle using the background-private `CryptoWorkerHost`/WASM
adapter (`src/vault-manager.ts`), and loads the vault's item metadata into
memory only — nothing is cached to disk. Popup save/update and TOTP
display/fill all revalidate a fresh authenticated check (at most 30s apart,
5s network deadline) before releasing anything; a network failure or 401
locks, with no offline fallback. There is no wrapped-bundle cache, item
cache, or mutation queue — an unsaved popup edit can be lost on lock or
service-worker eviction.

Editing an existing item requires re-entering its password/notes/TOTP
secret in the popup form: the background only ever sends the *current* TOTP
code back to the popup on explicit request, never any other decrypted
secret, so there is no path by which a saved secret is redisplayed for
editing without the user re-entering it.

## Autofill policy

The content script runs on HTTPS only and requests a fill only for a visible
username/password pair in the top-level document. The background rejects HTTP,
frames, hidden fields, cross-origin form actions, subdomains, look-alikes, and
all non-exact origins. It keeps decrypted values in memory only and releases a
selected entry only after a user gesture; locking clears its session and the
vault manager's own host/session/item cache.

## Lifetime and revocation

Background restart/eviction, explicit lock/logout, popup close, a 5-minute
trusted-popup-inactivity timeout, and authentication failure/401 all lock.
Lock (`BackgroundPolicy.lock`/`lockFromPopupClose`) is a purely local,
no-network event; logout additionally attempts server-side session
revocation (best-effort) before clearing local state in `finally`. Revoking
the extension's enrolled device from another client is detected on the
extension's next fresh authenticated check (at most 30s later while the
popup is open) — there is no idle background polling timer and no claim of
instantaneous remote erasure.
