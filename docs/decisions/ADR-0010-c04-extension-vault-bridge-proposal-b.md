# ADR-0010: C04 extension-to-vault bridge architecture (proposal B)

Status: **PROPOSED — pending human security review.** This is a candidate
architecture for `docs/tasks/C04.md`'s status gate ("BLOCKED pending a new
ADR and human security approval"). It is not an approval and authorizes no
implementation. It introduces no new cryptographic primitive and proposes no
change to `crates/crypto-core`, `docs/contracts/*`, or `crypto-envelope/v1`.

**This is proposal B**, drafted independently and in parallel with
[`ADR-0009`](./ADR-0009-c04-extension-vault-bridge-proposal.md) (proposal A)
for the same C04 decision, so the human security reviewer has two
independent takes to compare rather than one. Both agree on the core shape
(independent extension-side OPAQUE login, no session/token handoff from the
web app, bearer-only key-bundle access, popup-owned save/fill, C03's
exact-origin fill model retained). They diverge most notably on: how the
in-extension WASM crypto host is invoked (ADR-0009 doesn't specify; this
proposal's §1 explicitly proposes an in-process `CryptoWorkerHost` call
instead of a nested `Worker`, and flags that as its own open question, F-1)
and on how much of the device-key/`DeviceCreate.publicKey` gap each
resolves (ADR-0009's F2 states it explicitly as a blocking finding; this
proposal's §5 assumes a distinct extension `device_id` registration without
flagging the same publicKey-semantics gap — a reviewer comparing both should
treat ADR-0009's F2 as still open here too). Only one of the two (or a
synthesis) should be approved; approving both as-is would leave the
in-process-vs-nested-Worker and device-key questions unresolved either way.

## Context

C04 needs the Chrome/Firefox extension (`apps/extension/`,
`packages/extension-adapters/`, both from C02/C03) to unlock its own
ephemeral session and perform encrypted item read/save/update and TOTP
display, without ever reading the web app's (C01) IndexedDB or in-page
`VaultSession`/Worker state, and without a compromised page or content
script being able to enumerate vault entries or obtain credentials outside
a user-confirmed, exact-origin fill.

What already exists and this proposal builds on, rather than redesigns:

- **C01's web session shape** (`apps/web/src/vault/vault-session.ts`,
  `apps/web/src/crypto/worker-client.ts`,
  `packages/crypto-worker/src/index.ts`): a `CryptoWorkerHost` holds opaque
  numeric session handles over live WASM state; the main thread never sees
  raw keys, only a session number it cannot dereference. `VaultSession`
  keeps the *decrypted item cache* in the main thread (not the Worker) —
  this is already the one place in `apps/web` holding plaintext-shaped
  data in memory, and it is never persisted, logged, or transmitted as
  plaintext.
- **`apps/web/src/vault/account-bundle.ts`**: only the AEAD-wrapped
  key bundle (ciphertext) and public KDF parameters are persisted locally
  (`localStorage`), keyed by `accountId`, enabling offline unlock.
- **`apps/web/src/crypto/account-id.ts`**: `accountId` is a client-generated
  random identifier with **no server-side email/username directory**. That
  file's own comment already flags this as a cross-device/cross-context
  discovery gap: *"a user restoring a session on a fresh browser profile
  must already know their accountId ... or recreate association via the
  recovery kit."* A browser extension is exactly such a fresh context (its
  `browser.storage` is isolated from the page's `localStorage` by design —
  this is not a bug to route around, it is the same isolation C04's
  acceptance criteria require).
- **`packages/sdk`'s `AuthClient`/`ApiClient`/`opaque-client.ts`** (C02,
  ADR-0007): a complete, reusable OPAQUE register/login choreography that
  needs only an `accountId` and password bytes, and an `ApiClient` that
  holds one bearer token in an instance field (no cookie, no implicit
  cross-context sharing).
- **C02/C03's extension baseline**
  (`packages/extension-adapters/src/index.ts`, `apps/extension/src/*`): a
  background-owned, memory-only `ExtensionSession`; `decideFill`/
  `confirmFill` already implement T05/T06's fail-closed exact-origin,
  top-frame, HTTPS-only, visible-field, cross-origin-form-action, and
  fresh-user-gesture checks; `save-submitted` is already wired to be
  refused unconditionally pending this ADR. **`ExtensionSession.unlock()`
  currently accepts a plaintext `UnlockedLogin[]` with no caller that
  produces one — this proposal replaces that placeholder shape.**
- **ADR-0005/ADR-0006 (B04, approved)**: access tokens are short-lived
  (15 min default), rotated via `/auth/refresh`; a session may be
  device-bound; revoking a `device_id` transactionally revokes every
  session bound to it; recovery-reset revokes every device/session for the
  account.

## What this proposal decides

### 1. Bootstrap/auth — independent OPAQUE login, not a session handoff

**The extension performs its own, fully independent OPAQUE login**, using
the user's master password re-entered in the extension popup. It does not
read, receive, or derive from the web app's `VaultSession`, Worker state,
IndexedDB, or session token in any form. No key material, session handle,
or access token ever crosses from the page/web-app context into the
extension, in either direction.

Rationale for rejecting a cross-context handoff: any channel capable of
moving live session material from an authenticated web tab into the
extension (a `postMessage`, a shared token in an intermediate storage the
page can also reach, a custom scheme the page could imitate) is itself a
new boundary a hostile page or malicious extension could target, and it
would require the web app's frozen "no keys/vault plaintext outside the
Worker" model (`docs/ux/flows.md`) to grow an exception. An independent
login has no such channel to defend: it reduces to "does the extension's
own popup form correctly gate a password entry with a real OPAQUE
exchange," which is exactly what C01/C02 already implement and this ADR
reuses unmodified.

Concretely:

- The extension popup (`apps/extension/src/popup.ts`, extended) presents a
  password field when locked. Its submit handler sends the password bytes
  to the background over the existing `PopupToBackground` channel (popup
  ↔ background is already the extension's only trusted, non-page-reachable
  surface — see §4).
- The background instantiates `packages/sdk`'s `AuthClient` (with an
  `ApiClient` pointed at the same backend base URL as the web app, and a
  WASM-backed `OpaqueClient` per `packages/sdk/src/opaque-client.ts`) and
  calls `AuthClient.login(accountId, passwordBytes)` — the same call
  `apps/web`'s unlock view makes. This is new *usage* of an existing,
  already-reviewed export; it adds no OPAQUE code.
- **On the WASM crypto boundary specifically**: MV3's background
  `service_worker` context can be evicted by the browser on its own idle
  timer (commonly ~30s), and Firefox's MV2 `persistent: false` background
  page is likewise non-persistent. Nesting a second dedicated Worker
  inside an already-non-persistent background context is fragile across
  both engines and adds a lifecycle this ADR would rather make explicit
  than paper over. **Proposal: the background instantiates
  `packages/crypto-worker`'s exported `CryptoWorkerHost` directly in its
  own JS context** (calling `host.handle(request)` as a plain function,
  not via `postMessage` to a nested `Worker`) instead of re-hosting
  `worker-entry.ts`'s `new Worker(...)` pattern. This reuses 100% of the
  already-reviewed session/protocol/zeroization logic
  (`packages/crypto-worker/src/index.ts`); it changes only *how* the host
  is invoked (in-process call vs. postMessage), not what it does or what
  crosses in or out of it. The background service worker/page is already
  a distinct OS-level process/isolated JS realm from any page or content
  script (extension process model), so this keeps the "raw keys never
  reach a page-reachable context" property — it just does not add a
  second isolation layer *within* the extension the way `apps/web` does
  within a tab. **Open question for the human reviewer**: whether that
  weaker-than-web in-extension isolation is acceptable, or whether a
  nested Worker (with its cross-browser reliability cost) should be
  required instead. See findings table, F-1.
- A successful login yields a bearer access token (held only in the
  background's in-memory `ApiClient` instance — never written to
  `browser.storage`, matching T15/T19) and, via the existing
  `/account/key-bundle` endpoint (§3) and `unlock-item-session`/
  `unlock-item-session-with-recovery` WASM calls, an opaque numeric
  session handle from the in-process `CryptoWorkerHost`, exactly like
  `apps/web`'s. `ExtensionSession` is changed from holding a plaintext
  `UnlockedLogin[]` to holding that session handle plus a decrypted item
  cache built the same way `VaultSession.loadAllItemsIntoMemory` does
  (open each item's envelope through the host) — mirroring, not reusing,
  `apps/web`'s cache because it lives in a different process/context.

### 2. Account discovery — mirror the existing gap, do not invent a directory

There is no server-side email→`accountId` directory today (out of scope
here — adding one is a contract change requiring its own ADR). The
extension cannot read the web app's `localStorage`, so it cannot silently
"find" the accountId the way a same-origin script could.

**Proposal**: first-run extension setup asks the user to paste their
`accountId` (already shown as a copyable, explicitly non-secret value in
the web app per `account-id.ts`'s own doc comment) into the popup, once.
The extension persists it via `browser.storage.local` (non-secret, exactly
parallel to the web app's use of `localStorage` for the same value) and
reuses it for every subsequent login and for the offline wrapped-bundle
cache key (§6). This is the same shape as the existing web gap, not a new
one — it inherits `account-id.ts`'s documented limitation rather than
solving it, which is consistent with this task's scope (C04 must not
invent an architectural decision C01/C02 didn't already make). Fixing the
underlying gap (a real directory, or QR/short-code device-linking) is
listed as follow-up work, not decided here.

### 3. Key-bundle authorization — bearer token, no page involvement

After its own OPAQUE login (§1), the extension calls
`GET /account/key-bundle` with its own bearer token (via `ApiClient`,
exactly as `apps/web` does). Authorization is the existing
`security: [{ bearerAuth: [] }]` scheme already defined on that endpoint —
no new authorization mechanism, no contract change. What proves the
request came from the legitimate extension background and not a page: **a
page cannot obtain this token at all.** It exists only as an in-memory
field on the background's own `ApiClient` instance; `browser.storage`
(which a compromised extension surface could theoretically reach) is never
used to hold it; content scripts and pages have no API to read background
JS memory or to make privileged `fetch` calls carrying it (WebExtension
message-passing is explicit, typed, and one-directional per §4 — there is
no ambient credential a page can ride along on, unlike a cookie).

### 4. Origin/message authentication — extend C03's model, do not weaken it

`packages/extension-adapters`'s `decideFill`/`confirmFill` and
`docideFill`'s refusal reasons (`locked`, `not-top-frame`, `not-https`,
`cross-origin-form`, `hidden-field`, `no-exact-origin-match`,
`confirmation-required`) are unchanged and continue to gate every fill.
This ADR only adds new message types for unlock/lifecycle, all of which
are **popup-only** (never reachable from a content script or page):

| Boundary | Existing / proposed messages | What crosses | Form |
|---|---|---|---|
| page → content script | DOM events only (focusin, submit) | Nothing extension-internal; content script reads visible field state from the DOM it already has | n/a (no message-passing API involved) |
| content script → background | `offer`, `fill`, `save-submitted` (existing, unchanged) | `PageRequest` metadata (URL, form action, visibility flags) and, for `fill`, an `itemId` + user-gesture flag chosen by the popup UI | Plaintext metadata only — never credentials, never a password, never a key |
| background → content script | `refused`, `offer-available`, `fill` (existing, unchanged) | For `fill`: exactly the two-or-three selected field values (username, password, optional TOTP code) for one item, only after `confirmFill` | Plaintext field values, but only post-confirmation and only the one selected item — matches C04's acceptance criterion verbatim |
| popup → background (existing) | `get-offer`, `fill-selected`, `lock` | Selection/gesture signals only | n/a |
| popup → background (**new**) | `unlock` `{ password: Uint8Array }`, `set-account-id` `{ accountId: string }`, `revoke-check` (see §5) | Master password bytes (this ADR's only place raw password bytes cross a message boundary — popup and background are both extension-only, page-unreachable contexts, same trust level `apps/web`'s in-page unlock form and its Worker already have) | Raw password bytes in, nothing sensitive out (background replies `locked`/`unlocked`/error only) |
| background → popup (**new**) | `unlocked`, `unlock-failed`, `locked` | Status only, no key or credential data | n/a |
| background ↔ server (**new**) | OPAQUE register/login legs, `/account/key-bundle`, `/devices*`, `/vaults/{vaultId}/items`, `/vaults/{vaultId}/changes` (all existing `api-v1` endpoints, reused via `packages/sdk`) | Opaque OPAQUE protocol messages, encrypted key bundle, ciphertext item envelopes, bearer token | Ciphertext/opaque only — identical shape to what `apps/web` already sends; no new field, no plaintext |

A hostile page therefore still cannot: read background memory, forge a
popup-only message (content scripts and popup use separate
`runtime.onMessage` registrations; a page cannot call
`chrome.runtime.sendMessage` with extension privilege at all — that API is
not exposed to page JS, only to extension contexts), trigger `unlock`
(popup-only, requires the popup's own UI and a real user keystroke into a
password field the page cannot script), or receive fill data before
`confirmFill`'s fresh-gesture check. This is strictly additive to C03's
existing fail-closed model, not a relaxation of it.

### 5. Session lifetime/lock propagation — verifiable, not just documented

| Event | Mechanism | Verification hook |
|---|---|---|
| Explicit lock (popup "Lock" button) | Existing `lock` message → background calls the in-process `CryptoWorkerHost.handle({type:"lock"})` (closes every WASM session) and clears `ExtensionSession`'s item cache and `ApiClient`'s access token | `ExtensionSession.locked === true`; a subsequent `fill`/`offer` returns `{reason:"locked"}` |
| Browser/background restart or MV3 idle eviction | Nothing sensitive survives eviction by construction (§1: session handle, item cache, and access token are all in-memory only, never written to `browser.storage`) — a respawned background starts locked and requires a fresh `unlock` | Same as explicit lock: any request after a simulated service-worker restart in the E2E harness must return `{reason:"locked"}` |
| Logout | New `logout` popup action: background calls `/auth/logout` (revokes its own current session token server-side) then performs the same local-clear as explicit lock | Server-side: token is rejected by any subsequent authenticated call (`401`); locally: same assertion as explicit lock |
| Device revocation (B04 cascade) | The extension **registers itself as its own device** on first successful login (`POST /devices`, e.g. name `"Chrome extension"`/`"Firefox extension"`, distinct `device_id` from the web app's), binding its session to that `device_id` (ADR-0005 §2: explicit device registration binds the *current* session). `/auth/refresh` is called proactively before the 15-minute access-token expiry (or reactively on a `401`); a revoked device makes refresh fail, which triggers the same local-clear as logout | E2E: revoke the extension's `device_id` from the web app's device list, then assert the extension's next refresh/API call fails and its subsequent `fill`/`offer` returns `{reason:"locked"}` — no manual extension action required, matching "device revocation makes the extension session unusable" |
| Recovery-reset (out of C04, in scope for propagation) | ADR-0006: recovery-reset already revokes every session/device for the account server-side; extension observes this identically to device revocation (next refresh/call fails → locks) | Same mechanism as device revocation, no extension-specific code needed |

This makes lock/restart/logout/revocation converge on one implementation:
*the extension never trusts local state to mean "still authorized"* — a
missing in-memory session is `locked`, and a rejected refresh/API call is
also `locked`. There is no separate "is this session still valid" cache to
fall out of sync.

### 6. Encrypted persistence — wrapped bundle only, mirroring C01

The extension may persist, in `browser.storage.local`, **only**:

- the user-entered `accountId` (non-secret, §2);
- the same shape as `apps/web/src/vault/account-bundle.ts`'s
  `AccountBundle` — AEAD-wrapped `wrappedAccountKey`/`wrappedVaultKey`/
  `wrappedItemKey`, public `kdfParametersCbor`, all ciphertext/public
  parameters, never raw keys — refreshed after every successful unlock or
  key-bundle fetch, to allow **offline extension unlock** consistent with
  `docs/ux/flows.md`'s "Offline unlock uses only the local encrypted
  snapshot and wrapped key bundle";
- nothing else. No item ciphertext cache, no decrypted item cache, no
  access/refresh token, ever touches `browser.storage`. The decrypted item
  cache and the WASM session handle exist only in the background's live
  JS heap and are cleared by every path in §5's table.

`browser.storage.local` is not encrypted by the browser itself, which is
why only already-AEAD-wrapped ciphertext and public parameters are
eligible for it — identical reasoning to why `apps/web` puts the same
shape in plain `localStorage` today.

### 7. Explicit summary against C04's acceptance criteria

- *"The extension cannot read the web application's IndexedDB or Worker
  session"* — true by construction: the extension has its own storage
  partition (browser-enforced) and never attempts cross-context access;
  its WASM session is its own independent login (§1), not a read of the
  web app's.
- *"A compromised page/content script cannot enumerate vault entries or
  receive credentials before a user-confirmed, exact-origin fill"* — the
  content script only ever receives `PageRequest`-shaped metadata
  requests/decisions and, post-confirmation, one item's fill fields (§4
  table); it cannot query the item cache directly, cannot message the
  background as if it were the popup, and cannot trigger `unlock`.
- *"Lock, browser restart, logout, and device revocation make the
  extension session unusable"* — §5.
- *"The server continues to receive only opaque key bundles and
  ciphertext"* — §4 table, background↔server row; no new endpoint, no new
  payload shape.

## Findings for human review

| ID | Question | Why it needs a human |
|---|---|---|
| F-1 | Is in-process `CryptoWorkerHost` invocation inside the background context (no nested Worker) an acceptable isolation trade-off versus a nested Worker, given MV3 service-worker eviction and Firefox MV2 event-page non-persistence make a nested Worker's lifecycle awkward? | Security isolation judgment call outside this task's authority; affects T04/T19 posture inside the extension process |
| F-2 | Is pasting a copyable `accountId` into the extension popup an acceptable interim account-discovery UX, or does C04 require a real linking flow (QR code, short-lived pairing code issued by the web app) before shipping? | UX/security trade-off; a pairing-code flow would need its own endpoint (contract change) |
| F-3 | Should the extension register as a distinct `device_id` (this proposal) or attempt to share the web app's `device_id`? Sharing would require some cross-context device-identity signal this proposal deliberately avoids introducing (§1) | Confirms no hidden coupling is expected between the two device registrations |
| F-4 | Proactive-refresh interval and revocation-detection latency (how soon after a revoke must the extension actually notice, per C04's "Required tests: ... device revoke") — this proposal defers to whatever cadence the E2E test suite requires but does not fix a number | Concrete timing requirement for the test suite, not an architecture question |

## Consequences if approved

- C04's implementation gets a concrete, reviewed sequence: extension popup
  unlock form → `packages/sdk` `AuthClient.login` → in-process
  `CryptoWorkerHost` → `ExtensionSession` (item cache + WASM session
  handle) → existing `decideFill`/`confirmFill` fill path (unchanged).
- No `crates/crypto-core`, `docs/contracts/*`, or `crypto-envelope/v1`
  change is needed; `packages/sdk` and `packages/crypto-worker` are reused
  read-only (new call sites, no new exports required by this ADR itself —
  if implementation later finds a genuine gap, e.g. a `CryptoWorkerHost`
  export that needs widening, that is a smaller, separate ADR, not this
  one).
- `ExtensionSession.unlock(logins: UnlockedLogin[])`'s current
  plaintext-array shape must be replaced during implementation with the
  session-handle + cache shape described in §1; this is flagged so
  implementation does not silently keep the placeholder and call it done.
- This ADR does not resolve F-1..F-4; C04 implementation must not proceed
  until a human reviewer records decisions for at least F-1 and F-2 (F-3/
  F-4 are lower-stakes but should still get an explicit answer).
