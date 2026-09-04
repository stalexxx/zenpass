# ADR-0009: C04 extension vault bridge proposal (proposal A)

Status: **PROPOSED — pending human security review.** This is a design
proposal only. It authorizes no implementation, contract change, or new
cryptographic primitive.

**This is proposal A.** [`ADR-0010`](./ADR-0010-c04-extension-vault-bridge-proposal-b.md)
(proposal B) was drafted independently and in parallel for the same C04
decision — see its intro for a summary of where the two converge and
diverge. Only one of the two (or a synthesis) should be approved.

## Context

C04 must give the Chrome/Firefox extension an independently unlockable vault
without making the web application's origin-bound storage or `VaultSession`
an extension API. The existing web client deliberately keeps its item session
in a dedicated Worker and its encrypted repository in the web origin's
IndexedDB. An extension cannot and must not read either. Its existing C03
baseline instead has a background-owned volatile session, an isolated popup,
and a content script whose exact-origin/form checks reject HTTP, frames,
hidden fields, cross-origin form actions, subdomains, and look-alikes.

The existing v1 API already supports the needed server-side primitives:
independent two-leg OPAQUE login, a bearer-authenticated opaque
`/account/key-bundle` endpoint, item ciphertext endpoints, short-lived
sessions, explicit device binding, refresh rotation, logout, and a
device-revocation session cascade (ADR-0005/0006). ADR-0007 already exposes
the approved OPAQUE client operations through WASM; ADR-0008 establishes the
client-side account-wrapper and Worker patterns. No current implementation
wire exists for the key-bundle endpoint, and no extension Worker/session
implementation exists; this proposal must not imply that either is already
safe or complete.

A web page is hostile. A page can influence the DOM observed by a content
script, cause focus/submit events, and attempt to race navigation. It cannot
call the WebExtensions runtime API directly, but the background must also
treat a content-script request as untrusted input: a compromised content
script must not gain vault enumeration, session, or general decryption
capabilities. The popup and extension Worker are extension-controlled
contexts, but an unlocked client is still in scope for T04, T05, T06, T07,
T09, T15, and T19 mitigations.

## Decision to be approved

### 1. Independent extension unlock; no web-to-extension handoff

The extension shall perform an independent OPAQUE login from its
extension-controlled unlock popup. The user selects or enters an `accountId`
and enters the master password in the popup; the password is represented as a
mutable byte buffer and forwarded only to an extension-owned vault Worker.
That Worker performs ADR-0007's existing OPAQUE choreography directly with
the configured API and keeps the OPAQUE transient state, bearer token,
expiry, decrypted key handles, and crypto-session handles private. It returns
only a coarse `unlocked`/`locked`/generic-error result to the background.
The popup and background wipe their structured-clone password buffers in
`finally`; the Worker follows the existing `CryptoWorkerHost` zeroization and
close-session behavior. JavaScript string copies remain a documented
best-effort limitation, not a reason to persist them.

There is no web page, web origin, `postMessage`, external-message, native
messaging, IndexedDB, localStorage, or `VaultSession` handoff. In particular,
the extension shall not receive a web bearer token, opaque Worker handle,
wrapped bundle copied from web storage, decrypted item, recovery key, or
account password. This removes an untrusted page/content-script
authentication problem rather than attempting to solve it with an ambient
web-origin secret.

The extension Worker owns both the extension crypto session and authenticated
API client. The background is a policy router, not a vault or token holder.
It may retain only a boolean lock state and non-secret pending-fill binding.
Worker requests are allow-listed, schema-validated, size-bounded, and have no
raw-key export operation. All worker/network errors exposed outside the
Worker are generic and secret-free.

### 2. Account discovery and device binding

`accountId` is an opaque, non-secret client identifier, not an email lookup
key. On first extension unlock the popup requires the user to type/paste the
accountId previously shown by the web client (or choose a previously saved
account association). After a successful independent unlock, the extension
may save only that accountId, display label, API origin, and a format/version
marker in `storage.local`. It must neither discover accounts from an email nor
query a directory, and must never infer an accountId from a password.

The user must confirm the API origin during first setup; it is then fixed per
account association and changes require explicit removal/re-enrolment and
another unlock. This avoids an attacker-controlled page choosing the API
destination. The association is convenience metadata only: editing it cannot
unlock an account.

After each independent login, the Worker registers (or reuses through an
approved implementation of the existing device API) a clearly named extension
device and binds the newly issued session before it attempts refresh. The
existing `DeviceCreate.publicKey` field has no documented extension credential
semantics; C04 must not invent one. The implementation may use the existing
device-registration shape only after a reviewer decides what approved device
public-key material/value is appropriate, or it must perform no refresh and
require a fresh OPAQUE unlock after token expiry. No device private key is
persisted by this ADR.

### 3. Key bundle and encrypted records

Only the Worker, using its own post-OPAQUE bearer token in an HTTPS
`Authorization` header, calls `GET /account/key-bundle`. The endpoint returns
the already specified versioned opaque bundle. The Worker parses it as the
approved account-wrapper record and uses it only to open its own session; it
does not pass it to popup, background, content script, or page. The same
Worker fetches item records and submits mutations. Server authorization is
the independently authenticated bearer session, whose raw value never leaves
the Worker; browser process isolation plus validated `runtime` senders prove
that a page cannot make this request through the extension.

This requires implementing the existing frozen key-bundle route/client
wiring and a versioned extension wrapper-record adapter. It does **not**
authorize changing the endpoint, wrapper bytes, OPAQUE context, crypto
envelope, or server authorization model. If the extant endpoint cannot
supply the wrapper material C01 uses, implementation stops for a new ADR and
human review rather than adding an ad-hoc token or bundle format.

The Worker sends and receives only opaque key bundles and ciphertext to/from
the server. It encrypts all new/updated items before persistence or mutation,
and verifies/decrypts only inside its own crypto session. The server remains
unable to decrypt or derive vault contents.

### 4. Exact message contract and fill capability

The implementation shall replace C03's broad union handling with separate,
strictly validated internal message schemas. Every message rejects unknown
keys, invalid lengths, wrong sender context, stale request IDs, and a locked
session. `runtime.onMessage`/ports are the only extension message channel;
there is no `window.postMessage`, DOM event, `externally_connectable`, or
page-accessible extension API.

| Boundary | Allowed request/result | Authentication and required checks |
|---|---|---|
| Page ↔ content script | No protocol message. The page can only influence its own DOM and receive a browser-visible fill after approval. | Content script never injects a page bridge, never reads page messages, and runs only from the manifest's HTTPS match. |
| Content script → background | `offer` containing bounded, non-secret page/form facts: current HTTPS origin/URL, top-frame status, visible-field booleans, and same-origin form-action result. | Background accepts only `sender.id === runtime.id`, a tab sender, `frameId === 0`, and a sender/document URL whose canonical origin equals the reported origin. It independently re-applies C03 `decideFill`; caller-supplied item IDs, origin, or gesture flags never authorize a fill. Result is only `offer-available` or a generic refusal—never candidates, item IDs, titles, ciphertext, or values. |
| Popup ↔ background | Popup sends a mutable master-password byte buffer only for unlock; otherwise it sends non-secret account/API selection, a chosen candidate ID, or plaintext fields typed into the popup's save/edit form. It receives coarse lock/error state, candidate metadata, and a TOTP code only for an explicit display action. | Background accepts only the extension's own popup URL/sender ID. A candidate list is sent only to this popup and only for the active tab-bound offer. The click creates a single-use background nonce; a Boolean supplied by content code is never a user-gesture proof. The background never persists those plaintext buffers/fields and immediately forwards them to the Worker for wiping/processing. |
| Background ↔ Worker | The background forwards the unlock password buffer, popup-entered save/edit plaintext, exact-origin selection capability, and lock command. The Worker returns only candidate metadata for the popup, selected fill fields destined for the content script, or a one-time TOTP display result. | A private Worker channel, exact schemas, request IDs, size limits, and locked-by-default capability checks. No token/key/bundle/raw session handle crosses it; the background wipes caller-owned mutable buffers after forwarding. |
| Background → content script | A single-use `fill` capability/result: the selected username/password and, only when separately selected, current TOTP code; no title, URL, item ID, list, token, bundle, seed, or ciphertext. | It is emitted only after popup click, Worker re-validates the same exact HTTPS origin, background rechecks the tab/document binding immediately before send, and the content script rechecks the actual top-level visible fields and same-origin action immediately before assignment. The capability expires immediately after one send or navigation. |
| Worker ↔ server | OPAQUE messages, accountId, bearer token in HTTPS header, opaque key bundle, ciphertext mutations/records, opaque cursor, and non-secret protocol metadata. | TLS plus the existing API contract and bearer/session/device checks. No password, recovery key, raw key, decrypted field, TOTP seed/code, page URL, or telemetry/log payload is sent. |

An offer is bound in the background to a random, single-use `fillRequestId`,
tab ID, top-level frame/document identity where the platform exposes it,
canonical origin, form-action origin, and expiry. The popup may select only a
candidate in that bound offer. Before a fill, the background re-reads the tab
URL and rejects navigation/origin changes; the content script repeats the
field/form validation at delivery. A platform lacking a reliable top-level
document identity must fail closed on a navigation race rather than retain
an offer across navigation.

The C03 policy is retained and strengthened: only exact HTTPS origin matches;
no HTTP, subdomain, look-alike, iframe, hidden/read-only/disabled fields, or
cross-origin action; no automatic fill; and no content-script candidate
enumeration. A hostile page may provoke a non-secret offer indication or
cause refusal, but cannot enumerate entries, select an item, manufacture a
popup click, obtain a token/bundle, or receive a credential before the user
has selected that entry in the extension popup for that exact origin. A
compromised content script is similarly limited to causing offers/refusals;
it receives selected values only at the deliberately user-confirmed fill
point, which is the unavoidable boundary C03 already defines.

TOTP code display occurs only in the extension popup after a separate fresh
user action. TOTP fill is a separate popup action and one-use exact-origin
capability; the Worker derives the current code only then, never sends the
seed outside the Worker, and never stores a code. The implementation must use
the approved C01 client-side TOTP approach (native Web Crypto, no hand-rolled
primitive) or obtain a new approved decision.

Save/update is popup-owned. The content script may provide non-secret site
context only; it must not forward submitted username/password/TOTP values to
the background, as C03's current placeholder does. The user types/pastes or
edits credential fields in the extension popup's extension-controlled save
form after confirming the exact origin. Those fields go only popup →
background → Worker, are sealed in the Worker, and are never returned to the
page. This deliberately favors a safe manual save/update over a page-form
capture bridge.

### 5. Lifetime, locking, persistence, and revocation

The extension starts locked. A normal explicit lock, inactivity timeout,
popup/background shutdown, Worker error, browser restart, account removal,
logout, 401/expired-token response, failed refresh, or device-revoked
response must all take the same idempotent lock path: cancel pending offers,
close every Worker crypto session, zeroize mutable buffers, discard decrypted
item/candidate/TOTP state and bearer token, terminate the Worker, and notify
popup/content only with `locked`/generic refusal. No API request may be
started after lock until another independent unlock succeeds.

Chrome MV3 service-worker suspension/restart and Firefox background restart
are treated as lock events, not as resumable session mechanisms. Access and
refresh tokens, decrypted records, raw keys, OPAQUE state, Worker handles,
TOTP values, and passwords are never persisted in `storage.local`, IndexedDB,
sync storage, session storage, logs, diagnostics, crash reports, analytics,
or fixtures. There is no offline unlock in C04's first implementation.

Between popup opens the extension may persist only the non-secret account
association described above and encrypted-at-rest opaque item ciphertext plus
opaque cursors/mutation queue **if** C04 needs offline encrypted sync. Such a
cache must be namespaced by account/API origin, contain no plaintext or token,
be validated as bounded ciphertext/metadata before use, and be deleted on
explicit account removal; lock retains only this ciphertext cache. This ADR
does not approve a second encryption scheme around those records. Any desire
to persist a wrapped key bundle for offline unlock must be separately reviewed
against the exact C01 wrapper-record serialization and extension storage
threat model; it is prohibited in the first C04 implementation.

Device revocation is verified rather than inferred: each authenticated
operation and refresh must handle the existing 401 failure by taking the lock
path. A live extension must periodically refresh only after approved device
binding; refresh rotation replaces the Worker-only token atomically, and any
failure locks. This gives B04's server-side revoke cascade a client-observable
enforcement point even though the server cannot push a message into a dormant
extension.

Required C04 E2E/storage tests must demonstrate, in Chrome and Firefox:
independent unlock without web storage access; restart and timeout clearing;
logout/401/revocation making Worker operations fail; token rotation rejecting
the prior token; exact-origin confirmation fill and refusal for each C03
negative case; no candidate list/value before confirmation; manual
popup-owned save/update; TOTP display/fill one-use behavior; and inspection
of extension storage, network logs, and diagnostics for forbidden plaintext,
tokens, keys, or seeds.

## Consequences

- The extension and web vault become two independently unlocked client
  sessions. This is intentionally less convenient than silently sharing a
  web login, but preserves web-origin isolation and gives revocation a
  distinct device/session boundary.

- C04 implementation needs additive extension Worker/background/popup work,
  key-bundle route/client wiring, and test coverage within the post-approval
  paths. It must reuse ADR-0007's OPAQUE binding and existing Worker crypto
  operations; it may not duplicate OPAQUE, KDF, AEAD, or envelope logic in
  TypeScript.

- Manual popup-owned save/update does not capture passwords entered into a
  web page. Page-form capture remains explicitly out of scope unless a future
  ADR gives a narrowly authenticated, user-confirmed data-flow design.

- The accountId discovery experience remains a deliberate UX cost until a
  separately reviewed, non-enumerating account-association mechanism exists.

## Findings and open questions for human review

| ID | Finding / question | Required disposition before C04 implementation |
|---|---|---|
| C04-F1 | The frozen OpenAPI defines `GET /account/key-bundle`, but the current backend/SDK do not wire it and C01's local wrapper representation is not a documented API serialization. | Confirm that an additive implementation can map the existing opaque `KeyBundle` bytes to the approved C01 wrapper record without changing bytes/contracts; otherwise require a new ADR and contract/security review. |
| C04-F2 | `DeviceCreate.publicKey` has no approved extension device-key algorithm, proof-of-possession, persistence model, or reuse rule. Inventing one would be a cryptographic/protocol decision. | Approve a bounded reuse of an existing documented device-key scheme, or prohibit refresh for C04 and require re-OPAQUE-login after expiry. Do not fabricate a key format. |
| C04-F3 | MV3/Firefox lifecycle differences can terminate the background/Worker unexpectedly, and document-identity targeting differs by browser/version. | Security review must accept the concrete supported-browser API matrix and fail-closed navigation-race behavior before implementation. |
| C04-F4 | This proposal permits a content script to receive a selected credential only after popup confirmation because fill necessarily crosses that extension boundary. A fully compromised extension while unlocked remains outside the core confidentiality guarantee. | Confirm that this is the accepted T05 boundary and review the concrete sender/document checks and Chrome/Firefox E2E evidence. |
| C04-F5 | Existing C03 `save-submitted` transports page values but is intentionally fail-closed. | Approve popup-owned manual save/update as C04 scope, or require a separate ADR for any automated page-form capture. |
| C04-F6 | C01 has no secure second-device accountId discovery UX beyond a displayed/copyable opaque ID. | Approve manual accountId enrollment for C04, or define a separately reviewed non-enumerating recovery/association UX; do not add email lookup. |
