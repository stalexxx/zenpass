# C04-EXT: approved extension vault boundary

Goal: Implement the approved extension-side boundary from ADR-0011 without
reading web-origin state or persisting vault secrets.

Dependencies: ADR-0011 approval; C04-G1 API/SDK contract may be consumed only
after its merge. This task may harden existing extension boundaries first.

Allowed paths: `apps/extension/`, `packages/extension-adapters/`,
`docs/tasks/C04-EXT.md`.

Forbidden paths: `crates/crypto-core/`, `packages/contracts/`, backend,
SDK/web implementation, frozen envelope/sync contracts, new cryptographic
primitives, external messaging, remote code, plaintext vault/key/password/TOTP
persistence, logging, analytics, or fixtures.

Required implementation:

- Remove direct content-script fill and credential-bearing page-submit transport.
  Treat content input as bounded, non-secret offer metadata only.
- Separate popup/content authority with sender, extension ID, tab, frame,
document and origin validation; popup is the only selection source.
- Implement one-use, document-bound exact-origin fill capabilities; fail closed
on navigation, form change, unknown browser identity or late async response.
- Add final packaged-WASM CSP allowance only (`wasm-unsafe-eval`), no broad
eval/inline/remote-code permission.
- Build the extension-local session state machine and popup UX around approved
online-only independent unlock. Keep it locked until C04-G1's API/SDK methods
are merged; no mocked plaintext `UnlockedLogin[]` production path.
- On G1 merge, use its SDK/host APIs for independent OPAQUE unlock, key-bundle
opening, device binding, popup save/update and separate popup TOTP actions.
Lock on expiry, errors, popup close, restart/eviction, logout and 401.

Required tests: strict message schemas/sender validation; malicious content
script cannot enumerate/select/bypass confirmation; navigation/document races;
lock generation and late response; storage/log inspection; Chrome and Firefox
manifest/CSP builds. Full browser E2E is required after C04-G1 merge.

Verification: extension/adapters tests and build, boundary check, and final
real-browser E2E. Report using `docs/plan/INTEGRATOR.md`.
