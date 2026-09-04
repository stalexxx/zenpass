# C04-ADR-DRAFT: Candidate ADR for the extension-to-vault bridge

Goal: Produce ONE candidate ADR (in `docs/decisions/`) proposing the
extension authentication/bootstrap flow, account discovery, key-bundle
authorization, origin/message authentication, session lifetime/lock
propagation, encrypted persistence, and exact data allowed to cross each
boundary for C04 (`docs/tasks/C04.md`). This is a PROPOSAL for human
security review, not an approval and not implementation.

**Hard constraint, per `docs/tasks/C04.md` and `AGENTS.md`: do NOT start any
C04 implementation, do NOT edit `docs/contracts/*`, and do NOT touch
`apps/extension/`, `apps/web/`, `packages/sdk/`, or `crates/crypto-core/`.**
This task produces exactly one new Markdown file (plus, if genuinely useful,
a short companion diagram/sequence description in the same file — do not add
new files elsewhere).

## Required reading before drafting

- `docs/tasks/C04.md` (the acceptance criteria and constraints you are
  designing against — re-read it; every acceptance-criteria bullet there
  needs a concrete answer in your ADR, not a restatement).
- `docs/security/THREAT-MODEL.md`, specifically T04, T05, T06, T07, T09,
  T15, T19.
- `docs/decisions/ADR-0007-c02-browser-opaque-client-binding.md` and
  `docs/decisions/ADR-0008-c01-web-account-setup-wasm-and-totp.md` — these
  are the two closest-precedent ADRs (client-side crypto scope decisions
  that got human security approval before implementation started); match
  their level of rigor and their format.
- C01's existing web vault session/Worker architecture (read
  `apps/web/` and `packages/crypto-worker/` source, and
  `packages/crypto-wasm/ARCHITECTURE-GAPS.md`) and C02/C03's existing
  extension baseline (`apps/extension/`, `packages/extension-adapters/`) —
  your proposal must build on what already exists, not redesign it from
  scratch.
- `docs/contracts/api-v1.md` and `docs/ux/flows.md`.

## What the ADR must decide (each needs a concrete, justified answer)

1. **Bootstrap/auth**: how does the extension's background context
   authenticate to get its own OPAQUE-derived session, without ever reading
   the web app's IndexedDB or `VaultSession`? Does it do its own OPAQUE
   login independently (re-entering the master password in the extension
   popup), or is there a narrower, explicitly-scoped cross-context handoff —
   and if the latter, exactly what crosses the boundary and how is it
   authenticated against a hostile page/content-script?
2. **Account discovery**: how does the extension find the user's
   `accountId` (C01 already flagged this as a UX gap even for the web app)?
3. **Key-bundle authorization**: how does the extension obtain the
   encrypted key bundle it needs to derive item keys, and what proves the
   request came from the legitimate extension background context and not a
   malicious page?
4. **Origin/message authentication**: exact message-passing contract between
   content script, background, and popup; what a hostile page can and
   cannot induce the extension to do (tie this explicitly to C03's existing
   fail-closed exact-origin/form policy — extend it, do not weaken it).
5. **Session lifetime/lock propagation**: how lock, browser restart,
   logout, and device revocation (B04's revocation cascade) each terminate
   the extension's session — this must be verifiable, not just documented.
6. **Encrypted persistence**: what the extension may cache locally (if
   anything) between popup opens, in what encrypted form, and its own
   lock/eviction rules.
7. **Data crossing each boundary**: for every boundary you introduce
   (content script <-> page, content script <-> background, background <->
   popup, background <-> server), state explicitly what data type crosses it
   and in what form (ciphertext vs. plaintext vs. opaque token) — this is
   what the human reviewer will check against C04's acceptance criteria
   ("cannot read IndexedDB/Worker session," "compromised page/content script
   cannot enumerate vault entries or receive credentials before a
   user-confirmed, exact-origin fill," etc).

## Format

Follow the ADR structure already established in this repo (see ADR-0007/
ADR-0008): Context, Decision to be approved, a findings/open-questions table
if there are things only a human reviewer can decide, and an explicit
`Status: PROPOSED — pending human security review` line at the top. Do not
mark it approved yourself. Name the file
`docs/decisions/ADR-0009-c04-extension-vault-bridge-proposal.md` — if that
number is already taken by the time you look, use the next free `ADR-00NN`
number instead and say so in your completion report.

## Completion report format

Use the template in `docs/plan/INTEGRATOR.md`. In "Follow-up tasks", state
plainly that this ADR requires human security review/approval before C04
implementation may begin, per `docs/tasks/C04.md`'s status gate.
