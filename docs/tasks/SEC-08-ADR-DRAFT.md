# SEC-08-ADR-DRAFT: proposal draft for binding revision/deleted into the crypto envelope

Goal: prepare a **draft ADR** (a decision document for the human security
reviewer) proposing how to close the residual gap left open by SEC-04
(GitHub issue #4, fixed; residual tracked as issue #8): a dishonest server
can relabel a genuinely-valid *old* ciphertext under a fabricated *higher*
`revision`, and the client cannot detect this, because `crypto-envelope/v1`'s
AAD binds `keyVersion` but not `revision`/`deleted`.

**This is a proposal-drafting task, not an implementation task.** Do not
modify `crates/crypto-core`, `docs/contracts/*/v1`, or any envelope/wire
format. Do not change `packages/sdk`'s `assertMonotonicPut` or
`SyncEngine.pull` (already merged, working as designed within the current
envelope). Produce a document for human review, following the shape and
rigor of `docs/decisions/ADR-0003-crypto-envelope-v1-approval.md` and
`docs/decisions/ADR-0011-c04-approval-packet.md` — precise, evidence-based,
explicit about tradeoffs and what remains a human decision, never presenting
a recommendation as already authorized.

Allowed paths: `docs/decisions/`, `docs/tasks/SEC-08-ADR-DRAFT.md`. You may
*read* anything in the repo (crates/crypto-core, docs/contracts,
packages/sdk, existing ADRs, the C01 key hierarchy, migration files) to
ground the proposal in the actual current implementation — but write nothing
outside `docs/decisions/`.

Read first: `docs/contracts/crypto-envelope-v1.md` (or wherever the AAD/
envelope format is actually specified — find and cite the real file/line),
`crates/crypto-core`'s AEAD/envelope construction code (find where AAD bytes
are actually assembled — cite exact file/function), `packages/sdk/src/
repository.ts`'s `assertMonotonicPut` and its doc comment (states the exact
residual gap this ADR addresses), GitHub issue #8, ADR-0003 (crypto-envelope
v1 approval and its F-1/F-2/F-3 findings — G-06 in particular), and
ADR-0011 (a recent example of a well-structured proposal-plus-approval-gate
document for this project).

Required content for the draft:

1. **Precise problem statement.** Cite the exact AAD construction in
   `crates/crypto-core` (file/function/line) and show exactly which fields
   it authenticates today. State the exact attack: a dishonest/compromised
   server replays envelope bytes E (validly produced by the legitimate
   client at some point in the past) under a change-feed record claiming a
   higher `revision`/different `deleted` than when E was produced, and
   `assertMonotonicPut` accepts it as a legitimate advance because nothing
   cryptographically ties E to any particular revision or deleted state.
2. **At least two candidate designs**, each with concrete mechanism, not
   just a name:
   - Option A: extend the existing AAD construction to include `revision`
     and `deleted` (or a monotonic counter) as authenticated (not encrypted)
     associated data, alongside the existing `keyVersion`. Specify exactly
     what bytes get added, in what order, and why that doesn't collide with
     or weaken the existing AAD.
   - Option B: any other viable mechanism you can identify from actually
     reading the code (e.g. a client-side trusted high-water-mark scheme,
     a server-attested monotonic counter signed by something the client can
     verify, or an argument for why no viable client-only fix exists and a
     server-side trust assumption change is unavoidable). Do not force a
     second option if none is honestly viable — say so and explain why, the
     same way ADR-0011 explicitly named tradeoffs it was accepting rather
     than inventing false alternatives.
   For each option, cover: exact AAD/wire bytes, whether it requires a new
   `envelopeVersion` (a v2) or an in-place change, and — critically — what
   happens to **existing already-encrypted data**: does it require
   re-encryption of every existing item on next write, dual-read support
   for old envelopes indefinitely, or a one-time forced re-key? Be concrete
   about the migration mechanics across every client (web, extension) and
   the backend (does the backend need to know about `revision` inside the
   envelope, or does it stay opaque to it as today?).
3. **Recommendation** with reasoning, in ADR-0003/ADR-0011's style: state
   what you'd recommend and why, but do not claim it is decided — the human
   reviewer decides.
4. **Explicit scope boundary**: state plainly that this ADR, even once
   approved, only authorizes a bounded follow-up implementation task (crypto
   core change + client migration), not a blanket crypto-core rewrite —
   mirror ADR-0011's "Decision requested" section's discipline about not
   letting direction-approval expand into unbounded scope.
5. **Residual risks accepted either way**: if some replay/rollback shape
   still can't be fully closed even under your recommended option, say so
   explicitly rather than claiming full closure — this codebase's existing
   ADRs (ADR-0003 F-2/F-3, ADR-0011's first-enrollment replay residual) are
   consistently honest about exactly this kind of thing; match that standard.
6. A **human decision record** table/section styled like ADR-0003/ADR-0011's,
   left blank/pending for the actual human reviewer to fill in — do not
   fabricate an approval.

Verification: no code changes, so no test suite to run. Do a self-check pass:
every specific claim about existing code (AAD fields, envelope format,
`assertMonotonicPut` behavior) must be verified against the actual current
file/line before being stated as fact, not remembered/assumed from
documentation that might be stale.

Completion report format: Standard completion report (`docs/plan/
INTEGRATOR.md`). State clearly this is a draft awaiting human review, not an
approved or actionable ADR, and do not mark GitHub issue #8 closed or
resolved — it stays open until the human reviewer actually decides.
