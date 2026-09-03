# H01 follow-up: Argon2id target-device calibration evidence protocol (G-07)

Status: **documentation preparation only. No calibration has been performed,
no parameter values are chosen, and nothing in this document is approved or
binding.**

Prepared by the G-07 documentation-preparation follow-up at HEAD `0629e4f`
(branch `stalexxx/g07-calibration-protocol-opencode`). Per `AGENTS.md` and
`docs/tasks/H01.md`, only the human security reviewer may approve findings or
freeze `crypto-envelope/v1`; per `docs/security/DECISIONS.md` SD-0003, KDF
calibration approval is pending H01.

## 1. Purpose and boundary

Gap G-07 in `docs/security/H01-REVIEW-CHECKLIST.md` §4 records that no
Argon2id target-device calibration evidence exists (500–1000 ms within the
contracted bounds), blocking AC-2 for threat T08. This document specifies how
that evidence is to be produced, recorded, and reviewed. It is a protocol,
not a result.

- It selects **no** `memoryKiB`, `iterations`, or `parallelism` values. Any
  operating point is chosen by the client at first setup (per contract), or
  proposed by the executing task in its completion report, and is in all
  cases subject to human review.
- It adds **no** acceptance constraint. The only acceptance constraints are
  those already stated in `docs/contracts/crypto-envelope-v1.md`; §2 restates
  them with the contract as the normative source. Sampling and coverage rules
  in this document are method requirements for evidence quality, not
  parameter acceptance constraints.
- It does not modify `crypto-envelope/v1`, fixtures, code, `STATUS.md`, or
  task files. G-07 closes only when evidence is produced under this protocol
  **and** the human reviewer records a disposition in ADR-0003.
- Per the gap register, execution ownership rests with **B01 (post-approval)
  or A04 rework**; the human H01 reviewer owns review and disposition.
- Timing evidence is environment-dependent. It is recorded in the results and
  provenance tables (§6) and referenced from ADR-0003 — never as frozen
  fixtures under `fixtures/crypto/`, which must stay deterministic.
- The values in `fixtures/crypto/kdf-parameters.json` are test-only parameter
  *encodings* for the CBOR shape (including the G-11 defect); they are not
  calibration outputs and must not be cited as calibration evidence.

## 2. Normative constraints (restated; no additions)

From `docs/contracts/crypto-envelope-v1.md` ("Fixed algorithms and sizes",
"Argon2id and unlock"):

| # | Constraint (contract-stated) |
|---|---|
| C-1 | Argon2id, RFC 9106, version 19 (Argon2 v1.3), 32-byte output |
| C-2 | Salt is 16 random bytes — fresh and unique per user in production; a fixed test-only salt is permitted for measurement inputs |
| C-3 | First-setup calibration targets a derive time of 500–1000 ms |
| C-4 | `memoryKiB >= 65536` |
| C-5 | `iterations >= 3` |
| C-6 | `parallelism >= 1` |
| C-7 | `memoryKiB` is at most 25% of reported physical memory |
| C-8 | Parameters are persisted and never silently weakened; upgrading them creates a new password wrapper only |

Related contract surface: typed errors `InvalidKdfParameters` and
`KdfResourceLimit` govern out-of-bounds or unavailable parameters; threat T08
(offline/online guessing) is the threat calibrated cost mitigates, with
"target-device benchmarks" listed as its verification activity.

## 3. Device matrix

Evidence must cover the client classes that perform unlock in the MVP: the
web vault and the browser extensions run Argon2id in the browser via the WASM
binding path. Native follow-on clients (D01/D02) are gated separately and are
out of scope for this evidence set. The supported browser/OS version matrix
is itself an open decision (threat model "Open questions" #3); this protocol
must not silently fix it — executors record the exact versions measured, and
coverage claims hold only for the recorded versions. The floor-device
definition (slot D3) must be confirmed by the reviewer as consistent with the
eventual supported-version decision.

| Slot | Hardware class (indicative; actual specs recorded per run) | Evidence role | Required? |
|---|---|---|---|
| D1 | High-end desktop (8+ logical cores, 16+ GiB RAM) | Upper-bound feasibility: window reachable at high memory within C-7 | Yes |
| D2 | Mid-tier laptop (4–8 logical cores, 8–16 GiB RAM) | Median target device | Yes |
| D3 | Low-end / oldest-intended laptop or desktop (2–4 logical cores, up to 8 GiB RAM) | Floor device: binding constraint; must demonstrate that an in-window point exists within C-4..C-7, or produce a finding | Yes |
| D4 | CI/runner machine | Repeatability regression only; not a client target | Optional |

Engine dimension (browser evidence only):

| Engine slot | Requirement |
|---|---|
| E1 | One Chromium-based browser; exact stable version recorded at evidence time |
| E2 | One Gecko-based browser (Firefox stable or ESR at the executor's choice); exact version recorded |
| native | Rust crate execution in `crates/crypto-core-tests` — implementation-level cross-check, not a client target; B01/post-approval only |

Coverage rule: the evidence set contains at least D1, D2, and D3; D3 is
measured under both E1 and E2. Each (hardware slot, engine) combination is a
separate run record. Distinct engines on the same D-slot machine are
acceptable when the hardware is recorded identically.

## 4. Measurement method

### 4.1 Environment control

- Idle machine: no background installs, indexing, backups, or updates; record
  notable running software.
- Laptops plugged in, power-saver disabled, battery at a healthy charge level
  (record any exception).
- Record thermal-throttling indicators where the OS exposes them; anomalies
  go in the run record's notes field.
- OS and browser versions fixed for the whole run record; no updates mid-run.

### 4.2 Test inputs (test-only; no real secrets)

- Fixed test-only password bytes and a fixed 16-byte test salt, defined by the
  executing task and published in the run record. They contain no secret
  material by construction.
- Version 19, output length 32.
- Production behavior is unaffected: production derives with the user's
  password and a fresh unique salt (T08); the salt value does not materially
  affect timing.
- Record a SHA-256 digest of the normalized input record (algorithm, version,
  memoryKiB, iterations, parallelism, salt hex, password byte length) in
  provenance. Never log real passwords, vault data, keys, or recovery
  material anywhere in this process.

### 4.3 Candidate grid (measurement scaffold, not a selection)

To make results comparable across executors and devices, measurements follow
a deterministic ladder derived only from contract bounds:

- `memoryKiB`: powers of two from 65536 (C-4) up to the largest power of two
  not exceeding the C-7 cap for that run, plus the exact C-7 boundary value
  when it is not a power of two.
- `iterations`: start at 3 (C-5). While the median is below 500 ms and the
  candidate grid is not exhausted, increase (double, then bisect between the
  last under-target and first over-target value) until a median lands in the
  window or the next step would exceed it.
- If the median at `iterations = 3` already exceeds 1000 ms for a memory
  value, record that over-window point and step memory down one power of two
  — never below 65536. If 65536 at `iterations = 3` still exceeds the window,
  that is a finding (§5), never a reason to violate C-4.
- `parallelism`: 1 and the value matching the runtime's measured concurrent
  lane capability (§4.6).

All measured points are reported, in-window or not; no point is dropped
because it is out of window. The grid is a scaffold for comparability; the
executing task may extend it with additional points, also reported in full.
Parameter selection is out of scope for this document.

### 4.4 Timing and sampling

- Time one complete Argon2id derive (the KDF call producing the 32-byte
  output; no UI, storage, or network), using a monotonic clock, in the
  runtime that will actually execute it:
  - Browser evidence: inside the browser runtime through the same binding
    surface B03 will expose, or — pre-approval, while no repository crypto
    exists — an equivalent in-browser WASM Argon2 invocation. State how WASM
    instantiation cost is amortized (e.g., excluded after a warm-up).
  - Native cross-check: the approved Rust crate in `crates/crypto-core-tests`
    (post-approval only).
- Warm-up: discard the first 5 runs per run record and candidate point.
- Samples: at least 30 timed runs per candidate point; report median, p05,
  p95, min, and max.
- Candidates measured in grid order; record any deviation and cooldowns.

### 4.5 Physical-memory determination (C-7)

- Record the exact source of the "reported physical memory" figure for each
  run (OS sysinfo, browser-exposed device memory, or WASM engine limit as
  applicable) and the numeric value used; the 25% cap is computed from that
  recorded figure.
- Known measurement-validity caveat (to be recorded and resolved by B01/the
  reviewer, not silently here): browsers may expose rounded or imprecise
  device-memory figures, and WASM may cap addressable memory below physical
  memory. If more than one plausible figure exists, record all of them and
  flag the ambiguity for the reviewer instead of silently choosing the
  largest.

### 4.6 Parallelism and lanes

- Record logical and physical core counts visible to the runtime.
- Record whether the measured runtime executes Argon2 lanes in parallel
  (threaded WASM) or serially (single-threaded WASM); wall time depends on
  this. If the production web runtime is single-threaded, evidence informing
  it must be taken in that same mode.

### 4.7 Constraint evaluation

For every measured candidate, the run record states pass/fail for each
applicable constraint: C-1/C-2 verified at the encoding level (parameter map
shape per `kdf-parameters.json` schema), C-3 = median within [500, 1000] ms,
C-4..C-6 numeric bounds, C-7 against the recorded cap. C-8 is a policy
property verified by review of the B01 upgrade path, not by timing.

## 5. Failure handling

- If no candidate satisfies C-3..C-7 on a required device slot, that is a
  finding: recorded in the results table and routed to the H01 reviewer
  (pre-approval) or as a B01 blocker (post-approval). It must not be resolved
  by weakening any bound, trimming samples, or redefining the device slot
  after the fact.
- If a runtime cannot allocate the C-4 minimum (64 MiB) — WASM memory
  pressure, engine caps — record the `KdfResourceLimit` behavior; this is a
  finding, not a pass.

## 6. Results and provenance tables (templates; filled only by executors)

### 6.1 Run provenance (one row per run record)

| Field | Value |
|---|---|
| Run id | — |
| Date / timezone | — |
| Executor (task + agent or human) | — |
| Device slot (D1–D4); actual CPU model, cores/threads, physical RAM | — |
| OS + version | — |
| Browser/engine + version (or `native`) | — |
| WASM mode (threaded / single-threaded / n/a) | — |
| Argon2 implementation measured — post-approval: approved crate + version per ADR-0003 library table; pre-approval: independent reference implementation + version | — |
| Harness identity (script path and/or commit SHA) | — |
| Physical-memory source + value; 25% cap applied | — |
| Test-input record digest (sha256) | — |
| Power / thermal / environment notes | — |

### 6.2 Measured results (one row per candidate point)

| Run id | memoryKiB | iterations | parallelism | median ms | p05 ms | p95 ms | min ms | max ms | C-3 in window | C-4 | C-5 | C-6 | C-7 | anomalies |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| — | — | — | — | — | — | — | — | — | — | — | — | — | — | — |

Rules:

- Append-only once recorded and reviewed; corrections are new rows with a
  note, never edits (mirroring the decision-register discipline).
- The table records measurements only; it deliberately has no "selected
  parameter" column. Proposals, if any, belong in the executing task's
  completion report and the reviewer's disposition in ADR-0003.
- Timing outputs contain no secret material by construction (test-only
  inputs); keep it that way.

### 6.3 Regression policy

Re-run the protocol when the Argon2 library or version changes, when the WASM
binding stack changes materially, or when the reviewer requires it —
consistent with ADR-0003's rule that library upgrades re-run vector
verification. C-8 applies throughout: a re-run may justify stronger-or-equal
parameters via a new password wrapper, never a silent downgrade.

## 7. Executor and reviewer responsibilities

| Role | Duties |
|---|---|
| A04 rework (pre-approval option) | Produce evidence with an independent reference Argon2id implementation (no repository crypto exists yet); fill §6 tables; report gaps as findings |
| B01 (post-approval) | Produce evidence with the approved crate over the actual runtime paths (browser WASM plus native cross-check); implement first-setup calibration per contract; keep calibration logging free of secrets and of parameter-downgrade paths |
| Human H01 reviewer | Verify matrix coverage, method conformance, provenance completeness, and constraint evaluations; record disposition in ADR-0003; only the reviewer may conclude whether the evidence supports approval |

## 8. Non-goals

- No parameter values chosen or recommended.
- No approval, signature, or freeze — that authority belongs to the human
  reviewer via `docs/decisions/ADR-0003-crypto-envelope-v1-approval.md`.
- No change to `crypto-envelope/v1`, fixtures, code, `STATUS.md`, or task
  files.
- This document does not by itself close G-07 and does not alter any task
  status.
