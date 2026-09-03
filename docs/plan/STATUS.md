# Live status

This file is maintained by the integration agent.

| ID | Status | Owner | Dependencies | Last result |
|---|---|---|---|---|
| A00 | MERGED | foundation agent | — | Scaffold builds; boundary check and Rust tests pass |
| A01 | MERGED | security agent | A00 | 20 threats mapped to mitigations and verification |
| A02 | MERGED | contracts agent | A00 | OpenAPI, schemas, fixtures, and sync state machine added |
| A03 | MERGED | coordinator | A00 | UX flows and accessibility states documented |
| A04 | READY | crypto-spec agent | A01,A02 | H01 accepted deferred fixture findings F-2; G-03 wrap vectors, G-09 real recovery-wrap vector, and independent-adapter CI path remain open before production crypto delivery |
| H01 | MERGED | integration agent | A04 | `stalexxx` approved with findings on 2026-09-03; ADR-0003 freezes v1 and defers F-2/F-3 to B01/A04/H02 |
| B01 | MERGED | integration agent | H01 | Rust crypto-core integrated after independent Codex review; ADR-0003 F-2/F-3 and H02 release gates remain |
| B02 | MERGED | backend agent | A02 | Health, redaction, and repeatable PostgreSQL migration tests pass; Compose uses host port 5434 |
| B03 | READY | bindings agent | B01 | Rust crypto-core merged; binding work must preserve ADR-0003 F-2/F-3 constraints |
| B04 | BLOCKED | auth agent | B02,A02,H01,B03 | Backend has no permitted/implemented Rust OPAQUE binding; token/refresh, WebAuthn, recovery-proof persistence, and route-mount contracts need explicit follow-up decisions |
| B05 | BLOCKED | sync agent | B02,B04,A02 | |
| C01 | BLOCKED | web agent | B03,B05,C02 | |
| C02 | BLOCKED | sdk agent | A02,B03,B05 | |
| C03 | BLOCKED | extension agent | C01,C02 | |
| Q01 | BLOCKED | QA/security agent | C03 | |
| H02 | BLOCKED | external auditor | Q01 | |
| R01 | BLOCKED | release agent | H02 | |
| D01 | BLOCKED | desktop agent | R01 | |
| D02 | BLOCKED | mobile agent | R01 | |
