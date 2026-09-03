# Live status

This file is maintained by the integration agent.

| ID | Status | Owner | Dependencies | Last result |
|---|---|---|---|---|
| A00 | MERGED | foundation agent | — | Scaffold builds; boundary check and Rust tests pass |
| A01 | MERGED | security agent | A00 | 20 threats mapped to mitigations and verification |
| A02 | MERGED | contracts agent | A00 | OpenAPI, schemas, fixtures, and sync state machine added |
| A03 | MERGED | coordinator | A00 | UX flows and accessibility states documented |
| A04 | READY | crypto-spec agent | A01,A02 | Review failed: no crypto-fixtures package/verifier; AEAD and OPAQUE vectors incomplete |
| H01 | BLOCKED | human reviewer | A04 | Human approval required before crypto implementation merge |
| B01 | BLOCKED | rust agent | H01 | |
| B02 | READY | backend agent | A02 | Review failed: required health/migration tests missing; allowed path names apps/api, implementation uses apps/backend |
| B03 | BLOCKED | bindings agent | B01 | |
| B04 | BLOCKED | auth agent | B02,A02,H01 | |
| B05 | BLOCKED | sync agent | B02,B04,A02 | |
| C01 | BLOCKED | web agent | B03,B05,C02 | |
| C02 | BLOCKED | sdk agent | A02,B03,B05 | |
| C03 | BLOCKED | extension agent | C01,C02 | |
| Q01 | BLOCKED | QA/security agent | C03 | |
| H02 | BLOCKED | external auditor | Q01 | |
| R01 | BLOCKED | release agent | H02 | |
| D01 | BLOCKED | desktop agent | R01 | |
| D02 | BLOCKED | mobile agent | R01 | |
