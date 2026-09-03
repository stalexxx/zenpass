# Security decision register

This register is append-only. Tests do not substitute for human approval of
cryptographic or recovery changes; public release additionally requires an
external audit.

| ID | Decision | ADR / status | Reviewer | Evidence | Affected tasks |
|---|---|---|---|---|---|
| SD-0001 | Rust is the sole crypto implementation; clients use WASM/UniFFI | ADR-0001 / approved | Human | Architecture review | A00,B01,B03,C01,C02,C03,D01,D02 |
| SD-0002 | MVP uses client-side encrypted records and optimistic encrypted sync; backend cannot decrypt | ADR-0002 / approved | Human | sync-v1 and contract tests | A02,B02,B05,C02 |
| SD-0003 | Envelope/v1 bytes, key hierarchy, KDF/AEAD parameters, and recovery authorization await approval | ADR-0003 / pending H01 | Pending | crypto-envelope/v1, A04 vectors, H01-REVIEW-CHECKLIST.md, ADR-0003 (unsigned draft) | A04,H01,B01,B03,B04 |
| SD-0004 | Loss of both master password and recovery key is irreversible; support has no bypass | Recovery decision / approved in principle | Human | RECOVERY.md and T14 tests | A01,A03,A04,B04,C01,Q01 |
| SD-0005 | Metadata leakage is minimized, not zero; budget and retention require approval | ADR-0004 / open (unsigned draft) | Pending | T11 verification and metadata inventory; `docs/decisions/ADR-0004-metadata-leakage-budget-retention.md` (unsigned draft, decisions pending) | A01,A02,B02,B05,Q01,R01 |
| SD-0006 | Public release is blocked by unresolved Critical/High findings and requires external audit | Release gate / approved | Human | MASTER.md and Q01/H02 evidence | Q01,H02,R01 |

## Change procedure

1. Add a new append-only row and ADR; do not edit an approved decision in place.
2. List impacted contracts, tasks, threat IDs, migration/rollback implications,
   and verification evidence.
3. Obtain human security approval for crypto, authentication, recovery,
   plaintext-boundary, or trust-boundary changes.
4. Return affected tasks to READY when a contract changes; the integrator owns
   merge and status transitions.
