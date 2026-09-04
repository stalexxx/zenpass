# Q01 findings register

| ID | Severity | Finding | Owner | Disposition |
|---|---|---|---|---|
| Q01-001 | High | No external security audit evidence exists for crypto-core, authentication/recovery, sync anti-rollback, and build supply chain. `MASTER.md` and SD-0006 require it before public release. | H02 / human security reviewer | Open — blocks H02 and R01 until audit findings are remediated or formally accepted. |
| Q01-002 | Medium | Metadata leakage budget, backup retention, and user disclosure remain unsigned in ADR-0004 (SD-0005). Automated dump inspection cannot select or approve those policy values. | Human security reviewer / R01 | Open — release decision required. |
| Q01-003 | Medium | The dependency-light SAST and secret scanner is a baseline, not a substitute for a maintained SAST, secret-scanning, license, or SBOM attestation service. | R01 release owner | Open — select and retain production scanning evidence before public release. |
