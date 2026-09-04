# Q01 release-gate report

Status: **automated evidence complete for personal/internal use; external evidence remains required for public release.**

| Gate | Evidence command | Automated scope | Current disposition |
|---|---|---|---|
| Two-device offline/reconnect | `Q01_E2E=1 TEST_DATABASE_URL=... bun run test:e2e` | Real HTTP, PostgreSQL, WASM OPAQUE, queued offline mutation, reconnect, cross-device pull, tombstone replay | Ready to run in CI |
| Dump inspection | `Q01_DUMP_INSPECTION=1 TEST_DATABASE_URL=... bun run test:security` | `pg_dump` schema/data inspection and explicitly supplied test-only forbidden terms | Ready to run in CI; production terms require operator input |
| Backup restore | `Q01_BACKUP_RESTORE=1 TEST_DATABASE_URL=... bun run test:security` | `pg_dump` custom archive to isolated temporary database; verifies opaque bytes, revision, and tombstone | Ready to run in CI; requires a PostgreSQL role permitted to create/drop the isolated database |
| SAST / secret scan | `bun run test:security` | Dynamic-evaluation and high-confidence private-key/live-token signatures in production sources | Automated baseline only |
| SBOM input | `bun run test:security` | Resolves and validates Bun's complete workspace dependency graph | Automated baseline only |
| Dependency vulnerabilities | `bun audit` | Bun advisory database scan | Required CI gate |
| Fuzzing / external audit | Human-owned evidence | Not implemented by this dependency-light harness | Blocking finding Q01-001 |

The harness is deliberately gated. Without `Q01_E2E=1`, `Q01_DUMP_INSPECTION=1`, or `Q01_BACKUP_RESTORE=1`, the infrastructure-dependent tests are reported as skipped. If a gate is explicitly enabled without `TEST_DATABASE_URL`, a configuration test fails clearly. It never creates, logs, or stores plaintext vault data, keys, passwords, or TOTP values.

`pg_dump` must be the same major version as, or newer than, the target server. Set `Q01_PG_DUMP` and `Q01_PG_RESTORE` to explicit compatible client paths when the shell defaults are older; CI installs PostgreSQL 16 client tools for the PostgreSQL 16 service.

`C04` hostile-extension E2E is excluded from this MVP gate and remains a post-R01 follow-on task.
