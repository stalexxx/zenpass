# H02 residual-risk acceptance

Date: 2026-09-04

## Decision

The release owner accepted Q01-001 through Q01-003 as residual risks for a
personal/internal deployment only. This is not external audit evidence, does
not close H02 for a public release, and does not authorize relaxing any
cryptographic or zero-knowledge guarantees.

## Scope and conditions

| Finding | Accepted scope | Condition before public release |
|---|---|---|
| Q01-001 | No independent external audit evidence | Obtain an independent audit covering crypto-core, OPAQUE, recovery, sync anti-rollback, extension isolation, and supply chain; remediate or formally accept its findings. |
| Q01-002 | Metadata, backup-retention, and disclosure policies are not signed | Approve and publish the policy values in the relevant ADR/runbooks. |
| Q01-003 | Dependency-light local SAST/secret/SBOM checks only | Add maintained vulnerability, secret, license, and SBOM attestation evidence to CI and retain it with the release. |

## Evidence available for the internal deployment

- `cargo build --workspace` and `cargo test --workspace` passed (64 tests).
- Two-device offline/reconnect E2E passed with PostgreSQL and WASM OPAQUE.
- Q01 secret scan, dynamic-evaluation guard, SBOM-input check, and PostgreSQL
  16 dump inspection passed.

## Non-acceptance

This decision does not accept a Critical vulnerability, a protocol defect, or
plaintext-vault exposure. Discovery of any of those conditions blocks the
deployment until remediated or separately reviewed by a human security owner.
