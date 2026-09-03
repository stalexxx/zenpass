# Dependency policy

Dependencies are added only when they have a clear product or security purpose.
Before adding one, the owning agent must document its purpose, license, maintenance
health, transitive impact, and security alternatives in an ADR under
`docs/decisions/` and obtain integrator approval.

- Lockfiles are committed and CI uses `bun install --frozen-lockfile`.
- Runtime dependencies must use maintained releases and exact or conservative ranges.
- Cryptographic primitives may only be added to the Rust crypto-core after human
  security review; clients must not reimplement them.
- CI runs dependency, secret, and license checks before release.
- Generated dependency artifacts are produced by the integrator only.
