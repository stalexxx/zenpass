# ADR-0001: Cross-platform stack

## Decision

Use TypeScript for web, backend, extension, shared SDK, and React Native; use Rust as the sole crypto implementation, compiled to WASM and UniFFI; use Tauri for desktop; use PostgreSQL and managed EU cloud services.

## Rationale

This maximizes shared domain code while keeping security-sensitive primitives in one auditable implementation and leaves a migration path to native clients.

## Consequences

WASM memory handling, native binding release engineering, and separate browser packaging are mandatory. No client may reimplement KDF or AEAD.

