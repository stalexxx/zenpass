# RUST-04 candidate container for `zkpm-backend` (apps/backend-rust). This is
# a separate, parallel image from the existing Bun `infra/Dockerfile` — it
# does not replace it and is not referenced by any production compose file.
# It exists so a human can build, scan, and rehearse the Rust backend as a
# concrete deployable artifact before any cutover decision.
#
# Pinned base images (update deliberately, not opportunistically; record the
# new digest in docs/plan/reports/RUST-04.md and this comment when bumped):
#   builder: rust:1.93.1-slim-bookworm  — matches apps/backend-rust/rust-toolchain.toml exactly.
#   runtime: debian:bookworm-slim       — glibc runtime, matches builder's glibc ABI.
# Pin by tag here (Debian point releases are frequent); CI additionally
# resolves and records the immutable sha256 digest for the exact image that
# was built and tested (see .github/workflows/rust-backend.yml).

# ---- builder -----------------------------------------------------------
FROM rust:1.93.1-slim-bookworm AS builder
WORKDIR /build

# Only what --locked compile-time SQLx macros and crypto-core's native
# dependencies need; no network access at query-check time (SQLX_OFFLINE=1
# uses the committed apps/backend-rust/.sqlx metadata).
RUN apt-get update && apt-get install -y --no-install-recommends \
    pkg-config \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Bring in the whole repository root: apps/backend-rust depends on
# crates/crypto-core via a path dependency, and its own Cargo.lock pins the
# exact resolution used by every prior RUST task's CI. Copying the full
# workspace root (not just apps/backend-rust) keeps that path dependency
# resolvable without inventing a vendoring step.
COPY Cargo.toml Cargo.lock ./
COPY crates ./crates
COPY apps/backend-rust ./apps/backend-rust

WORKDIR /build/apps/backend-rust
ENV SQLX_OFFLINE=true
RUN cargo build --release --locked --bin zkpm-backend

# ---- runtime -------------------------------------------------------------
FROM debian:bookworm-slim AS runtime

# CA certificates for the SQLx rustls Postgres TLS backend (production
# requires ZKPM_DATABASE_TLS=verify-full, see apps/backend-rust/src/config.rs)
# and any outbound TLS. No other packages: no shell utilities beyond what
# Debian slim already carries, no package manager cache left behind.
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd --system --gid 10001 zkpm \
    && useradd --system --uid 10001 --gid zkpm --no-create-home --shell /usr/sbin/nologin zkpm

COPY --from=builder /build/apps/backend-rust/target/release/zkpm-backend /usr/local/bin/zkpm-backend
# No separate migrations directory is copied: `src/migrate.rs` embeds
# `migrations/` at compile time via `sqlx::migrate!("./migrations")`, so the
# `migrate` subcommand needs no filesystem access to SQL files at runtime.

WORKDIR /app
USER zkpm:zkpm

# No ports EXPOSEd implicitly beyond documentation; ZKPM_BIND controls the
# actual listen address/port (default 127.0.0.1:8080, overridden to
# 0.0.0.0:8080 only inside the private compose network — see the runbook).
EXPOSE 8080

ENTRYPOINT ["/usr/local/bin/zkpm-backend"]
CMD ["serve"]
