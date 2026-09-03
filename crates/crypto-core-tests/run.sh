#!/bin/sh
# B01 test invocation mechanism (allowed paths only).
#
# The root workspace manifest and root Cargo.lock are frozen for B01, and
# running unlocked root-workspace cargo commands would regenerate the
# forbidden lockfile. B01 verification therefore runs entirely inside this
# standalone test workspace (which builds crypto-core from its allowed path
# and runs the fixture, property, and fuzz-smoke suites).
#
# crypto-core's in-crate unit tests require the root workspace lockfile to
# carry the pinned dependency closure; that regeneration is owned by the
# integrator at merge time (see the B01 completion report). Once the
# integrator has committed the regenerated root lockfile, the root workspace
# checks (`cargo test --workspace`, fmt, clippy) apply unchanged.
set -eu

cd "$(dirname "$0")"

echo "== B01 standalone test workspace: crypto-core-tests =="
cargo test --workspace
cargo fmt --check
cargo clippy --workspace --all-targets -- -D warnings

echo "B01 verification complete"
