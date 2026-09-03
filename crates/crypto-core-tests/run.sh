#!/bin/sh
# B01 test invocation mechanism (allowed paths only).
#
# The root workspace manifest is frozen for B01, so the fixture/property/
# fuzz test crate intentionally lives as a standalone workspace under
# crates/crypto-core-tests/. This script runs the complete B01 verification
# suite: the root workspace (crypto-core unit tests) followed by the
# standalone B01 test workspace (fixtures, property, fuzz smoke), plus
# fmt/clippy gates for both. It exists so CI and the integrator have one
# explicit command that cannot silently skip the B01 tests.
set -eu

repo_root=$(cd "$(dirname "$0")/../.." && pwd)

echo "== root workspace: crypto-core =="
cd "$repo_root"
cargo test --workspace
cargo fmt --check
cargo clippy --workspace --all-targets -- -D warnings

echo "== B01 standalone test workspace: crypto-core-tests =="
cd "$repo_root/crates/crypto-core-tests"
cargo test --workspace
cargo fmt --check
cargo clippy --workspace --all-targets -- -D warnings

echo "B01 verification complete"
