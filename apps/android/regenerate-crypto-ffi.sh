#!/usr/bin/env bash
# D02-MVP: regenerate the vendored `crypto-ffi` JNI artifacts under
# apps/android/app/src/main/{jniLibs,kotlin/uniffi}. Run this after any
# change to crates/crypto-ffi/src/lib.rs.
#
# Requires: `rustup target add aarch64-linux-android`, the Android NDK at
# $ANDROID_HOME/ndk/27.1.12297006 (matching crates/crypto-ffi/.cargo/config.toml's
# hardcoded linker paths), and a host Rust toolchain to run the bindgen
# binary itself (built for aarch64-apple-darwin on this dev machine).
set -euo pipefail
cd "$(dirname "$0")/../.."   # repo root (this script lives in apps/android)

cd crates/crypto-ffi
cargo build --release --target aarch64-linux-android
cargo build --release --bin uniffi-bindgen --target aarch64-apple-darwin

OUT_DIR="$(mktemp -d)"
../../target/aarch64-apple-darwin/release/uniffi-bindgen generate \
  --library ../../target/aarch64-linux-android/release/libcrypto_ffi.so \
  --language kotlin --out-dir "$OUT_DIR" --no-format

cd ../..
mkdir -p apps/android/app/src/main/jniLibs/arm64-v8a
cp target/aarch64-linux-android/release/libcrypto_ffi.so \
  apps/android/app/src/main/jniLibs/arm64-v8a/libcrypto_ffi.so
cp "$OUT_DIR/uniffi/crypto_ffi/crypto_ffi.kt" \
  apps/android/app/src/main/kotlin/uniffi/crypto_ffi/crypto_ffi.kt

echo "Regenerated crypto-ffi JNI lib and Kotlin bindings."
