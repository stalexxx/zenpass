//! D02-MVP: mechanical UniFFI bindings-generator entry point (library mode).
//! Run with e.g.:
//!   cargo run --bin uniffi-bindgen -- generate --library \
//!     target/aarch64-linux-android/release/libcrypto_ffi.so \
//!     --language kotlin --out-dir <out>
fn main() {
    uniffi::uniffi_bindgen_main()
}
