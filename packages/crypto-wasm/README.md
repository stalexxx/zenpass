# crypto-wasm

`bun run build:wasm` installs the pinned `wasm-bindgen-cli` 0.2.108 under the
package-local ignored `.tools/`, compiles `src/lib.rs` for
`wasm32-unknown-unknown`, and emits the checked-in `pkg/` module/declaration.
`bun test` rebuilds and imports that actual browser WASM module.

The current browser export is deliberately metadata/AAD-only. A persisted
password/OPAQUE-to-item capability requires an authenticated OPAQUE transport
and a serialized wrapper-record ownership contract; B04 currently has neither
binding nor endpoint contract. Do not add raw-key APIs as a workaround.
