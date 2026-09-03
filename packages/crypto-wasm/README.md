# crypto-wasm

`bun run build:wasm` compiles `src/lib.rs` for `wasm32-unknown-unknown` and
uses pinned `wasm-bindgen` to emit the checked-in `pkg/` module and declaration
file. `bun test` rebuilds and imports that actual browser WASM module.

The current browser export is deliberately metadata/AAD-only. A persisted
password/OPAQUE-to-item capability requires an authenticated OPAQUE transport
and a serialized wrapper-record ownership contract; B04 currently has neither
binding nor endpoint contract. Do not add raw-key APIs as a workaround.
