# crypto-wasm

Safe TypeScript facade for generated `crypto-envelope/v1` WASM exports. Create
an opaque item session, use it for payload operations, and call `closeSession`
when the vault locks. Raw keys are intentionally not part of this package's
types or API; use it through `crypto-worker` from UI code.
