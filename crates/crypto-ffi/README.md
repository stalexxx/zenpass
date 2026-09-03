# crypto-ffi

UniFFI boundary for future native clients. `ItemSession::unlock` takes a
password plus canonical KDF parameters and encrypted account/vault/item
wrappers, then unwraps the full hierarchy inside Rust. It returns an opaque,
in-memory capability that becomes unusable after `close`; it has no raw-key
import/export API.
