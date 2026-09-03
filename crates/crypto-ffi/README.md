# crypto-ffi

UniFFI boundary for future native clients. `ItemSession` is an opaque,
in-memory capability: it generates and owns the key internally, returns only
envelope/plaintext bytes, and becomes unusable after `close`. It has no raw-key
import/export API.
