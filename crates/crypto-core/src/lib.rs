#![forbid(unsafe_code)]

//! Foundation boundary for the Rust-only cryptographic core.
//!
//! Protocol implementation is intentionally deferred until A04 and H01 approve
//! the byte-level contract. Client applications must depend on this crate through
//! its future WASM/UniFFI bindings and must not implement primitives themselves.

/// Returns the protocol implementation status for health checks and scaffolding.
pub const fn protocol_status() -> &'static str {
    "pending-a04-h01"
}

#[cfg(test)]
mod tests {
    use super::protocol_status;

    #[test]
    fn foundation_is_explicitly_unimplemented() {
        assert_eq!(protocol_status(), "pending-a04-h01");
    }
}
