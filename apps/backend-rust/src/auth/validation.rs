//! SEC-07: shared request-shape validation for the OPAQUE auth routes.
//! Ported unchanged from the Bun reference's `auth/validation.mjs`.

/// Matches `accounts.account_id varchar(128)` and the web client's own
/// generated identifiers, while staying permissive enough for other
/// bounded, opaque client-chosen identifiers. Never used to distinguish a
/// malformed account id from an unknown-but-well-formed one in the response
/// shape.
pub fn is_valid_account_id(account_id: &str) -> bool {
    !account_id.is_empty()
        && account_id.len() <= 128
        && account_id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_bounded_identifiers() {
        assert!(is_valid_account_id("acct-1234"));
        assert!(is_valid_account_id(&"a".repeat(128)));
    }

    #[test]
    fn rejects_empty_and_oversized() {
        assert!(!is_valid_account_id(""));
        assert!(!is_valid_account_id(&"a".repeat(129)));
    }

    #[test]
    fn rejects_disallowed_characters() {
        assert!(!is_valid_account_id("acct/1"));
        assert!(!is_valid_account_id("acct 1"));
    }
}
