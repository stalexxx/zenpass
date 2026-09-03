#![forbid(unsafe_code)]
//! Backend WASM bindings for the server side of the approved OPAQUE-3DH
//! Ristretto255 suite (RFC 9807, ADR-0003), loaded by `apps/backend` under
//! Bun the same way `packages/crypto-worker` loads `packages/crypto-wasm`
//! (ADR-0006). This crate exports no new cryptography: every function is a
//! byte-oriented, mechanical wrapper around an existing
//! `crypto_core::opaque` server-side helper.
//!
//! Registration's two legs (`RegistrationRequest` then `RegistrationUpload`)
//! are distinguished here by their exact fixed serialized length, which
//! differs deterministically for the pinned suite (ADR-0006 §4).
//! Login's two legs are *not* disambiguated this way: the caller (the
//! backend, which tracks whether it already holds pending login state for
//! an account) picks `login_start` or `login_finish` explicitly.

use crypto_core::opaque::{
    server_login_finish, server_login_start, server_login_state, server_registration_finish,
    server_registration_start, ServerSetupHandle,
};
use js_sys::{Object, Reflect};
use wasm_bindgen::prelude::*;
use zeroize::Zeroizing;

fn error(error: crypto_core::Error) -> JsValue {
    JsValue::from_str(match error {
        crypto_core::Error::InvalidEncoding => "InvalidEncoding",
        crypto_core::Error::UnsupportedVersion => "UnsupportedVersion",
        crypto_core::Error::NonCanonicalCbor => "NonCanonicalCbor",
        crypto_core::Error::UnknownField => "UnknownField",
        crypto_core::Error::InvalidContext => "InvalidContext",
        crypto_core::Error::InvalidNonce => "InvalidNonce",
        crypto_core::Error::AuthenticationFailed => "AuthenticationFailed",
        crypto_core::Error::InvalidKdfParameters => "InvalidKdfParameters",
        crypto_core::Error::KdfResourceLimit => "KdfResourceLimit",
        crypto_core::Error::InvalidKeyLength => "InvalidKeyLength",
        crypto_core::Error::InvalidRecoveryKit => "InvalidRecoveryKit",
        crypto_core::Error::Locked => "Locked",
        crypto_core::Error::Internal => "Internal",
    })
}

fn object(entries: &[(&str, JsValue)]) -> Result<JsValue, JsValue> {
    let result = Object::new();
    for (name, value) in entries {
        Reflect::set(&result, &(*name).into(), value).map_err(|_| JsValue::from_str("Internal"))?;
    }
    Ok(result.into())
}

fn bytes(value: &[u8]) -> JsValue {
    js_sys::Uint8Array::from(value).into()
}

/// Generate fresh process-wide server setup material (private key + OPRF
/// seed). Callers persist the returned bytes out-of-band (ADR-0006 §3); this
/// function never stores anything itself.
#[wasm_bindgen]
pub fn generate_server_setup() -> Vec<u8> {
    ServerSetupHandle::generate().serialize().to_vec()
}

/// Run one registration leg. `client_message` is either a fresh
/// `RegistrationRequest` (server has no prior state to consult) or a
/// `RegistrationUpload` finishing a prior request. Returns
/// `{ step: "response", message }` for the first leg (send `message` back to
/// the client) or `{ step: "record", message }` for the second leg (`message`
/// is the opaque credential record to persist in `opaque_credentials`).
///
/// The two legs are distinguished by exact serialized length rather than by
/// trying one and falling back to the other: `RegistrationRequest`'s
/// `deserialize` only validates its own fixed prefix and does not reject
/// trailing bytes, so a `RegistrationUpload` (which is longer) would
/// otherwise also parse successfully as a truncated `RegistrationRequest`.
/// Both lengths are fixed by the pinned ADR-0003 suite (Ristretto255):
/// `RegistrationRequest` serializes to exactly
/// [`REGISTRATION_REQUEST_LEN`] bytes; anything else is treated as the
/// second leg.
const REGISTRATION_REQUEST_LEN: usize = 32;

#[wasm_bindgen]
pub fn registration_step(
    setup: Vec<u8>,
    credential_identifier: String,
    client_message: Vec<u8>,
) -> Result<JsValue, JsValue> {
    let setup = Zeroizing::new(setup);
    let setup = ServerSetupHandle::deserialize(&setup).map_err(error)?;
    if client_message.len() == REGISTRATION_REQUEST_LEN {
        let response =
            server_registration_start(&setup, &client_message, credential_identifier.as_bytes())
                .map_err(error)?;
        return object(&[
            ("step", JsValue::from_str("response")),
            ("message", bytes(&response.message)),
        ]);
    }
    let record = server_registration_finish(&client_message).map_err(error)?;
    object(&[
        ("step", JsValue::from_str("record")),
        ("message", bytes(&record)),
    ])
}

/// Begin server login (KE1 -> KE2). `password_file` is the stored
/// `opaque_credentials.credential_record` for this account; callers must not
/// invoke this without one (ADR-0006 §9: unknown accounts are rejected
/// before reaching this binding, not inside it). Returns
/// `{ message, state }`: `message` is the KE2 challenge for the client,
/// `state` is opaque server login state the caller must hold (e.g. an
/// in-process map keyed by account id, ADR-0006 §6) and pass to
/// `login_finish` unmodified.
#[wasm_bindgen]
pub fn login_start(
    setup: Vec<u8>,
    password_file: Vec<u8>,
    credential_identifier: String,
    ke1: Vec<u8>,
    context: Vec<u8>,
) -> Result<JsValue, JsValue> {
    let setup = Zeroizing::new(setup);
    let setup = ServerSetupHandle::deserialize(&setup).map_err(error)?;
    let result = server_login_start(
        &setup,
        &password_file,
        credential_identifier.as_bytes(),
        &ke1,
        &context,
    )
    .map_err(error)?;
    object(&[
        ("message", bytes(&result.message)),
        ("state", bytes(&result.state_bytes())),
    ])
}

/// Finish server login (KE3). Succeeds only if the client proved knowledge
/// of the registered password against the given `state`; the caller then
/// treats the login as authenticated and issues its own session token (this
/// binding intentionally does not return the OPAQUE session key — the
/// backend's session token is independent, ADR-0005 §1).
#[wasm_bindgen]
pub fn login_finish(state: Vec<u8>, ke3: Vec<u8>, context: Vec<u8>) -> Result<(), JsValue> {
    let state = Zeroizing::new(state);
    let state = server_login_state(&state).map_err(error)?;
    server_login_finish(state, &ke3, &context).map_err(error)?;
    Ok(())
}

/// Test/reference OPAQUE client, exported only so this crate's own test
/// suite (`test/binding.test.ts`) can drive `registration_step`/`login_start`
/// /`login_finish` with a genuine protocol counterpart in the same process.
/// This is **not** the production browser client: the real browser client
/// belongs to a later web-client task (C01/C02) via `packages/crypto-wasm`,
/// per the DAG in `docs/plan/MASTER.md`. No new cryptography here either —
/// same mechanical wrapping as the server-side exports above.
pub mod test_client {
    use super::{bytes, error, object};
    use wasm_bindgen::prelude::*;

    #[wasm_bindgen]
    pub fn client_registration_start(password: Vec<u8>) -> Result<JsValue, JsValue> {
        let result = crypto_core::opaque::client_registration_start(&password).map_err(error)?;
        object(&[
            ("message", bytes(&result.message)),
            ("state", bytes(&result.state_bytes())),
        ])
    }

    #[wasm_bindgen]
    pub fn client_registration_finish(
        state: Vec<u8>,
        password: Vec<u8>,
        response: Vec<u8>,
    ) -> Result<JsValue, JsValue> {
        let state = crypto_core::opaque::client_registration_state(&state).map_err(error)?;
        let result = crypto_core::opaque::client_registration_finish(state, &password, &response)
            .map_err(error)?;
        object(&[("message", bytes(&result.message))])
    }

    #[wasm_bindgen]
    pub fn client_login_start(password: Vec<u8>) -> Result<JsValue, JsValue> {
        let result = crypto_core::opaque::client_login_start(&password).map_err(error)?;
        object(&[
            ("message", bytes(&result.message)),
            ("state", bytes(&result.state_bytes())),
        ])
    }

    #[wasm_bindgen]
    pub fn client_login_finish(
        state: Vec<u8>,
        password: Vec<u8>,
        response: Vec<u8>,
        context: Vec<u8>,
    ) -> Result<JsValue, JsValue> {
        let state = crypto_core::opaque::client_login_state(&state).map_err(error)?;
        let result = crypto_core::opaque::client_login_finish(state, &password, &response, &context)
            .map_err(error)?;
        object(&[("message", bytes(&result.message))])
    }
}

// No `#[cfg(test)]` module here: every exported function returns/consumes
// `wasm_bindgen::JsValue`, which requires an actual JS host and panics under
// native `cargo test` (same reason `packages/crypto-wasm` has no Rust unit
// tests). This binding is exercised end-to-end from the real generated WASM
// module by `test/binding.test.ts` under Bun, and its underlying
// `crypto_core::opaque` functions already carry their own Rust unit tests.
