//! OPAQUE helper API over the RFC 9807 implementation approved in
//! ADR-0003 (`opaque-ke` 4.0.1, vetted Ristretto255 profile: OPRF mode
//! ristretto255-SHA512, 3DH key exchange, SHA-512, Identity KSF, standard
//! transcript and envelope encodings).
//!
//! This module is a thin boundary: it fixes the approved suite, exposes
//! byte-oriented registration/login flows for the future WASM/UniFFI
//! bindings (B03/B04), and collapses every protocol failure into the
//! contract's generic [`Error::AuthenticationFailed`] so no UI can
//! distinguish a wrong password from tampered server material. Transport
//! decoding failures of locally stored state are [`Error::InvalidEncoding`];
//! failures to decode remote protocol messages are the generic
//! [`Error::AuthenticationFailed`] so tampering is indistinguishable from a
//! wrong password.
//!
//! The KSF is `Identity` because password stretching for unlock is performed
//! by the Argon2id wrapper ([`crate::kdf`]) on the client; server-side KSF
//! relief is out of scope for v1. Changing the suite requires H01
//! re-approval.

use opaque_ke::{
    CipherSuite, ClientLogin, ClientRegistration, CredentialFinalization, CredentialRequest,
    CredentialResponse, RegistrationRequest, RegistrationResponse, RegistrationUpload, ServerLogin,
    ServerRegistration, ServerSetup,
};
use rand::rngs::OsRng;
use sha2::Sha512;
use zeroize::Zeroizing;

use crate::error::Error;

/// The approved OPAQUE-3DH ristretto255-SHA512 suite (RFC 9807).
pub struct OpaqueSuite;

impl CipherSuite for OpaqueSuite {
    type OprfCs = opaque_ke::Ristretto255;
    type KeyExchange = opaque_ke::TripleDh<opaque_ke::Ristretto255, Sha512>;
    type Ksf = opaque_ke::ksf::Identity;
}

type ServerSetupKey = ServerSetup<OpaqueSuite>;
/// A zeroized secret buffer (session/export key material).
type SessionMaterial = Zeroizing<Vec<u8>>;

macro_rules! redacted_debug {
    ($($t:ty),* $(,)?) => {
        $(
            impl std::fmt::Debug for $t {
                fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                    f.write_str(concat!(stringify!($t), "(redacted)"))
                }
            }
        )*
    };
}

redacted_debug!(
    ClientRegistrationStartResult,
    ServerRegistrationStartResult,
    ClientRegistrationFinishResult,
    ClientLoginStartResult,
    ServerLoginStartResult,
    ClientLoginFinishResult,
    ServerLoginFinishResult,
    ServerSetupHandle,
);

fn auth<E>(_e: E) -> Error {
    Error::AuthenticationFailed
}

/// Client state between registration start and finish. Serialize opaquely
/// with [`ClientRegistrationStartResult::state_bytes`].
pub struct ClientRegistrationStartResult {
    /// The `RegistrationRequest` message bytes to send to the server.
    pub message: Vec<u8>,
    state: ClientRegistration<OpaqueSuite>,
}

impl ClientRegistrationStartResult {
    /// Opaque client-state bytes; required to finish registration later.
    #[must_use]
    pub fn state_bytes(&self) -> Vec<u8> {
        self.state.serialize().to_vec()
    }
}

/// Server-side setup material (keypair + OPRF seed).
pub struct ServerSetupHandle(ServerSetupKey);

impl ServerSetupHandle {
    /// Generate a fresh server setup.
    #[must_use]
    pub fn generate() -> Self {
        Self(ServerSetup::<OpaqueSuite>::new(&mut OsRng))
    }

    /// Serialized form for at-rest storage.
    #[must_use]
    pub fn serialize(&self) -> Vec<u8> {
        self.0.serialize().to_vec()
    }

    /// Restore from serialized form.
    pub fn deserialize(bytes: &[u8]) -> Result<Self, Error> {
        Ok(Self(
            ServerSetup::<OpaqueSuite>::deserialize(bytes).map_err(|_| Error::InvalidEncoding)?,
        ))
    }
}

/// Result of the server's registration start.
pub struct ServerRegistrationStartResult {
    /// The `RegistrationResponse` message bytes for the client.
    pub message: Vec<u8>,
}

/// Result of the client's registration finish.
pub struct ClientRegistrationFinishResult {
    /// The `RegistrationUpload` message bytes for the server.
    pub message: Vec<u8>,
    /// Client-side export key (zeroized on drop).
    pub export_key: Zeroizing<Vec<u8>>,
}

/// Result of the client's login start.
pub struct ClientLoginStartResult {
    /// The `KE1` message bytes for the server.
    pub message: Vec<u8>,
    state: ClientLogin<OpaqueSuite>,
}

impl ClientLoginStartResult {
    /// Opaque client-state bytes; required to finish login later.
    #[must_use]
    pub fn state_bytes(&self) -> Vec<u8> {
        self.state.serialize().to_vec()
    }
}

/// Result of the server's login start.
pub struct ServerLoginStartResult {
    /// The `KE2` message bytes for the client.
    pub message: Vec<u8>,
    state: ServerLogin<OpaqueSuite>,
}

impl ServerLoginStartResult {
    /// Opaque server-state bytes; required to finish login later.
    #[must_use]
    pub fn state_bytes(&self) -> Vec<u8> {
        self.state.serialize().to_vec()
    }
}

/// Result of the client's login finish.
pub struct ClientLoginFinishResult {
    /// The `KE3` message bytes for the server.
    pub message: Vec<u8>,
    /// Session key shared with the server (zeroized on drop).
    pub session_key: Zeroizing<Vec<u8>>,
    /// Export key (zeroized on drop).
    pub export_key: Zeroizing<Vec<u8>>,
}

/// Result of the server's login finish.
pub struct ServerLoginFinishResult {
    /// Session key shared with the client (zeroized on drop).
    pub session_key: Zeroizing<Vec<u8>>,
}

/// Begin client registration with a password.
pub fn client_registration_start(password: &[u8]) -> Result<ClientRegistrationStartResult, Error> {
    let result = ClientRegistration::<OpaqueSuite>::start(&mut OsRng, password).map_err(auth)?;
    Ok(ClientRegistrationStartResult {
        message: result.message.serialize().to_vec(),
        state: result.state,
    })
}

/// Restore client registration state produced by
/// [`client_registration_start`].
pub fn client_registration_state(bytes: &[u8]) -> Result<ClientRegistration<OpaqueSuite>, Error> {
    ClientRegistration::<OpaqueSuite>::deserialize(bytes).map_err(|_| Error::InvalidEncoding)
}

/// Produce the server's registration response.
pub fn server_registration_start(
    setup: &ServerSetupHandle,
    request: &[u8],
    credential_identifier: &[u8],
) -> Result<ServerRegistrationStartResult, Error> {
    let request = RegistrationRequest::<OpaqueSuite>::deserialize(request).map_err(auth)?;
    let result = ServerRegistration::<OpaqueSuite>::start(&setup.0, request, credential_identifier)
        .map_err(auth)?;
    Ok(ServerRegistrationStartResult {
        message: result.message.serialize().to_vec(),
    })
}

/// Finish client registration, producing the upload message.
pub fn client_registration_finish(
    state: ClientRegistration<OpaqueSuite>,
    password: &[u8],
    response: &[u8],
) -> Result<ClientRegistrationFinishResult, Error> {
    let response = RegistrationResponse::<OpaqueSuite>::deserialize(response).map_err(auth)?;
    let result = state
        .finish(
            &mut OsRng,
            password,
            response,
            opaque_ke::ClientRegistrationFinishParameters::new(
                Default::default(),
                Some(&opaque_ke::ksf::Identity),
            ),
        )
        .map_err(auth)?;
    Ok(ClientRegistrationFinishResult {
        message: result.message.serialize().to_vec(),
        export_key: Zeroizing::new(result.export_key.to_vec()),
    })
}

/// Persist the server-side password file from the upload message.
pub fn server_registration_finish(upload: &[u8]) -> Result<Vec<u8>, Error> {
    let upload = RegistrationUpload::<OpaqueSuite>::deserialize(upload).map_err(auth)?;
    Ok(ServerRegistration::<OpaqueSuite>::finish(upload)
        .serialize()
        .to_vec())
}

/// Begin client login with a password.
pub fn client_login_start(password: &[u8]) -> Result<ClientLoginStartResult, Error> {
    let result = ClientLogin::<OpaqueSuite>::start(&mut OsRng, password).map_err(auth)?;
    Ok(ClientLoginStartResult {
        message: result.message.serialize().to_vec(),
        state: result.state,
    })
}

/// Restore client login state produced by [`client_login_start`].
pub fn client_login_state(bytes: &[u8]) -> Result<ClientLogin<OpaqueSuite>, Error> {
    ClientLogin::<OpaqueSuite>::deserialize(bytes).map_err(|_| Error::InvalidEncoding)
}

/// Produce the server's KE2 challenge.
pub fn server_login_start(
    setup: &ServerSetupHandle,
    password_file: &[u8],
    credential_identifier: &[u8],
    ke1: &[u8],
    context: &[u8],
) -> Result<ServerLoginStartResult, Error> {
    let file = ServerRegistration::<OpaqueSuite>::deserialize(password_file).map_err(auth)?;
    let request = CredentialRequest::<OpaqueSuite>::deserialize(ke1).map_err(auth)?;
    let result = ServerLogin::<OpaqueSuite>::start(
        &mut OsRng,
        &setup.0,
        Some(file),
        request,
        credential_identifier,
        opaque_ke::ServerLoginParameters {
            context: Some(context),
            identifiers: Default::default(),
        },
    )
    .map_err(auth)?;
    Ok(ServerLoginStartResult {
        message: result.message.serialize().to_vec(),
        state: result.state,
    })
}

/// Restore server login state produced by [`server_login_start`].
pub fn server_login_state(bytes: &[u8]) -> Result<ServerLogin<OpaqueSuite>, Error> {
    ServerLogin::<OpaqueSuite>::deserialize(bytes).map_err(|_| Error::InvalidEncoding)
}

/// Finish client login: verify KE2, produce KE3 and session material.
///
/// Context substitution (a different `context` than the server used) fails
/// with the generic authentication error.
pub fn client_login_finish(
    state: ClientLogin<OpaqueSuite>,
    password: &[u8],
    response: &[u8],
    context: &[u8],
) -> Result<ClientLoginFinishResult, Error> {
    let response = CredentialResponse::<OpaqueSuite>::deserialize(response).map_err(auth)?;
    let result = state
        .finish(
            &mut OsRng,
            password,
            response,
            opaque_ke::ClientLoginFinishParameters::new(
                Some(context),
                Default::default(),
                Some(&opaque_ke::ksf::Identity),
            ),
        )
        .map_err(auth)?;
    Ok(ClientLoginFinishResult {
        message: result.message.serialize().to_vec(),
        session_key: Zeroizing::new(result.session_key.to_vec()),
        export_key: Zeroizing::new(result.export_key.to_vec()),
    })
}

/// Finish server login: verify KE3 and produce the session key.
pub fn server_login_finish(
    state: ServerLogin<OpaqueSuite>,
    ke3: &[u8],
    context: &[u8],
) -> Result<ServerLoginFinishResult, Error> {
    let ke3 = CredentialFinalization::<OpaqueSuite>::deserialize(ke3).map_err(auth)?;
    let result = state
        .finish(
            ke3,
            opaque_ke::ServerLoginParameters {
                context: Some(context),
                identifiers: Default::default(),
            },
        )
        .map_err(auth)?;
    Ok(ServerLoginFinishResult {
        session_key: Zeroizing::new(result.session_key.to_vec()),
    })
}

/// Run a full registration followed by a full login in-process.
///
/// Test and binding-smoke helper: performs the complete approved-suite
/// transcript and returns (session_key, client_export_key) on success.
pub fn round_trip(
    password: &[u8],
    context: &[u8],
) -> Result<(SessionMaterial, SessionMaterial), Error> {
    let setup = ServerSetupHandle::generate();
    let credential_identifier = b"credential-identifier";

    let reg = client_registration_start(password)?;
    let server_reg = server_registration_start(&setup, &reg.message, credential_identifier)?;
    let reg_finish = client_registration_finish(
        client_registration_state(&reg.state_bytes())?,
        password,
        &server_reg.message,
    )?;
    let password_file = server_registration_finish(&reg_finish.message)?;

    let login = client_login_start(password)?;
    let server_login = server_login_start(
        &setup,
        &password_file,
        credential_identifier,
        &login.message,
        context,
    )?;
    let client_finish = client_login_finish(
        client_login_state(&login.state_bytes())?,
        password,
        &server_login.message,
        context,
    )?;
    let server_finish = server_login_finish(
        server_login_state(&server_login.state_bytes())?,
        &client_finish.message,
        context,
    )?;

    if client_finish.session_key.as_slice() != server_finish.session_key.as_slice() {
        return Err(Error::AuthenticationFailed);
    }
    Ok((client_finish.session_key, client_finish.export_key))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn registration_and_login_round_trip_succeeds() {
        let (client_sk, client_ek) = round_trip(b"CorrectHorseBatteryStaple", b"ctx").unwrap();
        assert_eq!(client_sk.len(), 64);
        assert_eq!(client_ek.len(), 64);
    }

    #[test]
    fn wrong_password_fails_generically() {
        let setup = ServerSetupHandle::generate();
        let id = b"credential-identifier";
        let password = b"CorrectHorseBatteryStaple";
        let reg = client_registration_start(password).unwrap();
        let sr = server_registration_start(&setup, &reg.message, id).unwrap();
        let rf = client_registration_finish(
            client_registration_state(&reg.state_bytes()).unwrap(),
            password,
            &sr.message,
        )
        .unwrap();
        let file = server_registration_finish(&rf.message).unwrap();

        let login = client_login_start(b"WrongHorseBatteryStaple").unwrap();
        let ke2 = server_login_start(&setup, &file, id, &login.message, b"ctx")
            .unwrap()
            .message;
        assert_eq!(
            client_login_finish(
                client_login_state(&login.state_bytes()).unwrap(),
                b"WrongHorseBatteryStaple",
                &ke2,
                b"ctx",
            )
            .unwrap_err(),
            Error::AuthenticationFailed
        );
    }

    #[test]
    fn tampered_ke2_fails_generically() {
        let setup = ServerSetupHandle::generate();
        let id = b"credential-identifier";
        let reg = client_registration_start(b"CorrectHorseBatteryStaple").unwrap();
        let sr = server_registration_start(&setup, &reg.message, id).unwrap();
        let rf = client_registration_finish(
            client_registration_state(&reg.state_bytes()).unwrap(),
            b"CorrectHorseBatteryStaple",
            &sr.message,
        )
        .unwrap();
        let file = server_registration_finish(&rf.message).unwrap();

        let login = client_login_start(b"CorrectHorseBatteryStaple").unwrap();
        let mut ke2 = server_login_start(&setup, &file, id, &login.message, b"ctx")
            .unwrap()
            .message;
        ke2[0] ^= 0x01;
        assert_eq!(
            client_login_finish(
                client_login_state(&login.state_bytes()).unwrap(),
                b"CorrectHorseBatteryStaple",
                &ke2,
                b"ctx",
            )
            .unwrap_err(),
            Error::AuthenticationFailed
        );
    }

    #[test]
    fn context_substitution_fails_generically() {
        let setup = ServerSetupHandle::generate();
        let id = b"credential-identifier";
        let reg = client_registration_start(b"CorrectHorseBatteryStaple").unwrap();
        let sr = server_registration_start(&setup, &reg.message, id).unwrap();
        let rf = client_registration_finish(
            client_registration_state(&reg.state_bytes()).unwrap(),
            b"CorrectHorseBatteryStaple",
            &sr.message,
        )
        .unwrap();
        let file = server_registration_finish(&rf.message).unwrap();

        let login = client_login_start(b"CorrectHorseBatteryStaple").unwrap();
        let ke2 = server_login_start(&setup, &file, id, &login.message, b"OPAQUE-POC")
            .unwrap()
            .message;
        assert_eq!(
            client_login_finish(
                client_login_state(&login.state_bytes()).unwrap(),
                b"CorrectHorseBatteryStaple",
                &ke2,
                b"OPAQUE-TEST",
            )
            .unwrap_err(),
            Error::AuthenticationFailed
        );
    }

    #[test]
    fn corrupt_state_bytes_are_invalid_encoding() {
        assert_eq!(
            client_registration_state(&[0u8; 8]).unwrap_err(),
            Error::InvalidEncoding
        );
        assert_eq!(
            client_login_state(&[0u8; 8]).unwrap_err(),
            Error::InvalidEncoding
        );
    }

    #[test]
    fn corrupt_remote_messages_are_generic_auth_failures() {
        assert_eq!(
            server_registration_finish(&[0u8; 8]).unwrap_err(),
            Error::AuthenticationFailed
        );
        let setup = ServerSetupHandle::generate();
        assert_eq!(
            server_registration_start(&setup, &[0u8; 8], b"id").unwrap_err(),
            Error::AuthenticationFailed
        );
    }
}
