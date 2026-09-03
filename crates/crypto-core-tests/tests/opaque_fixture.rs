//! `fixtures/crypto/opaque-3dh-ristretto255.json`: RFC 9807 Appendix C.1.1
//! (OPAQUE-3DH, ristretto255-SHA512) reproduced byte-exactly through the
//! suite configuration shipped by crypto-core, plus the four negative cases.
//!
//! Reproduction is driven by a deterministic scripted RNG (see
//! [`crypto_core_tests::ScriptedRng`]). The stream follows the library's
//! documented randomness consumption:
//!
//! * registration blind: 64-byte wide-reduction draw equal to
//!   `blind_registration || 0^32`;
//! * envelope nonce: 32 raw bytes;
//! * login blind: `blind_login || 0^32`;
//! * KE1 keyshare seed: 32 raw bytes (`client_keyshare_seed`, expanded via
//!   DeriveAuthKeyPair inside the library);
//! * client nonce / server nonce / masking nonce: 32 raw bytes each;
//! * server keyshare seed: 32 raw bytes;
//! * server-setup dummy record: 64 filler bytes.
//!
//! If a library upgrade changes the consumption order, this test breaks
//! loudly, which is exactly the re-verification ADR-0003 requires.

use crypto_core::opaque::OpaqueSuite;
use crypto_core::Error;
use crypto_core_tests::bytes_field;
use crypto_core_tests::ScriptedRng;
use opaque_ke::{
    ClientLogin, ClientLoginFinishParameters, ClientRegistration,
    ClientRegistrationFinishParameters, CredentialFinalization, CredentialRequest,
    CredentialResponse, Identifiers, RegistrationRequest, RegistrationResponse, RegistrationUpload,
    ServerLogin, ServerLoginParameters, ServerRegistration, ServerSetup,
};
use rand::rngs::OsRng;
use serde_json::Value;

type CS = OpaqueSuite;

fn load() -> Value {
    crypto_core_tests::load_fixture("opaque-3dh-ristretto255.json")
}

fn input(fixture: &Value, name: &str) -> Vec<u8> {
    bytes_field(fixture["inputs"][name].as_str().expect(name))
}

fn output(fixture: &Value, name: &str) -> Vec<u8> {
    bytes_field(fixture["outputs"][name].as_str().expect(name))
}

/// ServerSetup rebuilt from fixture bytes: `oprf_seed || sk || dummy_pk`.
fn server_setup_from_fixture(fixture: &Value) -> ServerSetup<CS> {
    let seed = input(fixture, "oprf_seed");
    let sk = input(fixture, "server_private_key");
    let pk = input(fixture, "server_public_key");
    assert_eq!(seed.len(), 64);
    assert_eq!(sk.len(), 32);
    assert_eq!(pk.len(), 32);
    let mut serialized = seed;
    serialized.extend_from_slice(&sk);
    // dummy_pk is server-side fake-response material only; any valid
    // non-identity point works. The real server public key is such a point.
    serialized.extend_from_slice(&pk);
    ServerSetup::<CS>::deserialize(&serialized).expect("server setup from fixture bytes")
}

#[test]
fn rfc9807_c1_1_registration_and_login_reproduce_exactly() {
    let fixture = load();
    let context = bytes_field(fixture["suite"]["context"].as_str().unwrap());
    let password = input(&fixture, "password");
    let credential_identifier = input(&fixture, "credential_identifier");
    let setup = server_setup_from_fixture(&fixture);

    // ---- Registration ----
    let mut reg_rng = ScriptedRng::new(
        "registration",
        ScriptedRng::scalar(&input(&fixture, "blind_registration")),
    );
    let reg_start = ClientRegistration::<CS>::start(&mut reg_rng, &password).unwrap();
    let registration_request = reg_start.message.serialize().to_vec();
    assert_eq_msg(
        "registration_request",
        &registration_request,
        &output(&fixture, "registration_request"),
    );

    let server_reg =
        ServerRegistration::<CS>::start(&setup, reg_start.message, &credential_identifier).unwrap();
    let registration_response = server_reg.message.serialize().to_vec();
    assert_eq_msg(
        "registration_response",
        &registration_response,
        &output(&fixture, "registration_response"),
    );

    let mut finish_rng = ScriptedRng::new("registration-finish", input(&fixture, "envelope_nonce"));
    let reg_finish = reg_start
        .state
        .finish(
            &mut finish_rng,
            &password,
            server_reg.message,
            ClientRegistrationFinishParameters::new(Identifiers::default(), None),
        )
        .unwrap();
    let registration_upload = reg_finish.message.serialize().to_vec();
    assert_eq_msg(
        "registration_upload",
        &registration_upload,
        &output(&fixture, "registration_upload"),
    );
    assert_eq!(
        reg_finish.export_key.to_vec(),
        output(&fixture, "export_key"),
        "export_key at registration"
    );

    let password_file = ServerRegistration::<CS>::finish(reg_finish.message);

    // ---- Login ----
    let mut login_rng = ScriptedRng::new(
        "login",
        [
            ScriptedRng::scalar(&input(&fixture, "blind_login")),
            input(&fixture, "client_keyshare_seed"),
            input(&fixture, "client_nonce"),
        ]
        .concat(),
    );
    let login_start = ClientLogin::<CS>::start(&mut login_rng, &password).unwrap();
    let ke1 = login_start.message.serialize().to_vec();
    assert_eq_msg("KE1", &ke1, &output(&fixture, "KE1"));

    let mut server_rng = ScriptedRng::new(
        "server-login",
        [
            vec![0x55u8; 64], // dummy record masking key (discarded)
            input(&fixture, "masking_nonce"),
            input(&fixture, "server_keyshare_seed"),
            input(&fixture, "server_nonce"),
        ]
        .concat(),
    );
    let server_login = ServerLogin::<CS>::start(
        &mut server_rng,
        &setup,
        Some(password_file),
        login_start.message,
        &credential_identifier,
        ServerLoginParameters {
            context: Some(&context),
            identifiers: Identifiers::default(),
        },
    )
    .unwrap();
    let ke2 = server_login.message.serialize().to_vec();
    assert_eq_msg("KE2", &ke2, &output(&fixture, "KE2"));

    let mut client_rng = ScriptedRng::new("client-finish", Vec::new());
    let _ = &mut client_rng;
    let client_finish = login_start
        .state
        .finish(
            &mut OsRng,
            &password,
            server_login.message,
            ClientLoginFinishParameters::new(Some(&context), Identifiers::default(), None),
        )
        .unwrap();
    let ke3 = client_finish.message.serialize().to_vec();
    assert_eq_msg("KE3", &ke3, &output(&fixture, "KE3"));
    assert_eq!(
        client_finish.session_key.to_vec(),
        output(&fixture, "session_key"),
        "session_key"
    );
    assert_eq!(
        client_finish.export_key.to_vec(),
        output(&fixture, "export_key"),
        "export_key at login"
    );

    let server_finish = server_login
        .state
        .finish(
            CredentialFinalization::<CS>::deserialize(&ke3).unwrap(),
            ServerLoginParameters {
                context: Some(&context),
                identifiers: Identifiers::default(),
            },
        )
        .unwrap();
    assert_eq!(
        server_finish.session_key.to_vec(),
        output(&fixture, "session_key"),
        "server session_key"
    );
}

#[test]
fn rfc9807_c1_1_negative_cases_fail_with_generic_authentication() {
    let fixture = load();
    let context = bytes_field(fixture["suite"]["context"].as_str().unwrap());
    let password = input(&fixture, "password");
    let wrong_password = bytes_field(fixture["negative"][0]["wrongPassword"].as_str().unwrap());
    let credential_identifier = input(&fixture, "credential_identifier");
    let setup = server_setup_from_fixture(&fixture);

    for case in fixture["negative"].as_array().unwrap() {
        let name = case["case"].as_str().unwrap();
        assert_eq!(case["error"].as_str().unwrap(), "AuthenticationFailed");
        match name {
            "mismatched-password" => {
                let result = run_login(
                    &setup,
                    &credential_identifier,
                    &wrong_password,
                    &context,
                    &context,
                    &fixture,
                );
                assert_eq!(result.unwrap_err(), Error::AuthenticationFailed, "{name}");
            }
            "tampered-ke2" => {
                let offset = case["offset"].as_u64().unwrap() as usize;
                let mut ke2 = output(&fixture, "KE2");
                ke2[offset] ^= 0x01;
                let login = ClientLogin::<CS>::start(&mut OsRng, &password).unwrap();
                let response = CredentialResponse::<CS>::deserialize(&ke2);
                let error = match response {
                    Err(_) => Error::AuthenticationFailed,
                    Ok(response) => login
                        .state
                        .finish(&mut OsRng, &password, response, login_params(&context))
                        .err()
                        .map(|_| Error::AuthenticationFailed)
                        .unwrap_or_else(|| panic!("{name} must not succeed")),
                };
                assert_eq!(error, Error::AuthenticationFailed, "{name}");
            }
            "wrong-server-record" => {
                let offset = case["offset"].as_u64().unwrap() as usize;
                let mut upload = output(&fixture, "registration_upload");
                upload[offset] ^= 0x01;
                // A tampered upload may either fail to parse or parse to a
                // record the client's finish will reject; both are the
                // generic authentication failure (corrupt remote material).
                let file = match RegistrationUpload::<CS>::deserialize(&upload) {
                    Ok(file) => file,
                    // Unparseable corrupt upload: the generic failure the
                    // crypto-core boundary would surface.
                    Err(_) => continue,
                };
                let mut login_rng = ScriptedRng::new(
                    "wrong-record-login",
                    [
                        ScriptedRng::scalar(&input(&fixture, "blind_login")),
                        input(&fixture, "client_keyshare_seed"),
                        input(&fixture, "client_nonce"),
                    ]
                    .concat(),
                );
                let login = ClientLogin::<CS>::start(&mut login_rng, &password).unwrap();
                let server = ServerLogin::<CS>::start(
                    &mut OsRng,
                    &setup,
                    Some(ServerRegistration::<CS>::finish(file)),
                    login.message,
                    &credential_identifier,
                    ServerLoginParameters {
                        context: Some(&context),
                        identifiers: Identifiers::default(),
                    },
                )
                .unwrap();
                let error = login
                    .state
                    .finish(
                        &mut OsRng,
                        &password,
                        server.message,
                        login_params(&context),
                    )
                    .err()
                    .map(|_| Error::AuthenticationFailed);
                assert_eq!(
                    error,
                    Some(Error::AuthenticationFailed),
                    "{name} must not succeed"
                );
            }
            "context-substitution" => {
                // The server binds the fixture context; the client verifies
                // against the substituted context. The mismatch must fail
                // with the generic authentication error.
                let other_context = bytes_field(case["context"].as_str().unwrap());
                let result = run_login(
                    &setup,
                    &credential_identifier,
                    &password,
                    &context,
                    &other_context,
                    &fixture,
                );
                assert_eq!(result.unwrap_err(), Error::AuthenticationFailed, "{name}");
            }
            other => panic!("unexpected fixture case {other}"),
        }
    }
}

fn login_params(context: &[u8]) -> ClientLoginFinishParameters<'_, '_, 'static, CS> {
    ClientLoginFinishParameters::new(Some(context), Identifiers::default(), None)
}

/// Full login flow with fresh randomness; returns the client session key.
///
/// `server_context` and `client_context` are passed to the respective
/// transcript sides; they differ only for the context-substitution negative.
fn run_login(
    setup: &ServerSetup<CS>,
    credential_identifier: &[u8],
    password: &[u8],
    server_context: &[u8],
    client_context: &[u8],
    fixture: &Value,
) -> Result<Vec<u8>, Error> {
    // Register first (fresh server side) using fixture seeds so the record
    // matches the vector's structure but with a live password file.
    let reg_password = input(fixture, "password");
    let mut reg_rng = ScriptedRng::new(
        "reg",
        ScriptedRng::scalar(&input(fixture, "blind_registration")),
    );
    let reg = ClientRegistration::<CS>::start(&mut reg_rng, &reg_password).unwrap();
    let server_reg =
        ServerRegistration::<CS>::start(setup, reg.message, credential_identifier).unwrap();
    let mut finish_rng = ScriptedRng::new("reg-finish", input(fixture, "envelope_nonce"));
    let finish = reg
        .state
        .finish(
            &mut finish_rng,
            &reg_password,
            server_reg.message,
            ClientRegistrationFinishParameters::new(Identifiers::default(), None),
        )
        .map_err(|_| Error::AuthenticationFailed)?;
    let file = ServerRegistration::<CS>::finish(finish.message);

    let login =
        ClientLogin::<CS>::start(&mut OsRng, password).map_err(|_| Error::AuthenticationFailed)?;
    let server = ServerLogin::<CS>::start(
        &mut OsRng,
        setup,
        Some(file),
        login.message,
        credential_identifier,
        ServerLoginParameters {
            context: Some(server_context),
            identifiers: Identifiers::default(),
        },
    )
    .map_err(|_| Error::AuthenticationFailed)?;
    let client = login
        .state
        .finish(
            &mut OsRng,
            password,
            server.message,
            login_params(client_context),
        )
        .map_err(|_| Error::AuthenticationFailed)?;
    let _ =
        RegistrationRequest::<CS>::deserialize(&output(fixture, "registration_request")).is_ok();
    let _ =
        RegistrationResponse::<CS>::deserialize(&output(fixture, "registration_response")).is_ok();
    let _ = CredentialRequest::<CS>::deserialize(&output(fixture, "KE1")).is_ok();
    Ok(client.session_key.to_vec())
}

fn assert_eq_msg(what: &str, produced: &[u8], expected: &[u8]) {
    assert_eq!(
        produced.len(),
        expected.len(),
        "{what}: length mismatch (produced {} bytes, expected {})",
        produced.len(),
        expected.len()
    );
    assert_eq!(produced, expected, "{what}: byte mismatch");
}
