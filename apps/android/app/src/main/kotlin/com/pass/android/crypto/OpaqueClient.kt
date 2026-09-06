package com.pass.android.crypto

import uniffi.crypto_ffi.opaqueClientLoginFinish
import uniffi.crypto_ffi.opaqueClientLoginStart
import uniffi.crypto_ffi.opaqueClientRegistrationFinish
import uniffi.crypto_ffi.opaqueClientRegistrationStart

/** OPAQUE application context bytes: must match the server's exactly
 * (`OPAQUE_CONTEXT = "zkpm-opaque-v1"` in `apps/backend/src/auth/routes.mjs`)
 * or login fails generically. */
val OPAQUE_CONTEXT: ByteArray = "zkpm-opaque-v1".toByteArray(Charsets.UTF_8)

data class LoginStart(val message: ByteArray, val state: ByteArray)
data class LoginFinish(val message: ByteArray)
data class RegistrationStart(val message: ByteArray, val state: ByteArray)
data class RegistrationFinish(val message: ByteArray)

/** Extracted so `VaultManager`'s unit tests can inject a fake OPAQUE client
 * (no real handshake, so a `FakeVaultApi` can be scripted without also
 * standing up a real OPAQUE server) — `OpaqueClient` is the only real
 * implementation. */
interface OpaqueClientApi {
    fun clientLoginStart(password: ByteArray): LoginStart
    fun clientLoginFinish(state: ByteArray, password: ByteArray, response: ByteArray, context: ByteArray = OPAQUE_CONTEXT): LoginFinish
    fun clientRegistrationStart(password: ByteArray): RegistrationStart
    fun clientRegistrationFinish(state: ByteArray, password: ByteArray, response: ByteArray): RegistrationFinish
}

/**
 * Thin Kotlin-idiomatic wrapper over the generated `uniffi.crypto_ffi`
 * OPAQUE client bindings (D02-MVP's new crypto-ffi exports). Mirrors
 * `packages/sdk/src/opaque-client.ts`'s `OpaqueClient` interface shape;
 * `packages/sdk` is a forbidden path for this task so this is a deliberate
 * mirror. All protocol math happens inside Rust — this class never sees or
 * computes a key.
 */
class OpaqueClient : OpaqueClientApi {
    override fun clientLoginStart(password: ByteArray): LoginStart {
        val result = opaqueClientLoginStart(password)
        return LoginStart(result.message, result.state)
    }

    override fun clientLoginFinish(state: ByteArray, password: ByteArray, response: ByteArray, context: ByteArray): LoginFinish {
        val result = opaqueClientLoginFinish(state, password, response, context)
        return LoginFinish(result.message)
    }

    override fun clientRegistrationStart(password: ByteArray): RegistrationStart {
        val result = opaqueClientRegistrationStart(password)
        return RegistrationStart(result.message, result.state)
    }

    override fun clientRegistrationFinish(state: ByteArray, password: ByteArray, response: ByteArray): RegistrationFinish {
        val result = opaqueClientRegistrationFinish(state, password, response)
        return RegistrationFinish(result.message)
    }
}
