package com.pass.android.vault

import com.pass.android.crypto.LoginFinish
import com.pass.android.crypto.LoginStart
import com.pass.android.crypto.OPAQUE_CONTEXT
import com.pass.android.crypto.OpaqueClientApi
import com.pass.android.crypto.RegistrationFinish
import com.pass.android.crypto.RegistrationStart

/** A no-op OPAQUE client for `VaultManager` unlock tests that only need to
 * reach the *unlock choreography* (device enrollment / key-bundle
 * fetch/parse / crypto-ffi unlock) without a real OPAQUE server on the
 * other end — the real protocol math is exercised separately by
 * `crates/crypto-ffi`'s own tests and by the real-backend integration
 * suite. Returns fixed, meaningless bytes; a `FakeVaultApi` paired with
 * this never actually validates them. */
class FakeOpaqueClient : OpaqueClientApi {
    override fun clientLoginStart(password: ByteArray): LoginStart = LoginStart(byteArrayOf(1), byteArrayOf(2))
    override fun clientLoginFinish(state: ByteArray, password: ByteArray, response: ByteArray, context: ByteArray): LoginFinish = LoginFinish(byteArrayOf(3))
    override fun clientRegistrationStart(password: ByteArray): RegistrationStart = RegistrationStart(byteArrayOf(1), byteArrayOf(2))
    override fun clientRegistrationFinish(state: ByteArray, password: ByteArray, response: ByteArray): RegistrationFinish = RegistrationFinish(byteArrayOf(3))
}
