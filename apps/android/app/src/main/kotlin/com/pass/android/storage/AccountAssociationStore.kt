package com.pass.android.storage

import android.content.Context
import android.content.SharedPreferences
import androidx.security.crypto.EncryptedSharedPreferences
import androidx.security.crypto.MasterKey

/**
 * D4 analog: the *only* thing this app persists across process death is the
 * non-secret account association (accountId + confirmed API origin), and
 * only inside `EncryptedSharedPreferences` backed by an Android
 * Keystore-generated key (Jetpack Security Crypto) — never a plain file,
 * never plaintext `SharedPreferences`.
 *
 * Design call (no ADR precedent covers Android specifically, so this is a
 * documented judgment call rather than an escalation — it is ordinary
 * platform-idiomatic use of the one Android API built for exactly this
 * purpose, not a security/scope boundary question):
 * - `MasterKey` uses `AES256_GCM`, the library's own recommended scheme,
 *   generated/held in the Android Keystore (`AndroidKeyStore` provider) —
 *   the key material itself never leaves hardware-backed (or software
 *   fallback, on emulators/older devices) Keystore storage.
 * - `PrefKeyEncryptionScheme.AES256_SIV` / `PrefValueEncryptionScheme
 *   .AES256_GCM` (the library defaults) both encrypt keys and values; no
 *   plaintext accountId/origin string is ever written to disk.
 * - No key material, password, wrapped bundle, or vault item ever goes
 *   through this store — only the accountId string and the confirmed
 *   HTTPS origin string, exactly matching D4's "non-secret account
 *   association" allowance.
 */
class AccountAssociationStore(context: Context) {
    data class Association(val accountId: String, val apiOrigin: String)

    private val prefs: SharedPreferences

    init {
        val masterKey = MasterKey.Builder(context)
            .setKeyScheme(MasterKey.KeyScheme.AES256_GCM)
            .build()
        prefs = EncryptedSharedPreferences.create(
            context,
            "pass_account_association",
            masterKey,
            EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
            EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM,
        )
    }

    fun save(association: Association) {
        prefs.edit()
            .putString(KEY_ACCOUNT_ID, association.accountId)
            .putString(KEY_API_ORIGIN, association.apiOrigin)
            .apply()
    }

    fun load(): Association? {
        val accountId = prefs.getString(KEY_ACCOUNT_ID, null) ?: return null
        val apiOrigin = prefs.getString(KEY_API_ORIGIN, null) ?: return null
        return Association(accountId, apiOrigin)
    }

    fun clear() {
        prefs.edit().clear().apply()
    }

    companion object {
        private const val KEY_ACCOUNT_ID = "account_id"
        private const val KEY_API_ORIGIN = "api_origin"
    }
}
