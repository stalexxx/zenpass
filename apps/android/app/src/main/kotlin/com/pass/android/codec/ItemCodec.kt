package com.pass.android.codec

import kotlinx.serialization.Serializable
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json
import java.nio.charset.StandardCharsets

/**
 * Port of `apps/extension/src/item-codec.ts` (itself a mirror of
 * `apps/web/src/vault/item-codec.ts`): plaintext-shaped vault item content
 * and its wire encoding as the JSON payload sealed inside an item's
 * ciphertext. Kept byte-for-byte compatible so items created by any client
 * are readable by the others. This module only ever touches plaintext
 * bytes transiently, in memory, on the way into/out of crypto-ffi.
 */
@Serializable
data class VaultItemData(
    val type: String, // "login" | "note" | "totp-login"
    val title: String,
    val username: String? = null,
    val password: String? = null,
    val url: String? = null,
    val notes: String? = null,
    /** Raw base32 TOTP secret, present only for type "totp-login". */
    val totpSecret: String? = null,
)

private val json = Json { encodeDefaults = false; ignoreUnknownKeys = true }

fun encodeItemData(data: VaultItemData): ByteArray =
    json.encodeToString(data).toByteArray(StandardCharsets.UTF_8)

class MalformedItemPayloadException : Exception("malformed vault item payload")

fun decodeItemData(bytes: ByteArray): VaultItemData {
    val text = String(bytes, StandardCharsets.UTF_8)
    val parsed = try {
        json.decodeFromString<VaultItemData>(text)
    } catch (e: Exception) {
        throw MalformedItemPayloadException()
    }
    if (parsed.title.isEmpty() && parsed.type.isEmpty()) throw MalformedItemPayloadException()
    return parsed
}

/** Local input validation, mirroring apps/web/apps/extension's rules so the
 * same item is accepted or rejected identically by every client. */
fun validateItemData(data: VaultItemData): List<String> {
    val problems = mutableListOf<String>()
    if (data.title.isBlank()) problems.add("Title is required.")
    if (data.title.length > 500) problems.add("Title is too long.")
    if (data.type == "login" || data.type == "totp-login") {
        if (data.username.isNullOrEmpty() && data.password.isNullOrEmpty()) {
            problems.add("A login needs a username or a password.")
        }
    }
    if (data.type == "totp-login" && data.totpSecret.isNullOrEmpty()) {
        problems.add("A TOTP login needs a secret.")
    }
    if ((data.notes?.length ?: 0) > 100_000) problems.add("Notes are too long.")
    return problems
}
