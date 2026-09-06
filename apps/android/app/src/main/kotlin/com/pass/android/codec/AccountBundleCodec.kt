package com.pass.android.codec

import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.jsonPrimitive
import java.nio.charset.CharacterCodingException
import java.nio.charset.CodingErrorAction
import java.nio.charset.StandardCharsets
import java.util.Base64

/**
 * D02-MVP port of `packages/sdk/src/account-bundle-codec.ts` (ADR-0011 G1:
 * client-side canonical codec for the `AccountBundle` JSON object carried
 * opaquely inside `KeyBundle.bundle`). Field-for-field, rule-for-rule port;
 * `packages/sdk` is a forbidden path for this task so this is a deliberate
 * mirror, exactly like the extension's own copy is a mirror of the web
 * client's — divergence between copies is a bug the fixtures below are
 * meant to catch, not a shared implementation.
 */
const val ACCOUNT_BUNDLE_FORMAT = "c04-account-bundle/1"

val ACCOUNT_BUNDLE_FIELDS = listOf(
    "format",
    "accountId",
    "vaultId",
    "itemId",
    "kdfParametersCbor",
    "wrappedAccountKey",
    "wrappedVaultKey",
    "wrappedItemKey",
    "wrappedRecoveryKey",
)

data class AccountBundleFields(
    val format: String,
    val accountId: String,
    val vaultId: String,
    val itemId: String,
    val kdfParametersCbor: String,
    val wrappedAccountKey: String,
    val wrappedVaultKey: String,
    val wrappedItemKey: String,
    val wrappedRecoveryKey: String,
)

private const val MAX_OUTER_BYTES = 512 * 1024
private const val MAX_WRAPPER_BYTES = 64 * 1024
private const val MAX_KDF_PARAMS_BYTES = 512

private val ID_PATTERN = Regex("^[A-Za-z0-9][A-Za-z0-9_-]{0,127}$")
private val B64_PATTERN = Regex("^b64:[A-Za-z0-9+/]+={0,2}$")

private val json = Json { ignoreUnknownKeys = false }

data class AccountBundleBytes(
    val accountId: String,
    val vaultId: String,
    val itemId: String,
    val kdfParametersCbor: ByteArray,
    val wrappedAccountKey: ByteArray,
    val wrappedVaultKey: ByteArray,
    val wrappedItemKey: ByteArray,
    val wrappedRecoveryKey: ByteArray,
)

/** Builds the canonical `KeyBundle.bundle` wire value (a `b64:`-prefixed
 * string) from raw wrapped bytes, in the fixed ADR-0011 G1 field order.
 * Test/fixture helper mirroring `packages/sdk/src/account-bundle-codec.ts`'s
 * `buildAccountBundle` — also usable by real unlock code that ever needs to
 * publish a bundle (not needed by this MVP's read-only flow, but kept
 * alongside the parser for fixture symmetry with the TS reference). */
fun buildAccountBundle(fields: AccountBundleBytes): String {
    fun b64(bytes: ByteArray) = encodeB64(bytes)
    val canonical = buildString {
        append('{')
        append("\"format\":\"").append(ACCOUNT_BUNDLE_FORMAT).append('"').append(',')
        append("\"accountId\":\"").append(fields.accountId).append('"').append(',')
        append("\"vaultId\":\"").append(fields.vaultId).append('"').append(',')
        append("\"itemId\":\"").append(fields.itemId).append('"').append(',')
        append("\"kdfParametersCbor\":\"").append(b64(fields.kdfParametersCbor)).append('"').append(',')
        append("\"wrappedAccountKey\":\"").append(b64(fields.wrappedAccountKey)).append('"').append(',')
        append("\"wrappedVaultKey\":\"").append(b64(fields.wrappedVaultKey)).append('"').append(',')
        append("\"wrappedItemKey\":\"").append(b64(fields.wrappedItemKey)).append('"').append(',')
        append("\"wrappedRecoveryKey\":\"").append(b64(fields.wrappedRecoveryKey)).append('"')
        append('}')
    }
    val bytes = canonical.toByteArray(StandardCharsets.UTF_8)
    return encodeB64(bytes)
}

/**
 * Parses and validates a `KeyBundle.bundle` wire value. Returns the decoded
 * fields (still `b64:`-encoded byte-strings; callers unwrap them with
 * crypto-ffi) on success, or `null` for anything malformed, oversized, or
 * non-canonical. Never throws on attacker- or server-controlled input.
 */
fun parseAccountBundle(bundleWireValue: String?): AccountBundleFields? {
    if (bundleWireValue == null || !B64_PATTERN.matches(bundleWireValue)) return null

    val outerBytes = safeDecodeStandardBase64(bundleWireValue.removePrefix("b64:")) ?: return null
    if (outerBytes.isEmpty() || outerBytes.size > MAX_OUTER_BYTES) return null

    val text = strictUtf8Decode(outerBytes) ?: return null

    val parsed = try {
        json.parseToJsonElement(text)
    } catch (e: Exception) {
        return null
    }
    val record = (parsed as? JsonObject) ?: return null

    val keys = record.keys
    if (keys.size != ACCOUNT_BUNDLE_FIELDS.size) return null
    for (field in ACCOUNT_BUNDLE_FIELDS) {
        val value = record[field] ?: return null
        val primitive = value as? JsonPrimitive ?: return null
        if (!primitive.isString) return null
    }

    fun str(field: String): String = record.getValue(field).jsonPrimitive.content

    if (str("format") != ACCOUNT_BUNDLE_FORMAT) return null
    if (!ID_PATTERN.matches(str("accountId"))) return null
    if (!ID_PATTERN.matches(str("vaultId"))) return null
    if (!ID_PATTERN.matches(str("itemId"))) return null

    val kdf = str("kdfParametersCbor")
    if (!B64_PATTERN.matches(kdf)) return null
    val kdfBytes = safeDecodeStandardBase64(kdf.removePrefix("b64:")) ?: return null
    if (kdfBytes.isEmpty() || kdfBytes.size > MAX_KDF_PARAMS_BYTES) return null

    for (field in listOf("wrappedAccountKey", "wrappedVaultKey", "wrappedItemKey", "wrappedRecoveryKey")) {
        val value = str(field)
        if (!B64_PATTERN.matches(value)) return null
        val bytes = safeDecodeStandardBase64(value.removePrefix("b64:")) ?: return null
        if (bytes.isEmpty() || bytes.size > MAX_WRAPPER_BYTES) return null
    }

    // Canonical reproduction: reject reordered/duplicate/unknown keys and
    // non-canonical escapes/whitespace by requiring an exact byte match
    // against a freshly serialized fixed-order copy, rather than trusting
    // any "normalized" reading of hostile input. Every field value here is
    // already known (by the pattern checks above) to contain only
    // JSON-safe ASCII (no quote/backslash/control chars needing escaping),
    // so a manually built compact object literal reproduces exactly what
    // `JSON.stringify` on the same fixed-order object would produce.
    val canonical = buildString {
        append('{')
        ACCOUNT_BUNDLE_FIELDS.forEachIndexed { index, field ->
            if (index > 0) append(',')
            append('"').append(field).append("\":\"").append(str(field)).append('"')
        }
        append('}')
    }
    val canonicalBytes = canonical.toByteArray(StandardCharsets.UTF_8)
    if (!canonicalBytes.contentEquals(outerBytes)) return null

    return AccountBundleFields(
        format = str("format"),
        accountId = str("accountId"),
        vaultId = str("vaultId"),
        itemId = str("itemId"),
        kdfParametersCbor = str("kdfParametersCbor"),
        wrappedAccountKey = str("wrappedAccountKey"),
        wrappedVaultKey = str("wrappedVaultKey"),
        wrappedItemKey = str("wrappedItemKey"),
        wrappedRecoveryKey = str("wrappedRecoveryKey"),
    )
}

private fun safeDecodeStandardBase64(value: String): ByteArray? = try {
    Base64.getDecoder().decode(value)
} catch (e: IllegalArgumentException) {
    null
}

private fun strictUtf8Decode(bytes: ByteArray): String? {
    val decoder = StandardCharsets.UTF_8.newDecoder()
    decoder.onMalformedInput(CodingErrorAction.REPORT)
    decoder.onUnmappableCharacter(CodingErrorAction.REPORT)
    return try {
        decoder.decode(java.nio.ByteBuffer.wrap(bytes)).toString()
    } catch (e: CharacterCodingException) {
        null
    }
}
