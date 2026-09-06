package com.pass.android.codec

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Test
import java.nio.charset.StandardCharsets
import java.util.Base64

/** Port of `packages/sdk/test/account-bundle-codec.test.ts`'s positive and
 * negative cases (ADR-0011 G1). */
class AccountBundleCodecTest {
    private fun bytes(label: String, length: Int = label.length): ByteArray {
        val out = ByteArray(length)
        for (i in 0 until length) out[i] = label[i % label.length].code.toByte()
        return out
    }

    private fun validBytesInput() = AccountBundleBytes(
        accountId = "acct-01",
        vaultId = "vault-01",
        itemId = "item-01",
        kdfParametersCbor = bytes("kdf"),
        wrappedAccountKey = bytes("account-key"),
        wrappedVaultKey = bytes("vault-key"),
        wrappedItemKey = bytes("item-key"),
        wrappedRecoveryKey = bytes("recovery-key"),
    )

    @Test
    fun `buildAccountBundle then parseAccountBundle round-trips exactly`() {
        val wire = buildAccountBundle(validBytesInput())
        assert(wire.startsWith("b64:"))
        val parsed = parseAccountBundle(wire)
        assertNotNull(parsed)
        assertEquals("acct-01", parsed!!.accountId)
        assertEquals("vault-01", parsed.vaultId)
        assertEquals("item-01", parsed.itemId)
        assertEquals("c04-account-bundle/1", parsed.format)
    }

    @Test
    fun `rejects a non-b64-prefixed wire value`() {
        assertNull(parseAccountBundle("not-b64"))
    }

    @Test
    fun `rejects an unrecognized format`() {
        val tampered = tamperField(buildAccountBundle(validBytesInput()), "format", "other/1")
        assertNull(parseAccountBundle(tampered))
    }

    @Test
    fun `rejects duplicate keys that JSON parse would otherwise silently collapse`() {
        val wire = buildAccountBundle(validBytesInput())
        val decoded = String(Base64.getDecoder().decode(wire.removePrefix("b64:")), StandardCharsets.UTF_8)
        val injected = decoded.replaceFirst("{\"format\"", "{\"format\":\"c04-account-bundle/1\",\"format\"")
        val reEncoded = "b64:" + Base64.getEncoder().encodeToString(injected.toByteArray(StandardCharsets.UTF_8))
        assertNull(parseAccountBundle(reEncoded))
    }

    @Test
    fun `rejects an unknown extra field`() {
        val wire = buildAccountBundle(validBytesInput())
        val decoded = String(Base64.getDecoder().decode(wire.removePrefix("b64:")), StandardCharsets.UTF_8)
        val withExtra = decoded.dropLast(1) + ",\"extra\":\"nope\"}"
        val reEncoded = "b64:" + Base64.getEncoder().encodeToString(withExtra.toByteArray(StandardCharsets.UTF_8))
        assertNull(parseAccountBundle(reEncoded))
    }

    @Test
    fun `rejects a missing field`() {
        val wire = buildAccountBundle(validBytesInput())
        val decoded = String(Base64.getDecoder().decode(wire.removePrefix("b64:")), StandardCharsets.UTF_8)
        val withoutField = decoded.replace(Regex(",\"wrappedRecoveryKey\":\"[^\"]*\""), "")
        val reEncoded = "b64:" + Base64.getEncoder().encodeToString(withoutField.toByteArray(StandardCharsets.UTF_8))
        assertNull(parseAccountBundle(reEncoded))
    }

    @Test
    fun `rejects a malformed account, vault, or item id`() {
        val input = validBytesInput().copy(itemId = "has a space")
        assertNull(parseAccountBundle(buildAccountBundle(input)))
    }

    @Test
    fun `rejects a wrapper exceeding the 64 KiB cap`() {
        val oversized = validBytesInput().copy(wrappedItemKey = bytes("x", 64 * 1024 + 1))
        assertNull(parseAccountBundle(buildAccountBundle(oversized)))
    }

    @Test
    fun `accepts a wrapper at exactly the 64 KiB cap`() {
        val atCap = validBytesInput().copy(wrappedItemKey = bytes("x", 64 * 1024))
        assertNotNull(parseAccountBundle(buildAccountBundle(atCap)))
    }

    @Test
    fun `rejects KDF params exceeding the 512-byte cap`() {
        val oversized = validBytesInput().copy(kdfParametersCbor = bytes("x", 513))
        assertNull(parseAccountBundle(buildAccountBundle(oversized)))
    }

    @Test
    fun `rejects a zero-length wrapper`() {
        val empty = validBytesInput().copy(wrappedItemKey = ByteArray(0))
        assertNull(parseAccountBundle(buildAccountBundle(empty)))
    }

    @Test
    fun `never throws on adversarial input`() {
        val adversarial = listOf("b64:bnVsbA==", "b64:W10=", "b64:IjEyMyI=", "not-even-b64-shaped", "")
        for (value in adversarial) {
            parseAccountBundle(value) // must not throw
        }
    }

    @Test
    fun `field order matches ADR-0011 G1`() {
        assertEquals(
            listOf(
                "format", "accountId", "vaultId", "itemId", "kdfParametersCbor",
                "wrappedAccountKey", "wrappedVaultKey", "wrappedItemKey", "wrappedRecoveryKey",
            ),
            ACCOUNT_BUNDLE_FIELDS,
        )
    }

    private fun tamperField(wire: String, field: String, value: String): String {
        val decoded = String(Base64.getDecoder().decode(wire.removePrefix("b64:")), StandardCharsets.UTF_8)
        val tampered = decoded.replace(Regex("\"$field\":\"[^\"]*\""), "\"$field\":\"$value\"")
        return "b64:" + Base64.getEncoder().encodeToString(tampered.toByteArray(StandardCharsets.UTF_8))
    }
}
