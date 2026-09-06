package com.pass.android.totp

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/** RFC 6238 Appendix B known-answer test vectors (same vectors already used
 * in `packages/extension-adapters/test/totp.test.ts` and `apps/web/test/totp.test.ts`),
 * using the well-known 20-byte ASCII seed "12345678901234567890" (SHA1),
 * base32-encoded. Published test vectors, not a real user secret. */
class TotpTest {
    private val seedAscii = "12345678901234567890"

    private fun toBase32(bytes: ByteArray): String {
        val alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
        var bits = 0
        var value = 0
        val output = StringBuilder()
        for (byte in bytes) {
            value = (value shl 8) or (byte.toInt() and 0xff)
            bits += 8
            while (bits >= 5) {
                output.append(alphabet[(value ushr (bits - 5)) and 31])
                bits -= 5
            }
        }
        if (bits > 0) output.append(alphabet[(value shl (5 - bits)) and 31])
        return output.toString()
    }

    private val secret = toBase32(seedAscii.toByteArray(Charsets.US_ASCII))

    @Test
    fun `base32Decode round-trips a known ASCII seed`() {
        val seedBytes = seedAscii.toByteArray(Charsets.US_ASCII)
        assertEquals(seedBytes.toList(), base32Decode(toBase32(seedBytes)).toList())
    }

    @Test(expected = InvalidTotpSecretException::class)
    fun `base32Decode rejects invalid characters`() {
        base32Decode("not-valid-base32!!!")
    }

    @Test
    fun `base32Decode tolerates whitespace, dashes, and lowercase`() {
        val seedBytes = seedAscii.toByteArray(Charsets.US_ASCII)
        val encoded = toBase32(seedBytes)
        val spaced = encoded.lowercase().chunked(4).joinToString(" ").trim()
        assertEquals(seedBytes.toList(), base32Decode(spaced).toList())
    }

    @Test
    fun `T equals 59s gives 94287082 for 8-digit SHA1`() {
        assertEquals("94287082", computeTotp(secret, TotpOptions(digits = 8), 59_000L))
    }

    @Test
    fun `T equals 1111111109s gives 07081804 for 8-digit SHA1`() {
        assertEquals("07081804", computeTotp(secret, TotpOptions(digits = 8), 1_111_111_109_000L))
    }

    @Test
    fun `T equals 1111111111s gives 14050471 for 8-digit SHA1`() {
        assertEquals("14050471", computeTotp(secret, TotpOptions(digits = 8), 1_111_111_111_000L))
    }

    @Test
    fun `default options give a zero-padded 6-digit code`() {
        val code = computeTotp(secret, atEpochMs = 59_000L)
        assertTrue(code.matches(Regex("^\\d{6}$")))
    }

    @Test(expected = EmptyTotpSecretException::class)
    fun `rejects an empty secret`() {
        computeTotp("", atEpochMs = 0L)
    }

    @Test
    fun `secondsRemaining counts down within a 30s period`() {
        assertEquals(30, secondsRemaining(30, 0L))
        assertEquals(29, secondsRemaining(30, 1_000L))
        assertEquals(1, secondsRemaining(30, 29_000L))
        assertEquals(30, secondsRemaining(30, 30_000L))
    }
}
