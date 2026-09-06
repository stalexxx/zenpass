package com.pass.android.totp

import java.security.InvalidKeyException
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

/**
 * RFC 6238 (TOTP) code generation, display only (ADR-0011 D6 analog:
 * "extend ADR-0008's native crypto TOTP permission to display only").
 * Mirrors `packages/extension-adapters/src/totp.ts`'s approved algorithm —
 * native `javax.crypto` HMAC, never a hand-rolled HMAC/hash — as its own
 * small pure module inside this task's `apps/android` allowed path,
 * matching the existing account-bundle-codec.ts/item-codec.ts precedent of
 * mirroring a shape across a language/runtime split rather than sharing a
 * module across a forbidden-path boundary. No new cryptographic primitive.
 * The TOTP seed only ever reaches this module already decrypted, in
 * memory, from the unlocked in-memory vault; it is never itself persisted,
 * logged, or transmitted.
 */
enum class TotpAlgorithm(val macAlgorithm: String) {
    SHA1("HmacSHA1"),
    SHA256("HmacSHA256"),
    SHA512("HmacSHA512"),
}

data class TotpOptions(
    val algorithm: TotpAlgorithm = TotpAlgorithm.SHA1,
    val digits: Int = 6,
    val periodSeconds: Int = 30,
)

private val BASE32_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"

class InvalidTotpSecretException : Exception("invalid base32 TOTP secret")
class EmptyTotpSecretException : Exception("empty TOTP secret")

/** Decodes an RFC 4648 base32 secret (case-insensitive, padding/whitespace
 * and dashes tolerated) into raw bytes. Throws on characters outside the
 * base32 alphabet — a malformed secret must fail closed. */
fun base32Decode(input: String): ByteArray {
    val cleaned = input.trim().uppercase().replace(Regex("[\\s-]+"), "").trimEnd('=')
    if (cleaned.isEmpty()) return ByteArray(0)
    var bits = 0
    var value = 0
    val bytes = mutableListOf<Byte>()
    for (char in cleaned) {
        val index = BASE32_ALPHABET.indexOf(char)
        if (index == -1) throw InvalidTotpSecretException()
        value = (value shl 5) or index
        bits += 5
        if (bits >= 8) {
            bits -= 8
            bytes.add(((value shr bits) and 0xff).toByte())
        }
    }
    return bytes.toByteArray()
}

private fun counterBytes(counter: Long): ByteArray {
    val bytes = ByteArray(8)
    var remaining = counter
    for (i in 7 downTo 0) {
        bytes[i] = (remaining and 0xff).toByte()
        remaining = remaining ushr 8
    }
    return bytes
}

private fun hmac(secret: ByteArray, message: ByteArray, algorithm: TotpAlgorithm): ByteArray {
    val mac = Mac.getInstance(algorithm.macAlgorithm)
    try {
        mac.init(SecretKeySpec(secret, algorithm.macAlgorithm))
    } catch (e: InvalidKeyException) {
        throw InvalidTotpSecretException()
    }
    return mac.doFinal(message)
}

private fun dynamicTruncate(hmacResult: ByteArray, digits: Int): String {
    val offset = (hmacResult[hmacResult.size - 1].toInt() and 0x0f)
    val binary =
        ((hmacResult[offset].toInt() and 0x7f) shl 24) or
            ((hmacResult[offset + 1].toInt() and 0xff) shl 16) or
            ((hmacResult[offset + 2].toInt() and 0xff) shl 8) or
            (hmacResult[offset + 3].toInt() and 0xff)
    var mod = 1
    repeat(digits) { mod *= 10 }
    val code = binary % mod
    return code.toString().padStart(digits, '0')
}

/** Computes the TOTP code for `secretBase32` at `atEpochMs`. `secretBase32`
 * is caller-owned already-decrypted plaintext; this function does not
 * retain a copy beyond the synchronous decode step. */
fun computeTotp(secretBase32: String, options: TotpOptions = TotpOptions(), atEpochMs: Long): String {
    val secret = base32Decode(secretBase32)
    if (secret.isEmpty()) throw EmptyTotpSecretException()
    val counter = Math.floorDiv(atEpochMs / 1000, options.periodSeconds.toLong())
    val digest = hmac(secret, counterBytes(counter), options.algorithm)
    return dynamicTruncate(digest, options.digits)
}

/** Seconds remaining in the current TOTP period at `atEpochMs`, for a
 * countdown display. */
fun secondsRemaining(periodSeconds: Int = 30, atEpochMs: Long): Int {
    val elapsed = (Math.floorMod(atEpochMs / 1000, periodSeconds.toLong())).toInt()
    return periodSeconds - elapsed
}
