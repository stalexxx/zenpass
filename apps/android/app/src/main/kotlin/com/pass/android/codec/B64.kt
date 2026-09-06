package com.pass.android.codec

import java.util.Base64

/** `b64:` + standard padded base64, matching `packages/sdk/src/b64.ts` and
 * `apps/backend/src/auth/codec.mjs` exactly (docs/contracts/crypto-envelope-v1.md:
 * "Binary API value | `b64:` + standard RFC 4648 base64 with padding"). */
private const val PREFIX = "b64:"

fun encodeB64(bytes: ByteArray): String = PREFIX + Base64.getEncoder().encodeToString(bytes)

class InvalidB64Exception : Exception("expected a 'b64:'-prefixed base64 string")

fun decodeB64(value: String): ByteArray {
    if (!value.startsWith(PREFIX)) throw InvalidB64Exception()
    return try {
        Base64.getDecoder().decode(value.substring(PREFIX.length))
    } catch (e: IllegalArgumentException) {
        throw InvalidB64Exception()
    }
}
