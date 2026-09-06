package com.pass.android.origin

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

/** Port of `apps/extension/test/origin.test.ts`'s cases for
 * `confirmApiOrigin`. */
class OriginConfirmationTest {
    @Test
    fun `accepts a bare HTTPS origin, with or without a trailing slash`() {
        assertEquals(ConfirmedApiOrigin("https://api.example.test"), confirmApiOrigin("https://api.example.test"))
        assertEquals(ConfirmedApiOrigin("https://api.example.test"), confirmApiOrigin("https://api.example.test/"))
        assertEquals(ConfirmedApiOrigin("https://api.example.test:8443"), confirmApiOrigin("https://api.example.test:8443"))
    }

    @Test
    fun `rejects plain HTTP`() {
        assertNull(confirmApiOrigin("http://api.example.test"))
    }

    @Test
    fun `rejects URL credentials`() {
        assertNull(confirmApiOrigin("https://user:pass@api.example.test"))
    }

    @Test
    fun `rejects query configuration`() {
        assertNull(confirmApiOrigin("https://api.example.test?x=1"))
    }

    @Test
    fun `rejects fragment configuration`() {
        assertNull(confirmApiOrigin("https://api.example.test#frag"))
    }

    @Test
    fun `rejects a non-root path`() {
        assertNull(confirmApiOrigin("https://api.example.test/v1"))
    }

    @Test
    fun `rejects malformed, empty, or oversized input`() {
        assertNull(confirmApiOrigin(""))
        assertNull(confirmApiOrigin(null))
        assertNull(confirmApiOrigin("not a url"))
        assertNull(confirmApiOrigin("https://" + "a".repeat(600) + ".test"))
    }

    @Test
    fun `rejects a bare hostname with no scheme`() {
        assertNull(confirmApiOrigin("api.example.test"))
    }
}
