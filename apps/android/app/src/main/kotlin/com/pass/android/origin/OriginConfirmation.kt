package com.pass.android.origin

import java.net.MalformedURLException
import java.net.URI
import java.net.URISyntaxException

/**
 * D1 independent-unlock origin confirmation (ADR-0011: "The configured API
 * must be an explicitly confirmed HTTPS origin, pinned per account
 * association. Reject URL credentials, query/fragment configuration,
 * cross-origin redirects, and API destinations supplied by page/content
 * messages."). Port of `apps/extension/src/origin.ts`'s exact validation
 * rules to Kotlin; this module only ever validates a login-screen-entered
 * string.
 */
private const val MAX_ORIGIN_LENGTH = 512

data class ConfirmedApiOrigin(val origin: String)

/**
 * Validates and normalizes a login-screen-entered API origin string.
 * Accepts only a bare HTTPS origin (optionally trailing slash) with no
 * userinfo, path (other than `/`), query, or fragment. Returns null for
 * anything else — including a bare hostname (ambiguous scheme), `http://`,
 * or a URL carrying extra configuration.
 */
fun confirmApiOrigin(input: String?): ConfirmedApiOrigin? {
    if (input.isNullOrEmpty() || input.length > MAX_ORIGIN_LENGTH) return null

    val uri: URI
    try {
        uri = URI(input)
    } catch (e: URISyntaxException) {
        return null
    }

    if (uri.scheme != "https") return null
    if (uri.userInfo != null) return null
    if (uri.rawQuery != null) return null
    if (uri.rawFragment != null) return null
    val path = uri.rawPath ?: ""
    if (path != "" && path != "/") return null
    val host = uri.host ?: return null
    if (host.isEmpty()) return null

    // java.net.URI does not expose a normalized "origin" the way the DOM
    // URL API does; reconstruct scheme://host[:port] explicitly (with the
    // default HTTPS port omitted, matching URL.origin's behavior).
    val port = uri.port
    val origin = if (port == -1 || port == 443) "https://$host" else "https://$host:$port"
    return ConfirmedApiOrigin(origin)
}
