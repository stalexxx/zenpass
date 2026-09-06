package com.pass.android.net

import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.contentOrNull
import kotlinx.serialization.json.decodeFromJsonElement
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody
import java.io.IOException
import java.util.concurrent.TimeUnit

/** Thrown for any non-2xx HTTP response that isn't handled as a typed
 * result by a specific method (e.g. a 409 Conflict from mutateItem, which
 * is returned as a value, not thrown). */
class HttpError(val status: Int, val body: JsonObject?) : Exception("HTTP $status")

/** Thrown when the request itself fails (offline, DNS, TLS, timeout,
 * refused redirect, etc.) — distinct from HttpError so callers can tell a
 * network failure apart from a definite server response. */
class NetworkError(cause: Throwable?) : Exception("network request failed", cause)

// `encodeDefaults = true`: kotlinx.serialization omits a default-valued
// field from its JSON output unless told otherwise, which silently dropped
// `DeviceCreateBearerSession.enrollmentMode` (whose one legal value is also
// its default) from the wire request — the backend's `classifyDeviceCreate`
// then saw a body with only `name` and correctly rejected it as neither
// disjoint `DeviceCreate` shape (400). Always encoding declared fields
// keeps every wire type's shape explicit regardless of Kotlin-side defaults.
private val json = Json { ignoreUnknownKeys = true; encodeDefaults = true }
private val JSON_MEDIA_TYPE = "application/json".toMediaType()

sealed class OpaqueStepOutcome {
    data class MessageLeg(val message: String) : OpaqueStepOutcome()
    data class SessionLeg(val session: Session) : OpaqueStepOutcome()
}

data class MutateOutcome(val status: Int, val item: ItemRecord? = null, val conflict: Conflict? = null)
data class GetKeyBundleOutcome(val status: Int, val keyBundle: KeyBundle? = null)

/** The subset of the API surface `VaultManager` needs, extracted as an
 * interface so unit tests can inject a fake implementation instead of a
 * real `ApiClient`/OkHttp stack (required by D02-MVP's "lifecycle/
 * lock-on-failure behavior with a fake API client" test). `ApiClient` is
 * the only real implementation. */
interface VaultApi {
    fun setAccessToken(token: String?)
    fun getAccessToken(): String?
    fun opaqueLoginStep(accountId: String, clientMessageB64: String): OpaqueStepOutcome
    fun refresh(): Session
    fun logout()
    fun listDevices(): List<Device>
    fun registerBearerSessionDevice(name: String): Device
    fun getKeyBundle(): GetKeyBundleOutcome
    fun mutateItem(vaultId: String, mutation: Mutation): MutateOutcome
    fun listChanges(vaultId: String, cursor: String?, limit: Int?): ChangePage
}

/**
 * Typed HTTP client over the sync/v1 and auth/v1 API surfaces
 * (`docs/contracts/`), ported from `packages/sdk/src/http-client.ts`'s
 * shape to OkHttp. D1: every request is pinned to the caller-confirmed
 * `baseUrl` origin (see `origin.confirmApiOrigin`) and redirects are never
 * followed — a redirect response is a hard failure, matching
 * `apps/extension/src/origin.ts`'s `pinnedFetch`.
 */
class ApiClient(
    private val baseUrl: String,
    /** Test-only seam: the real-backend integration suite runs against
     * `tests/browser/https-fixture.mjs`'s freshly-generated self-signed
     * certificate (there is no CA to install one from in this
     * environment) — the same accommodation
     * `apps/extension/test/vault-manager.integration.test.ts` makes via
     * `NODE_TLS_REJECT_UNAUTHORIZED=0`, scoped here to one explicitly
     * opted-in `ApiClient` instance instead of a process-wide JVM
     * property. Never used by production code, which always calls the
     * single-argument constructor. */
    trustAllCertificatesForIntegrationTestOnly: Boolean = false,
) : VaultApi {
    @Volatile
    private var accessToken: String? = null

    private val client = OkHttpClient.Builder()
        .followRedirects(false)
        .followSslRedirects(false)
        .connectTimeout(5, TimeUnit.SECONDS)
        .readTimeout(5, TimeUnit.SECONDS)
        .writeTimeout(5, TimeUnit.SECONDS)
        .apply { if (trustAllCertificatesForIntegrationTestOnly) trustAllCertificates() }
        .build()

    override fun setAccessToken(token: String?) {
        accessToken = token
    }

    override fun getAccessToken(): String? = accessToken

    private data class RawResponse(val status: Int, val body: JsonObject?)

    private fun request(
        method: String,
        path: String,
        body: String? = null,
        auth: Boolean = true,
        query: Map<String, String?> = emptyMap(),
    ): RawResponse {
        var url = baseUrl.trimEnd('/') + path
        val nonNullQuery = query.filterValues { it != null }
        if (nonNullQuery.isNotEmpty()) {
            url += "?" + nonNullQuery.entries.joinToString("&") { (k, v) ->
                "${java.net.URLEncoder.encode(k, "UTF-8")}=${java.net.URLEncoder.encode(v, "UTF-8")}"
            }
        }
        val builder = Request.Builder().url(url)
        if (auth) {
            val token = accessToken ?: throw IllegalStateException("ApiClient: no access token set for an authenticated request")
            builder.addHeader("authorization", "Bearer $token")
        }
        val requestBody = body?.toRequestBody(JSON_MEDIA_TYPE)
        when (method) {
            "GET" -> builder.get()
            "POST" -> builder.post(requestBody ?: "".toRequestBody(JSON_MEDIA_TYPE))
            "PUT" -> builder.put(requestBody ?: "".toRequestBody(JSON_MEDIA_TYPE))
            else -> throw IllegalArgumentException("unsupported method $method")
        }

        val response = try {
            client.newCall(builder.build()).execute()
        } catch (e: IOException) {
            throw NetworkError(e)
        }
        response.use {
            // D1: pinnedFetch's redirect refusal — OkHttp with
            // followRedirects(false) surfaces a 3xx as a normal response
            // rather than following it; treat it as a hard failure exactly
            // like the extension's pinnedFetch does.
            if (it.code in 300..399) throw NetworkError(IOException("refusing to follow a redirect"))
            if (it.code == 204) return RawResponse(204, null)
            val text = it.body?.string().orEmpty()
            val parsedBody = if (text.isNotEmpty()) {
                try {
                    json.parseToJsonElement(text).jsonObject
                } catch (e: Exception) {
                    null
                }
            } else null
            return RawResponse(it.code, parsedBody)
        }
    }

    private fun expectOk(
        method: String,
        path: String,
        body: String? = null,
        auth: Boolean = true,
        query: Map<String, String?> = emptyMap(),
    ): JsonObject? {
        val (status, respBody) = request(method, path, body, auth, query)
        if (status < 200 || status >= 300) throw HttpError(status, respBody)
        return respBody
    }

    // --- Auth (OPAQUE two-leg register/login) ---

    fun opaqueRegisterStep(accountId: String, clientMessageB64: String): String {
        val reqBody = json.encodeToString(OpaqueStepRequest.serializer(), OpaqueStepRequest(accountId, clientMessageB64))
        val respBody = expectOk("POST", "/auth/opaque/register", reqBody, auth = false)
        return respBody!!["message"]!!.jsonPrimitive.content
    }

    override fun opaqueLoginStep(accountId: String, clientMessageB64: String): OpaqueStepOutcome {
        val reqBody = json.encodeToString(OpaqueStepRequest.serializer(), OpaqueStepRequest(accountId, clientMessageB64))
        val (status, body) = request("POST", "/auth/opaque/login", reqBody, auth = false)
        if (status < 200 || status >= 300) throw HttpError(status, body)
        val accessToken = body?.get("accessToken")?.jsonPrimitive?.contentOrNull
        return if (accessToken != null) {
            val expiresAt = body["expiresAt"]!!.jsonPrimitive.content
            OpaqueStepOutcome.SessionLeg(Session(accessToken, expiresAt))
        } else {
            OpaqueStepOutcome.MessageLeg(body!!["message"]!!.jsonPrimitive.content)
        }
    }

    override fun refresh(): Session {
        val body = expectOk("POST", "/auth/refresh")!!
        return json.decodeFromJsonElement(Session.serializer(), body)
    }

    override fun logout() {
        expectOk("POST", "/auth/logout")
        accessToken = null
    }

    // --- Devices ---

    override fun listDevices(): List<Device> {
        val body = expectOk("GET", "/devices")!!
        return json.decodeFromJsonElement(
            kotlinx.serialization.builtins.ListSerializer(Device.serializer()),
            body["devices"]!!.jsonArrayOrEmpty(),
        )
    }

    /** ADR-0011 G2: enrolls a device with no proof-of-possession, authorized
     * only by the caller's own bearer session (must be fresh from OPAQUE
     * login and not yet bound to any device). */
    override fun registerBearerSessionDevice(name: String): Device {
        val reqBody = json.encodeToString(DeviceCreateBearerSession.serializer(), DeviceCreateBearerSession(name))
        val body = expectOk("POST", "/devices", reqBody)!!
        return json.decodeFromJsonElement(Device.serializer(), body)
    }

    // --- Account key bundle (ADR-0011 G1) ---

    /** Returns the account's published opaque key bundle, or `{ status: 404
     * }` if the authenticated account has never published one. */
    override fun getKeyBundle(): GetKeyBundleOutcome {
        val (status, body) = request("GET", "/account/key-bundle")
        if (status == 200) return GetKeyBundleOutcome(200, json.decodeFromJsonElement(KeyBundle.serializer(), body!!))
        if (status == 404) return GetKeyBundleOutcome(404)
        throw HttpError(status, body)
    }

    // --- Sync ---

    override fun mutateItem(vaultId: String, mutation: Mutation): MutateOutcome {
        val reqBody = json.encodeToString(Mutation.serializer(), mutation)
        val (status, body) = request("POST", "/vaults/${encode(vaultId)}/items", reqBody)
        if (status == 201) return MutateOutcome(201, item = json.decodeFromJsonElement(ItemRecord.serializer(), body!!))
        if (status == 409) return MutateOutcome(409, conflict = json.decodeFromJsonElement(Conflict.serializer(), body!!))
        throw HttpError(status, body)
    }

    override fun listChanges(vaultId: String, cursor: String?, limit: Int?): ChangePage {
        val body = expectOk(
            "GET",
            "/vaults/${encode(vaultId)}/changes",
            query = mapOf("cursor" to cursor, "limit" to limit?.toString()),
        )!!
        return json.decodeFromJsonElement(ChangePage.serializer(), body)
    }

    private fun encode(value: String): String = java.net.URLEncoder.encode(value, "UTF-8")
}

private fun kotlinx.serialization.json.JsonElement.jsonArrayOrEmpty() =
    (this as? kotlinx.serialization.json.JsonArray) ?: kotlinx.serialization.json.JsonArray(emptyList())

/** Test-only: configures the builder to trust any TLS certificate,
 * including a freshly-generated self-signed one. See the
 * `trustAllCertificatesForIntegrationTestOnly` constructor parameter doc
 * comment above for why this exists and its scope. */
private fun OkHttpClient.Builder.trustAllCertificates(): OkHttpClient.Builder {
    val trustAllManager = object : javax.net.ssl.X509TrustManager {
        override fun checkClientTrusted(chain: Array<out java.security.cert.X509Certificate>?, authType: String?) {}
        override fun checkServerTrusted(chain: Array<out java.security.cert.X509Certificate>?, authType: String?) {}
        override fun getAcceptedIssuers(): Array<java.security.cert.X509Certificate> = arrayOf()
    }
    val sslContext = javax.net.ssl.SSLContext.getInstance("TLS")
    sslContext.init(null, arrayOf<javax.net.ssl.TrustManager>(trustAllManager), java.security.SecureRandom())
    sslSocketFactory(sslContext.socketFactory, trustAllManager)
    hostnameVerifier { _, _ -> true }
    return this
}
