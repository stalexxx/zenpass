package com.pass.android.vault

import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.jsonPrimitive
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody
import java.io.File
import java.util.concurrent.TimeUnit

data class ProvisionedAccount(val accountId: String, val vaultId: String, val itemId: String, val password: String, val baseUrl: String)

/** Drives `apps/android/scripts/integration-fixture.mjs` (a Bun
 * subprocess) as the real-backend/real-HTTPS-fixture counterpart to
 * `apps/extension/test/vault-manager.integration.test.ts`'s in-process
 * `startHttpsFixture`/`provisionAccount` — see that script's own header
 * comment for why this indirection exists (Kotlin cannot import
 * `packages/sdk`/`packages/crypto-worker`, which own OPAQUE registration
 * and hierarchy creation, both out of this MVP's Android scope).
 *
 * Commands (`verify_no_plaintext`/`revoke_device`) go over a plain
 * loopback HTTP control server the subprocess exposes — not stdin/stdout —
 * per the script's header comment on why a line-based stdio protocol
 * proved unreliable under real concurrent traffic.
 */
class IntegrationFixtureProcess private constructor(
    private val process: Process,
    private val controlUrl: String,
) : AutoCloseable {
    private val json = Json { ignoreUnknownKeys = true }
    private val client = OkHttpClient.Builder()
        .connectTimeout(5, TimeUnit.SECONDS)
        .readTimeout(30, TimeUnit.SECONDS)
        .build()

    fun sendCommand(commandJson: String): Map<String, Any?> {
        val request = Request.Builder()
            .url(controlUrl)
            .post(commandJson.toRequestBody("application/json".toMediaType()))
            .build()
        client.newCall(request).execute().use { response ->
            val text = response.body?.string().orEmpty()
            val obj = json.parseToJsonElement(text) as JsonObject
            return obj.mapValues { (_, v) ->
                val p = v as? kotlinx.serialization.json.JsonPrimitive
                when {
                    p == null -> null
                    p.isString -> p.content
                    p.content == "true" -> true
                    p.content == "false" -> false
                    else -> p.content
                }
            }
        }
    }

    /** Tears the subprocess down. Forcible destruction is always safe here
     * — this process is test-only and its backing Postgres connections are
     * cleaned up by the OS/Postgres when the socket drops. */
    override fun close() {
        process.destroyForcibly()
        process.waitFor(5, TimeUnit.SECONDS)
    }

    companion object {
        /** Starts the fixture, provisioning one account per (id, password)
         * pair, and returns both the process handle and each provisioned
         * account (accountId/vaultId/itemId/password/baseUrl — the baseUrl
         * is the same HTTPS fixture URL for every account in one process). */
        fun start(repoRootDir: String, accounts: List<Pair<String, String>>): Pair<IntegrationFixtureProcess, List<ProvisionedAccount>> {
            val requestJson = accounts.joinToString(",", "[", "]") { (id, password) ->
                """{"id":"$id","password":"${password.replace("\"", "\\\"")}"}"""
            }
            val builder = ProcessBuilder("bun", "apps/android/scripts/integration-fixture.mjs", requestJson)
            builder.directory(File(repoRootDir))
            // Classic ProcessBuilder pitfall: if neither stdout nor stderr
            // is drained, the child can block once the OS pipe buffer for
            // the undrained stream fills. stdout carries this protocol's
            // line-delimited JSON and is read explicitly below; stderr is
            // inherited straight through to this JVM process's own stderr
            // instead of being left as a second undrained pipe.
            builder.redirectError(ProcessBuilder.Redirect.INHERIT)
            val process = builder.start()
            val stdout = process.inputStream.bufferedReader()
            val json = Json { ignoreUnknownKeys = true }

            val provisioned = mutableListOf<ProvisionedAccount>()
            var controlUrl: String? = null
            while (controlUrl == null) {
                val line = stdout.readLine()
                    ?: throw IllegalStateException("integration fixture process exited before READY (check TEST_DATABASE_URL / openssl / bun)")
                if (line.trim() == "READY") continue
                val obj = json.parseToJsonElement(line).let { it as JsonObject }
                if (obj.containsKey("controlUrl")) {
                    controlUrl = obj["controlUrl"]!!.jsonPrimitive.content
                    continue
                }
                provisioned.add(
                    ProvisionedAccount(
                        accountId = obj["accountId"]!!.jsonPrimitive.content,
                        vaultId = obj["vaultId"]!!.jsonPrimitive.content,
                        itemId = obj["itemId"]!!.jsonPrimitive.content,
                        password = obj["password"]!!.jsonPrimitive.content,
                        baseUrl = obj["baseUrl"]!!.jsonPrimitive.content,
                    ),
                )
            }
            return IntegrationFixtureProcess(process, controlUrl) to provisioned
        }
    }
}
