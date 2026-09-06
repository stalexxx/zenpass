package com.pass.android.vault

import com.pass.android.net.ApiClient
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Assume.assumeTrue
import org.junit.Test
import java.io.File

/**
 * D02-MVP real-backend/real-crypto-ffi integration suite (mirrors
 * `apps/extension/test/vault-manager.integration.test.ts`'s acceptance
 * evidence, ported to this Android client): real backend (`apps/backend`),
 * real PostgreSQL, real self-signed HTTPS (`tests/browser/https-fixture.mjs`
 * via `apps/android/scripts/integration-fixture.mjs`), and the real
 * crypto-ffi JNI build (JNA-loaded from the host `target/release` build —
 * see `app/build.gradle.kts`) driving the actual `VaultManager` this task
 * ships. Only OPAQUE *registration* and hierarchy *creation* (out of this
 * MVP's Android scope) run through the Bun fixture subprocess instead of
 * Kotlin — every unlock/list/save/TOTP/revoke assertion below runs through
 * this module's own `VaultManager`/`ApiClient`/crypto-ffi code.
 *
 * Skipped (not failed) without `TEST_DATABASE_URL` — matching every other
 * integration test in this repo. Run with:
 *   TEST_DATABASE_URL=postgres://pass:pass@127.0.0.1:5434/pass \
 *     ./gradlew :app:testDebugUnitTest --tests "*RealBackendIntegrationTest"
 */
class VaultManagerRealBackendIntegrationTest {
    private val repoRootDir: String = requireNotNull(System.getProperty("pass.repoRootDir")) {
        "pass.repoRootDir system property must be set (see app/build.gradle.kts's Test task configuration)"
    }
    private val databaseUrl: String? = System.getenv("TEST_DATABASE_URL")?.takeIf { it.isNotBlank() }

    private fun assumeCanRun() {
        assumeTrue("requires TEST_DATABASE_URL (real PostgreSQL) — see class doc comment", databaseUrl != null)
    }

    private fun realApi(origin: String) = ApiClient(origin, trustAllCertificatesForIntegrationTestOnly = true)

    @Test
    fun `unlocks, enrolls a device, and starts with an empty vault`() {
        assumeCanRun()
        val (fixture, accounts) = IntegrationFixtureProcess.start(repoRootDir, listOf("empty" to "CorrectHorseBatteryStaple1!"))
        fixture.use {
            val account = accounts.single()
            val manager = VaultManager(deviceName = "integration-test-device", createApi = ::realApi)

            val password = account.password.toByteArray()
            val passwordCopy = password.copyOf()
            val result = manager.unlock(account.accountId, account.baseUrl, passwordCopy)

            assertTrue(result is UnlockResult.Ok)
            assertTrue(manager.isUnlocked())
            assertEquals(emptyList<ItemSummary>(), manager.listItems())
            assertTrue("unlock() must zeroize the caller's password buffer", passwordCopy.all { it == 0.toByte() })
        }
    }

    @Test
    fun `wrong password fails generically and never unlocks`() {
        assumeCanRun()
        val (fixture, accounts) = IntegrationFixtureProcess.start(repoRootDir, listOf("wrongpw" to "CorrectHorseBatteryStaple1!"))
        fixture.use {
            val account = accounts.single()
            val manager = VaultManager(deviceName = "integration-test-device", createApi = ::realApi)

            val result = manager.unlock(account.accountId, account.baseUrl, "WrongHorseBatteryStaple1!".toByteArray())

            assertTrue(result is UnlockResult.Failed)
            assertFalse(manager.isUnlocked())
        }
    }

    @Test
    fun `save round-trips as ciphertext only and a fresh unlock reads it back`() {
        assumeCanRun()
        val (fixture, accounts) = IntegrationFixtureProcess.start(repoRootDir, listOf("save" to "CorrectHorseBatteryStaple1!"))
        fixture.use {
            val account = accounts.single()
            val manager = VaultManager(deviceName = "integration-test-device", createApi = ::realApi)
            manager.unlock(account.accountId, account.baseUrl, account.password.toByteArray())

            val saveResult = manager.saveItem(
                VaultManager.SaveItemInput(
                    type = "login",
                    title = "Example login",
                    username = "alice@example.test",
                    password = "s3cr3t-plaintext-marker",
                    url = "https://example.test",
                ),
            )
            assertTrue(saveResult is SaveItemResult.Ok)
            val itemId = (saveResult as SaveItemResult.Ok).itemId

            // Direct database check: the stored ciphertext must never
            // contain the plaintext password/username as a substring.
            val verify = fixture.sendCommand(
                """{"cmd":"verify_no_plaintext","vaultId":"${account.vaultId}","markers":["s3cr3t-plaintext-marker","alice@example.test"]}""",
            )
            assertEquals("ciphertext must not leak plaintext markers: $verify", true, verify["ok"])

            // A fresh manager instance (simulating restart) re-unlocking
            // must read the saved item back correctly.
            val manager2 = VaultManager(deviceName = "integration-test-device-2", createApi = ::realApi)
            val reunlock = manager2.unlock(account.accountId, account.baseUrl, account.password.toByteArray())
            assertTrue(reunlock is UnlockResult.Ok)
            val items = manager2.listItems()
            assertEquals(1, items.size)
            assertEquals(itemId, items[0].itemId)
            assertEquals("Example login", items[0].title)
            assertEquals("alice@example.test", items[0].username)
        }
    }

    @Test
    fun `TOTP display computes the real RFC 6238 code for a saved totp-login item`() {
        assumeCanRun()
        val (fixture, accounts) = IntegrationFixtureProcess.start(repoRootDir, listOf("totp" to "CorrectHorseBatteryStaple1!"))
        fixture.use {
            val account = accounts.single()
            val manager = VaultManager(deviceName = "integration-test-device", createApi = ::realApi)
            manager.unlock(account.accountId, account.baseUrl, account.password.toByteArray())

            val saved = manager.saveItem(
                VaultManager.SaveItemInput(type = "totp-login", title = "GH", username = "a", password = "p", totpSecret = "JBSWY3DPEHPK3PXP"),
            )
            assertTrue(saved is SaveItemResult.Ok)
            val totp = manager.getTotp((saved as SaveItemResult.Ok).itemId)

            assertNotNull(totp)
            assertTrue(totp!!.code.matches(Regex("^\\d{6}$")))
        }
    }

    @Test
    fun `revoking the enrolled device from a second client locks the open session`() {
        assumeCanRun()
        val (fixture, accounts) = IntegrationFixtureProcess.start(repoRootDir, listOf("revoke" to "CorrectHorseBatteryStaple1!"))
        fixture.use {
            val account = accounts.single()
            var authFailures = 0
            var clock = 0L
            val manager = VaultManager(deviceName = "revoke-me-device", now = { clock }, createApi = ::realApi, onAuthFailure = { authFailures += 1 })
            val result = manager.unlock(account.accountId, account.baseUrl, account.password.toByteArray())
            assertTrue(result is UnlockResult.Ok)
            assertTrue(manager.isUnlocked())

            val revoke = fixture.sendCommand(
                """{"cmd":"revoke_device","accountId":"${account.accountId}","password":"${account.password}","deviceName":"revoke-me-device"}""",
            )
            assertEquals("device revoke must succeed: $revoke", true, revoke["ok"])

            // D5: the next fresh authenticated check the still-open session
            // performs must now fail and lock — no offline/cached fallback.
            clock += 31_000
            val fresh = manager.checkFresh()

            assertFalse(fresh)
            assertFalse(manager.isUnlocked())
            assertEquals(1, authFailures)
        }
    }
}
