package com.pass.android.vault

import com.pass.android.codec.AccountBundleFields
import com.pass.android.codec.VaultItemData
import com.pass.android.codec.decodeB64
import com.pass.android.codec.decodeItemData
import com.pass.android.codec.encodeB64
import com.pass.android.codec.encodeItemData
import com.pass.android.codec.parseAccountBundle
import com.pass.android.codec.validateItemData
import com.pass.android.crypto.OPAQUE_CONTEXT
import com.pass.android.crypto.OpaqueClient
import com.pass.android.crypto.OpaqueClientApi
import com.pass.android.net.ApiClient
import com.pass.android.net.HttpError
import com.pass.android.net.Mutation
import com.pass.android.net.NetworkError
import com.pass.android.net.OpaqueStepOutcome
import com.pass.android.net.VaultApi
import com.pass.android.origin.confirmApiOrigin
import com.pass.android.totp.computeTotp
import com.pass.android.totp.secondsRemaining
import uniffi.crypto_ffi.CryptoFfiException
import uniffi.crypto_ffi.ItemSession
import uniffi.crypto_ffi.PersistedItemAccess
import java.util.UUID

/** D5: "at most 30 seconds apart" between fresh authenticated checks. */
const val FRESH_CHECK_INTERVAL_MS = 30_000L

/** D5: "a 5-second network deadline" — enforced by ApiClient's OkHttpClient
 * connect/read/write timeouts (see net/ApiClient.kt), reusing the same
 * constant here for lifecycle bookkeeping/tests. */
const val NETWORK_DEADLINE_MS = 5_000L

private const val KEY_VERSION: ULong = 1u
private const val ENVELOPE_VERSION = "crypto-envelope/v1"

/** Matches apps/web's/the extension's default (256 MiB) so every client
 * reports the same KDF resource envelope against the same hierarchy. */
private const val DEFAULT_REPORTED_MEMORY_KIB: ULong = 262_144u

sealed class UnlockResult {
    object Ok : UnlockResult()
    data class Failed(val reason: String = "unlock-failed") : UnlockResult()
}

sealed class SaveItemResult {
    data class Ok(val itemId: String) : SaveItemResult()
    data class Failed(val reason: String, val problems: List<String> = emptyList()) : SaveItemResult()
}

data class ItemSummary(
    val itemId: String,
    val title: String,
    val type: String,
    val username: String?,
    val url: String?,
)

data class TotpDisplay(val code: String, val secondsRemaining: Int)

// `internal` (not `private`) so this module's own unit tests — which live
// in the same Gradle module's test source set, with Kotlin's standard
// friend-module access to `internal` declarations — can install a fixed
// post-unlock state directly, without needing a fake OPAQUE server to
// drive `unlock()` end-to-end (see `installUnlockedStateForTesting` below).
internal data class ItemEntry(val itemId: String, val revision: Long, val data: VaultItemData)

internal data class UnlockedState(
    val api: VaultApi,
    val session: ItemSession,
    val accountId: String,
    val vaultId: String,
    var accessTokenExpiresAt: String,
    val items: MutableMap<String, ItemEntry>,
)

/**
 * D02-MVP `VaultManager`, ADR-0011 D1/D2/D3/D5/D6 analogs adapted for a
 * single-Activity Android app (no background-service-worker/popup split —
 * this whole app is one trusted process, closer to the *web* client's trust
 * model than the extension's). Independent OPAQUE login, G2 bearer-session
 * device enrollment, key-bundle fetch/opening via crypto-ffi's `ItemSession`,
 * in-memory item cache built from the sync change feed, save/update, and
 * TOTP display. Online-only: every secret display/mutation revalidates a
 * fresh authenticated check (at most 30s apart, 5s network deadline) before
 * proceeding; a network failure or 401 locks, with no offline cached-data
 * fallback. Nothing here is ever persisted (D4) — everything lives only in
 * memory for the life of the unlocked session; a `lock()`/process death
 * clears it all.
 *
 * Port of `apps/extension/src/vault-manager.ts`'s shape, not its code.
 */
class VaultManager(
    private val deviceName: String,
    private val now: () -> Long = { System.currentTimeMillis() },
    private val reportedPhysicalMemoryKib: ULong = DEFAULT_REPORTED_MEMORY_KIB,
    private val createOpaqueClient: () -> OpaqueClientApi = { OpaqueClient() },
    private val onAuthFailure: () -> Unit = {},
    /** Test seam: unit tests inject a fake `VaultApi` here instead of a
     * real OkHttp-backed `ApiClient`, per D02-MVP's "lifecycle/
     * lock-on-failure behavior with a fake API client" test requirement. */
    private val createApi: (String) -> VaultApi = { origin -> ApiClient(origin) },
) {
    @Volatile
    private var state: UnlockedState? = null
    private var lastFreshCheckAt: Long = 0

    fun isUnlocked(): Boolean = state != null

    /** Test-only seam: installs a post-unlock state directly, so lifecycle
     * tests (checkFresh/lock/saveItem/getTotp behavior against a fake
     * `VaultApi`) don't need to drive a real OPAQUE handshake through
     * `unlock()` — the real end-to-end path is covered separately by the
     * real-backend integration suite. `session` may be any `ItemSession`
     * (e.g. `ItemSession.create()`, which needs no password/server); its
     * cryptographic content is irrelevant to the behaviors under test here. */
    internal fun installUnlockedStateForTesting(
        api: VaultApi,
        session: ItemSession,
        accountId: String,
        vaultId: String,
        accessTokenExpiresAt: String,
        items: MutableMap<String, ItemEntry> = mutableMapOf(),
    ) {
        state = UnlockedState(api, session, accountId, vaultId, accessTokenExpiresAt, items)
        // Deliberately far in the past (not just 0) so the very next
        // `checkFresh()` always performs a real check regardless of what a
        // test's injected `now()` clock starts at.
        lastFreshCheckAt = Long.MIN_VALUE / 2
    }

    /** Always starts from a clean slate: a failed unlock never leaves
     * partial state (a stale token, a live crypto session, etc.) lying
     * around. `password` is zeroized before returning. */
    fun unlock(accountId: String, apiOriginInput: String, password: ByteArray): UnlockResult {
        dispose()
        try {
            if (accountId.isEmpty() || accountId.length > 256) return UnlockResult.Failed()
            val confirmed = confirmApiOrigin(apiOriginInput) ?: return UnlockResult.Failed()

            val api = createApi(confirmed.origin)
            val opaque = createOpaqueClient()

            val loginStart = opaque.clientLoginStart(password)
            val leg1 = api.opaqueLoginStep(accountId, encodeB64(loginStart.message))
            if (leg1 !is OpaqueStepOutcome.MessageLeg) return UnlockResult.Failed()
            val loginFinish = opaque.clientLoginFinish(loginStart.state, password, decodeB64(leg1.message), OPAQUE_CONTEXT)
            val leg2 = api.opaqueLoginStep(accountId, encodeB64(loginFinish.message))
            if (leg2 !is OpaqueStepOutcome.SessionLeg) return UnlockResult.Failed()
            api.setAccessToken(leg2.session.accessToken)

            // G2: bind this fresh, device-unbound session to its own named
            // device before anything else. If this fails, the whole unlock
            // fails closed — without a device binding, a server-side revoke
            // cannot invalidate this session (D5's revocation criterion).
            api.registerBearerSessionDevice(deviceName)

            val bundleOutcome = api.getKeyBundle()
            if (bundleOutcome.status != 200) return UnlockResult.Failed()
            val parsed: AccountBundleFields = parseAccountBundle(bundleOutcome.keyBundle!!.bundle) ?: return UnlockResult.Failed()
            if (parsed.accountId != accountId) return UnlockResult.Failed()

            val access = PersistedItemAccess(
                accountId = parsed.accountId,
                vaultId = parsed.vaultId,
                itemId = parsed.itemId,
                accountKeyVersion = KEY_VERSION,
                vaultKeyVersion = KEY_VERSION,
                itemKeyVersion = KEY_VERSION,
                kdfParametersCbor = decodeB64(parsed.kdfParametersCbor),
                reportedPhysicalMemoryKib = reportedPhysicalMemoryKib,
                wrappedAccountKey = decodeB64(parsed.wrappedAccountKey),
                wrappedVaultKey = decodeB64(parsed.wrappedVaultKey),
                wrappedItemKey = decodeB64(parsed.wrappedItemKey),
            )
            val session = try {
                ItemSession.unlock(password, access)
            } catch (e: CryptoFfiException) {
                return UnlockResult.Failed()
            }

            val items = loadAllItems(api, session, parsed.accountId, parsed.vaultId)
            state = UnlockedState(
                api = api,
                session = session,
                accountId = parsed.accountId,
                vaultId = parsed.vaultId,
                accessTokenExpiresAt = leg2.session.expiresAt,
                items = items,
            )
            lastFreshCheckAt = now()
            return UnlockResult.Ok
        } catch (e: Exception) {
            dispose()
            return UnlockResult.Failed()
        } finally {
            java.util.Arrays.fill(password, 0)
        }
    }

    private fun loadAllItems(api: VaultApi, session: ItemSession, accountId: String, vaultId: String): MutableMap<String, ItemEntry> {
        val items = mutableMapOf<String, ItemEntry>()
        var cursor: String? = null
        while (true) {
            val page = try {
                api.listChanges(vaultId, cursor, null)
            } catch (e: HttpError) {
                // A brand-new vault that has never had an item created
                // returns 404 (the backend only auto-creates the vault row
                // on first mutation) — an empty vault must still unlock
                // successfully, so this is "no items yet", not a failure.
                if (e.status == 404 && cursor == null) break
                throw e
            }
            for (record in page.changes) {
                if (record.deleted) {
                    items.remove(record.itemId)
                    continue
                }
                val opened = try {
                    session.openItemPayload(accountId, vaultId, record.itemId, KEY_VERSION, decodeB64(record.ciphertext))
                } catch (e: CryptoFfiException) {
                    continue // corrupt/foreign record: skip, never crash the whole load
                }
                try {
                    val data = decodeItemData(opened)
                    items[record.itemId] = ItemEntry(record.itemId, record.revision, data)
                } catch (e: Exception) {
                    // malformed payload: skip, log nothing (may contain plaintext)
                }
            }
            if (page.changes.isEmpty() || page.nextCursor == null) break
            cursor = page.nextCursor
        }
        return items
    }

    private fun dispose() {
        val s = state
        state = null
        lastFreshCheckAt = 0
        if (s != null) {
            try { s.session.closeSession() } catch (e: Exception) { /* continue clearing */ }
            try { s.api.setAccessToken(null) } catch (e: Exception) { /* continue clearing */ }
        }
    }

    private fun handleAuthFailure() {
        dispose()
        try { onAuthFailure() } catch (e: Exception) { /* never let a callback throw escape */ }
    }

    /** Purely local lock (no network call). */
    fun lock() {
        dispose()
    }

    /** Logout attempts server revocation but always clears local state — a
     * failed logout cannot promise server revocation. */
    fun logout() {
        val s = state
        try {
            s?.api?.logout()
        } catch (e: Exception) {
            // Best-effort only; local state clears below regardless.
        } finally {
            dispose()
        }
    }

    private fun maybeRefresh(s: UnlockedState): Boolean {
        val msLeft = try {
            java.time.Instant.parse(s.accessTokenExpiresAt).toEpochMilli() - now()
        } catch (e: Exception) {
            0L
        }
        if (msLeft > 30_000L) return true
        return try {
            val refreshed = s.api.refresh()
            if (state !== s) return false
            s.api.setAccessToken(refreshed.accessToken)
            s.accessTokenExpiresAt = refreshed.expiresAt
            true
        } catch (e: Exception) {
            if (state === s) handleAuthFailure()
            false
        }
    }

    /** D5: the fresh authenticated check required before every secret
     * display and mutation, reused within a rolling 30s window. */
    fun checkFresh(): Boolean {
        val s = state ?: return false
        val nowMs = now()
        if (nowMs - lastFreshCheckAt <= FRESH_CHECK_INTERVAL_MS) return true
        if (!maybeRefresh(s)) return false
        if (state !== s) return false
        return try {
            s.api.listDevices()
            if (state !== s) return false
            lastFreshCheckAt = now()
            true
        } catch (e: Exception) {
            if (state === s) handleAuthFailure()
            false
        }
    }

    fun listItems(): List<ItemSummary> {
        val s = state ?: return emptyList()
        return s.items.values.map { ItemSummary(it.itemId, it.data.title, it.data.type, it.data.username, it.data.url) }
    }

    fun getTotp(itemId: String): TotpDisplay? {
        val s = state ?: return null
        if (!checkFresh() || state !== s) return null
        val entry = s.items[itemId] ?: return null
        if (entry.data.type != "totp-login" || entry.data.totpSecret.isNullOrEmpty()) return null
        return try {
            val code = computeTotp(entry.data.totpSecret, atEpochMs = now())
            if (state !== s) null else TotpDisplay(code, secondsRemaining(30, now()))
        } catch (e: Exception) {
            null
        }
    }

    data class SaveItemInput(
        val itemId: String? = null,
        val type: String,
        val title: String,
        val username: String? = null,
        val password: String? = null,
        val url: String? = null,
        val notes: String? = null,
        val totpSecret: String? = null,
    )

    fun saveItem(input: SaveItemInput): SaveItemResult {
        val s = state ?: return SaveItemResult.Failed("locked")
        val data = VaultItemData(
            type = input.type,
            title = input.title,
            username = input.username,
            password = input.password,
            url = input.url,
            notes = input.notes,
            totpSecret = input.totpSecret,
        )
        val problems = validateItemData(data)
        if (problems.isNotEmpty()) return SaveItemResult.Failed("validation", problems)
        if (!checkFresh() || state !== s) return SaveItemResult.Failed("network")

        val itemId = input.itemId ?: randomUuid()
        val baseRevision = if (input.itemId != null) (s.items[input.itemId]?.revision ?: 0L) else 0L
        val envelope = try {
            s.session.sealItemPayload(s.accountId, s.vaultId, itemId, KEY_VERSION, encodeItemData(data))
        } catch (e: CryptoFfiException) {
            return SaveItemResult.Failed("locked")
        }

        val mutation = Mutation(
            mutationId = randomUuid(),
            itemId = itemId,
            vaultId = s.vaultId,
            baseRevision = baseRevision,
            ciphertext = encodeB64(envelope),
            envelopeVersion = ENVELOPE_VERSION,
            deleted = false,
        )
        return try {
            val outcome = s.api.mutateItem(s.vaultId, mutation)
            if (state !== s) return SaveItemResult.Failed("locked")
            if (outcome.status == 409) return SaveItemResult.Failed("conflict")
            s.items[itemId] = ItemEntry(itemId, outcome.item!!.revision, data)
            SaveItemResult.Ok(itemId)
        } catch (e: HttpError) {
            if (state === s && e.status == 401) handleAuthFailure()
            SaveItemResult.Failed("network")
        } catch (e: NetworkError) {
            SaveItemResult.Failed("network")
        }
    }

    private fun randomUuid(): String = UUID.randomUUID().toString()
}
