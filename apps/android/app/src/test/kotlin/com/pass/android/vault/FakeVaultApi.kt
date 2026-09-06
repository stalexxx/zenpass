package com.pass.android.vault

import com.pass.android.net.ChangePage
import com.pass.android.net.Device
import com.pass.android.net.GetKeyBundleOutcome
import com.pass.android.net.HttpError
import com.pass.android.net.ItemRecord
import com.pass.android.net.KeyBundle
import com.pass.android.net.Mutation
import com.pass.android.net.MutateOutcome
import com.pass.android.net.OpaqueStepOutcome
import com.pass.android.net.Session
import com.pass.android.net.VaultApi

/** A programmable fake of [VaultApi] for VaultManager's lifecycle unit
 * tests (D02-MVP's "lifecycle/lock-on-failure behavior with a fake API
 * client" requirement) — no OkHttp/network involved. */
class FakeVaultApi : VaultApi {
    private var accessTokenValue: String? = null

    var loginStepResponses: MutableList<OpaqueStepOutcome> = mutableListOf()
    var registerBearerSessionDeviceResult: (() -> Device) = { Device("device-1", "test", "now", null, null) }
    var getKeyBundleResult: (() -> GetKeyBundleOutcome) = { GetKeyBundleOutcome(404) }
    var listChangesResult: (() -> ChangePage) = { ChangePage(emptyList(), null) }
    var listDevicesResult: (() -> List<Device>) = { emptyList() }
    var refreshResult: (() -> Session) = { Session("refreshed-token", "2999-01-01T00:00:00Z") }
    var mutateItemResult: ((String, Mutation) -> MutateOutcome)? = null

    var listDevicesCallCount = 0
        private set
    var refreshCallCount = 0
        private set
    var logoutCallCount = 0
        private set

    override fun setAccessToken(token: String?) {
        accessTokenValue = token
    }

    override fun getAccessToken(): String? = accessTokenValue

    override fun opaqueLoginStep(accountId: String, clientMessageB64: String): OpaqueStepOutcome {
        return loginStepResponses.removeAt(0)
    }

    override fun refresh(): Session {
        refreshCallCount += 1
        return refreshResult()
    }

    override fun logout() {
        logoutCallCount += 1
        accessTokenValue = null
    }

    override fun listDevices(): List<Device> {
        listDevicesCallCount += 1
        return listDevicesResult()
    }

    override fun registerBearerSessionDevice(name: String): Device = registerBearerSessionDeviceResult()

    override fun getKeyBundle(): GetKeyBundleOutcome = getKeyBundleResult()

    override fun mutateItem(vaultId: String, mutation: Mutation): MutateOutcome =
        mutateItemResult?.invoke(vaultId, mutation) ?: MutateOutcome(
            201,
            item = ItemRecord(mutation.itemId, mutation.vaultId, mutation.ciphertext, mutation.envelopeVersion, mutation.baseRevision + 1, false, "now", "now"),
        )

    override fun listChanges(vaultId: String, cursor: String?, limit: Int?): ChangePage = listChangesResult()
}

fun httpUnauthorized(): Nothing = throw HttpError(401, null)
