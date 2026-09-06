package com.pass.android.net

import kotlinx.serialization.Serializable

/** Wire types mirroring `packages/contracts/src/index.ts` exactly — this
 * task's forbidden `packages/sdk`/contract paths mean these are a port, not
 * a shared import, matching the account-bundle-codec.ts precedent. */

@Serializable
data class Device(
    val deviceId: String,
    val name: String,
    val createdAt: String,
    val lastSeenAt: String? = null,
    val revokedAt: String? = null,
)

@Serializable
data class ItemRecord(
    val itemId: String,
    val vaultId: String,
    val ciphertext: String,
    val envelopeVersion: String,
    val revision: Long,
    val deleted: Boolean,
    val createdAt: String,
    val updatedAt: String,
)

@Serializable
data class Mutation(
    val mutationId: String,
    val itemId: String,
    val vaultId: String,
    val baseRevision: Long,
    val ciphertext: String,
    val envelopeVersion: String,
    val deleted: Boolean,
)

@Serializable
data class ChangePage(
    val changes: List<ItemRecord>,
    val nextCursor: String? = null,
)

@Serializable
data class Conflict(
    val error: String,
    val mutationId: String,
    val current: ItemRecord,
    val attempted: Mutation,
)

@Serializable
data class ApiError(
    val error: String,
    val message: String,
    val requestId: String,
)

@Serializable
data class KeyBundleConflict(
    val error: String,
    val currentVersion: Int? = null,
    val attemptedVersion: Int,
)

@Serializable
data class KeyBundle(
    val bundle: String,
    val version: Int,
)

@Serializable
data class Session(
    val accessToken: String,
    val expiresAt: String,
)

@Serializable
data class OpaqueStepRequest(
    val accountId: String,
    val clientMessage: String,
)

@Serializable
data class OpaqueMessageResponse(
    val message: String,
)

@Serializable
data class DeviceCreateBearerSession(
    val name: String,
    val enrollmentMode: String = "bearer-session-v1",
)
