export type Id = string;

export interface Account { accountId: Id; createdAt: string; }
export interface Device { deviceId: Id; name: string; createdAt: string; lastSeenAt: string | null; revokedAt: string | null; }
export interface Vault { vaultId: Id; encryptedName: string; createdAt: string; updatedAt: string; }
export interface ItemRecord {
  itemId: Id; vaultId: Id; ciphertext: string; envelopeVersion: string;
  revision: number; deleted: boolean; createdAt: string; updatedAt: string;
}
export interface Mutation { mutationId: Id; itemId: Id; vaultId: Id; baseRevision: number; ciphertext: string; envelopeVersion: string; deleted: boolean; }
export interface ChangePage { changes: ItemRecord[]; nextCursor: string | null; }
export interface Conflict { error: "conflict"; mutationId: Id; current: ItemRecord; attempted: Mutation; }
export interface ApiError { error: string; message: string; requestId: string; }

/** ADR-0011 G1: `/account/key-bundle` PUT 409, distinct from sync's `Conflict` (which embeds an `ItemRecord`). */
export interface KeyBundleConflict { error: "key_bundle_conflict"; currentVersion: number | null; attemptedVersion: number; }

export interface KeyBundle { bundle: string; version: number; }

/** ADR-0011 G2: the legacy branch requires a stored `publicKey` (no proof-of-possession is implemented for it);
 * the `bearer-session-v1` branch trades that for an explicit bearer-only, revocable enrollment with no key material.
 * The two branches are disjoint — a request must match exactly one. */
export type DeviceCreate =
  | { name: string; publicKey: string }
  | { name: string; enrollmentMode: "bearer-session-v1" };
