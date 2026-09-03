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
