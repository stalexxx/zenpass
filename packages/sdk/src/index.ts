export { ApiClient, HttpError, NetworkError } from "./http-client.ts";
export type {
  ApiClientOptions,
  MutateOutcome,
  MutateConflictOutcome,
  GetKeyBundleOutcome,
  PutKeyBundleOutcome,
} from "./http-client.ts";
export { buildAccountBundle, parseAccountBundle, ACCOUNT_BUNDLE_FORMAT } from "./account-bundle-codec.ts";
export type { AccountBundleBytes, AccountBundleFields } from "./account-bundle-codec.ts";
export { AuthClient } from "./auth-client.ts";
export { OPAQUE_CONTEXT, createWasmOpaqueClient } from "./opaque-client.ts";
export type { OpaqueClient, OpaqueStartResult, OpaqueFinishResult } from "./opaque-client.ts";
export { SyncEngine, retryDelayMs } from "./sync-state-machine.ts";
export type { MutationSyncState, BackoffOptions, PushOutcome, PullOutcome } from "./sync-state-machine.ts";
export { InMemoryLocalRepository, RecordConflictError, assertMonotonicPut } from "./repository.ts";
export type { LocalRepository, QueuedMutation } from "./repository.ts";
export { encodeB64, decodeB64 } from "./b64.ts";
export type { Session } from "./types.ts";
export type {
  Id,
  Account,
  Device,
  Vault,
  ItemRecord,
  Mutation,
  ChangePage,
  Conflict,
  ApiError,
  KeyBundle,
  KeyBundleConflict,
  DeviceCreate,
} from "./types.ts";
