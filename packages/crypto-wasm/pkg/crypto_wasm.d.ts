/* tslint:disable */
/* eslint-disable */

/**
 * Browser-owned capability store. Keys never leave this Rust object; JS sees
 * only numeric session ids and encrypted/public bytes.
 */
export class WasmCrypto {
    free(): void;
    [Symbol.dispose](): void;
    close_session(session: number): void;
    /**
     * Runtime-only setup path: creates fresh keys internally and returns only
     * encrypted wrappers plus canonical public metadata. No key bytes leave
     * WASM; this enables binding lifecycle tests without static fixtures.
     */
    create_item_session_for_setup(password: Uint8Array, reported_physical_memory_kib: bigint): any;
    inspect_envelope(envelope: Uint8Array): any;
    constructor();
    open_item_payload(session: number, account_id: string, vault_id: string, item_id: string, key_version: bigint, envelope: Uint8Array): Uint8Array;
    seal_item_payload(session: number, account_id: string, vault_id: string, item_id: string, key_version: bigint, plaintext: Uint8Array): Uint8Array;
    /**
     * Opens the persisted password/account/vault/item envelope hierarchy
     * inside WASM. This is intentionally not an OPAQUE exchange: B03 has no
     * server transport authority and must not simulate one.
     */
    unlock_item_session(password: Uint8Array, kdf_parameters_cbor: Uint8Array, reported_physical_memory_kib: bigint, account_id: string, vault_id: string, item_id: string, account_key_version: bigint, vault_key_version: bigint, item_key_version: bigint, wrapped_account_key: Uint8Array, wrapped_vault_key: Uint8Array, wrapped_item_key: Uint8Array): number;
}

/**
 * Actual WASM export used for the cross-binding canonical-AAD golden vector.
 * It accepts identifiers only and cannot observe or return a key.
 */
export function encode_item_payload_aad(account_id: string, vault_id: string, item_id: string, key_version: bigint): Uint8Array;

export function protocol_status(): string;

export type InitInput = RequestInfo | URL | Response | BufferSource | WebAssembly.Module;

export interface InitOutput {
    readonly memory: WebAssembly.Memory;
    readonly __wbg_wasmcrypto_free: (a: number, b: number) => void;
    readonly encode_item_payload_aad: (a: number, b: number, c: number, d: number, e: number, f: number, g: bigint) => [number, number, number, number];
    readonly protocol_status: () => [number, number];
    readonly wasmcrypto_close_session: (a: number, b: number) => void;
    readonly wasmcrypto_create_item_session_for_setup: (a: number, b: number, c: number, d: bigint) => [number, number, number];
    readonly wasmcrypto_inspect_envelope: (a: number, b: number, c: number) => [number, number, number];
    readonly wasmcrypto_new: () => number;
    readonly wasmcrypto_open_item_payload: (a: number, b: number, c: number, d: number, e: number, f: number, g: number, h: number, i: bigint, j: number, k: number) => [number, number, number, number];
    readonly wasmcrypto_seal_item_payload: (a: number, b: number, c: number, d: number, e: number, f: number, g: number, h: number, i: bigint, j: number, k: number) => [number, number, number, number];
    readonly wasmcrypto_unlock_item_session: (a: number, b: number, c: number, d: number, e: number, f: bigint, g: number, h: number, i: number, j: number, k: number, l: number, m: bigint, n: bigint, o: bigint, p: number, q: number, r: number, s: number, t: number, u: number) => [number, number, number];
    readonly __wbindgen_exn_store: (a: number) => void;
    readonly __externref_table_alloc: () => number;
    readonly __wbindgen_externrefs: WebAssembly.Table;
    readonly __wbindgen_malloc: (a: number, b: number) => number;
    readonly __wbindgen_realloc: (a: number, b: number, c: number, d: number) => number;
    readonly __externref_table_dealloc: (a: number) => void;
    readonly __wbindgen_free: (a: number, b: number, c: number) => void;
    readonly __wbindgen_start: () => void;
}

export type SyncInitInput = BufferSource | WebAssembly.Module;

/**
 * Instantiates the given `module`, which can either be bytes or
 * a precompiled `WebAssembly.Module`.
 *
 * @param {{ module: SyncInitInput }} module - Passing `SyncInitInput` directly is deprecated.
 *
 * @returns {InitOutput}
 */
export function initSync(module: { module: SyncInitInput } | SyncInitInput): InitOutput;

/**
 * If `module_or_path` is {RequestInfo} or {URL}, makes a request and
 * for everything else, calls `WebAssembly.instantiate` directly.
 *
 * @param {{ module_or_path: InitInput | Promise<InitInput> }} module_or_path - Passing `InitInput` directly is deprecated.
 *
 * @returns {Promise<InitOutput>}
 */
export default function __wbg_init (module_or_path?: { module_or_path: InitInput | Promise<InitInput> } | InitInput | Promise<InitInput>): Promise<InitOutput>;
