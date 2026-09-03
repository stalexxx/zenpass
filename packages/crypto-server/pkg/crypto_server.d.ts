/* tslint:disable */
/* eslint-disable */

export function client_login_finish(state: Uint8Array, password: Uint8Array, response: Uint8Array, context: Uint8Array): any;

export function client_login_start(password: Uint8Array): any;

export function client_registration_finish(state: Uint8Array, password: Uint8Array, response: Uint8Array): any;

export function client_registration_start(password: Uint8Array): any;

/**
 * Generate fresh process-wide server setup material (private key + OPRF
 * seed). Callers persist the returned bytes out-of-band (ADR-0006 §3); this
 * function never stores anything itself.
 */
export function generate_server_setup(): Uint8Array;

/**
 * Finish server login (KE3). Succeeds only if the client proved knowledge
 * of the registered password against the given `state`; the caller then
 * treats the login as authenticated and issues its own session token (this
 * binding intentionally does not return the OPAQUE session key — the
 * backend's session token is independent, ADR-0005 §1).
 */
export function login_finish(state: Uint8Array, ke3: Uint8Array, context: Uint8Array): void;

/**
 * Begin server login (KE1 -> KE2). `password_file` is the stored
 * `opaque_credentials.credential_record` for this account; callers must not
 * invoke this without one (ADR-0006 §9: unknown accounts are rejected
 * before reaching this binding, not inside it). Returns
 * `{ message, state }`: `message` is the KE2 challenge for the client,
 * `state` is opaque server login state the caller must hold (e.g. an
 * in-process map keyed by account id, ADR-0006 §6) and pass to
 * `login_finish` unmodified.
 */
export function login_start(setup: Uint8Array, password_file: Uint8Array, credential_identifier: string, ke1: Uint8Array, context: Uint8Array): any;

export function registration_step(setup: Uint8Array, credential_identifier: string, client_message: Uint8Array): any;

export type InitInput = RequestInfo | URL | Response | BufferSource | WebAssembly.Module;

export interface InitOutput {
    readonly memory: WebAssembly.Memory;
    readonly client_login_finish: (a: number, b: number, c: number, d: number, e: number, f: number, g: number, h: number) => [number, number, number];
    readonly client_login_start: (a: number, b: number) => [number, number, number];
    readonly client_registration_finish: (a: number, b: number, c: number, d: number, e: number, f: number) => [number, number, number];
    readonly client_registration_start: (a: number, b: number) => [number, number, number];
    readonly generate_server_setup: () => [number, number];
    readonly login_finish: (a: number, b: number, c: number, d: number, e: number, f: number) => [number, number];
    readonly login_start: (a: number, b: number, c: number, d: number, e: number, f: number, g: number, h: number, i: number, j: number) => [number, number, number];
    readonly registration_step: (a: number, b: number, c: number, d: number, e: number, f: number) => [number, number, number];
    readonly __wbindgen_exn_store: (a: number) => void;
    readonly __externref_table_alloc: () => number;
    readonly __wbindgen_externrefs: WebAssembly.Table;
    readonly __wbindgen_malloc: (a: number, b: number) => number;
    readonly __externref_table_dealloc: (a: number) => void;
    readonly __wbindgen_free: (a: number, b: number, c: number) => void;
    readonly __wbindgen_realloc: (a: number, b: number, c: number, d: number) => number;
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
