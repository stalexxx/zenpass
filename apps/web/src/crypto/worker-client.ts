// Browser-side client for packages/crypto-worker's protocol. Spawns the
// real dedicated Worker (packages/crypto-worker/src/worker.ts) and drives
// it with the existing CryptoRequest/CryptoResponse discriminated union
// plus ADR-0008's two additions. This is the *only* place in apps/web that
// talks to the Worker — every other module goes through this client, so
// there is exactly one boundary to audit for "no raw key ever crosses back
// into the main thread" (per docs/ux/flows.md: "Unlock runs in a Worker
// and reports only success/failure plus vault data needed by the current
// view").
// Relative import (not the bare package name): packages/crypto-worker has
// no package.json "exports" field (B03 left it a source-only workspace
// package), and adding one is outside ADR-0008's narrow grant. Importing
// its protocol types by relative path avoids touching that package.json
// at all.
import type { CryptoRequest, CryptoResponse } from "../../../../packages/crypto-worker/src/protocol.ts";

export class CryptoError extends Error {
  constructor(readonly code: CryptoResponse["error"]) {
    super(`crypto worker error: ${code}`);
    this.name = "CryptoError";
  }
}

type Pending = { resolve: (value: CryptoResponse) => void; reject: (error: unknown) => void };

/** Thin request/response-by-id RPC layer over a real Worker. Holds no key
 * material itself (a session number is an opaque handle the Worker
 * resolves; nothing here can dereference it into bytes). */
export class CryptoWorkerClient {
  private worker: Worker;
  private pending = new Map<string, Pending>();
  private nextId = 1;

  constructor(worker?: Worker) {
    // Bun's bundler does not rewrite this URL string the way Vite/esbuild
    // do for `new Worker(new URL(...))` — it bundles src/worker-entry.ts
    // to its own dist/worker-entry.js entrypoint (see
    // apps/web/scripts/build.ts) but leaves this literal untouched. So
    // this deliberately points at the *built* sibling file relative to
    // the bundled main.js's own URL (both land directly in dist/), not at
    // the TypeScript source path — this only ever runs against the
    // production build in a real browser (tests supply a fake `worker`).
    this.worker = worker ?? new Worker(new URL("./worker-entry.js", import.meta.url), { type: "module" });
    this.worker.addEventListener("message", (event: MessageEvent<CryptoResponse>) => {
      const response = event.data;
      const pending = this.pending.get(response.id);
      if (!pending) return;
      this.pending.delete(response.id);
      pending.resolve(response);
    });
    this.worker.addEventListener("error", (event) => {
      // A Worker-level error (e.g. failed to load the module) fails every
      // outstanding request rather than hanging the UI forever.
      for (const [id, pending] of this.pending) {
        pending.reject(event.error ?? new Error("crypto worker error"));
        this.pending.delete(id);
      }
    });
  }

  private send(request: CryptoRequest): Promise<CryptoResponse> {
    return new Promise((resolve, reject) => {
      this.pending.set(request.id, { resolve, reject });
      this.worker.postMessage(request);
    });
  }

  private id(): string {
    const id = String(this.nextId);
    this.nextId += 1;
    return id;
  }

  private async call(request: CryptoRequest): Promise<CryptoResponse> {
    const response = await this.send(request);
    if (!response.ok) throw new CryptoError(response.error);
    return response;
  }

  async createAccountSetup(args: {
    password: Uint8Array;
    reportedPhysicalMemoryKiB: bigint;
    accountId: string;
    vaultId: string;
    itemId: string;
  }) {
    const response = await this.call({ id: this.id(), type: "create-account-setup", ...args });
    if (response.type !== "account-setup") throw new Error("unexpected response type");
    return response.result;
  }

  async unlockItemSession(args: Omit<Extract<CryptoRequest, { type: "unlock-item-session" }>, "id" | "type">): Promise<number> {
    const response = await this.call({ id: this.id(), type: "unlock-item-session", ...args });
    if (response.type !== "session") throw new Error("unexpected response type");
    return response.session;
  }

  async unlockItemSessionWithRecovery(
    args: Omit<Extract<CryptoRequest, { type: "unlock-item-session-with-recovery" }>, "id" | "type">,
  ): Promise<number> {
    const response = await this.call({ id: this.id(), type: "unlock-item-session-with-recovery", ...args });
    if (response.type !== "session") throw new Error("unexpected response type");
    return response.session;
  }

  async sealItemPayload(session: number, accountId: string, vaultId: string, itemId: string, keyVersion: bigint, plaintext: Uint8Array): Promise<Uint8Array> {
    const response = await this.call({ id: this.id(), type: "seal-item-payload", session, accountId, vaultId, itemId, keyVersion, plaintext });
    if (response.type !== "bytes") throw new Error("unexpected response type");
    return response.bytes;
  }

  async openItemPayload(session: number, accountId: string, vaultId: string, itemId: string, keyVersion: bigint, envelope: Uint8Array): Promise<Uint8Array> {
    const response = await this.call({ id: this.id(), type: "open-item-payload", session, accountId, vaultId, itemId, keyVersion, envelope });
    if (response.type !== "bytes") throw new Error("unexpected response type");
    return response.bytes;
  }

  async lock(): Promise<void> {
    await this.call({ id: this.id(), type: "lock" });
  }

  /** Terminates the underlying Worker outright (e.g. on page unload).
   * Prefer `lock()` for a normal lock — this is for teardown. */
  terminate(): void {
    this.worker.terminate();
    for (const [id, pending] of this.pending) {
      pending.reject(new Error("crypto worker terminated"));
      this.pending.delete(id);
    }
  }
}
