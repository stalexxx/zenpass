import type { CryptoResponse } from "./protocol.ts";
import { CryptoWorkerHost } from "./index.ts";

export interface WorkerScope {
  addEventListener(type: "message" | "close", listener: (event: { data: unknown }) => void): void;
  postMessage(message: CryptoResponse): void;
}

/**
 * Installs the concrete Worker event boundary. Responses are copied before
 * posting, so callers cannot mutate a buffer still retained by a backend.
 * Worker termination drops the isolate; `close` additionally invokes dispose
 * when the runtime delivers that lifecycle event.
 */
export function installCryptoWorker(scope: WorkerScope, host: CryptoWorkerHost): void {
  scope.addEventListener("message", (event) => {
    const response = host.handle(event.data);
    scope.postMessage(copyResponse(response));
  });
  scope.addEventListener("close", () => host.dispose());
}

function copyResponse(response: CryptoResponse): CryptoResponse {
  if (response.ok && response.type === "bytes") {
    return { ...response, bytes: response.bytes.slice() };
  }
  if (response.ok && response.type === "account-setup") {
    const r = response.result;
    return {
      ...response,
      result: {
        ...r,
        kdfParametersCbor: r.kdfParametersCbor.slice(),
        wrappedAccountKey: r.wrappedAccountKey.slice(),
        wrappedVaultKey: r.wrappedVaultKey.slice(),
        wrappedItemKey: r.wrappedItemKey.slice(),
        wrappedRecoveryKey: r.wrappedRecoveryKey.slice(),
        recoveryKey: r.recoveryKey.slice(),
      },
    };
  }
  return response;
}
