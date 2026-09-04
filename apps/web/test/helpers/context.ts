import init from "crypto-wasm";
import { ApiClient, AuthClient } from "@zkpm/sdk";
import { CryptoWorkerClient } from "../../src/crypto/worker-client.ts";
import { IndexedDBLocalRepository } from "../../src/db/indexeddb-repository.ts";
import { Announcer } from "../../src/lib/announcer.ts";
import { createContext, type AppContext, type View } from "../../src/lib/context.ts";
import { createFakeFetch, createFakeCryptoWorker, fakeOpaqueClient, type FakeServerOptions } from "./fake-backend.ts";

let namespaceCounter = 0;

export async function buildTestContext(options: FakeServerOptions = {}): Promise<{ ctx: AppContext; container: HTMLElement; views: View[] }> {
  await init();
  const container = document.createElement("div");
  document.body.append(container);
  const announcer = new Announcer(document.body);
  const api = new ApiClient({ baseUrl: "http://vault.test.invalid", fetchImpl: createFakeFetch(options) });
  const auth = new AuthClient(api, fakeOpaqueClient);
  const cryptoClient = new CryptoWorkerClient(await createFakeCryptoWorker());
  namespaceCounter += 1;
  const repo = new IndexedDBLocalRepository(`test-ctx-${namespaceCounter}-${Date.now()}`);
  const views: View[] = [];
  const ctx = createContext({
    api, auth, crypto: cryptoClient, repo, announcer,
    navigate: (view) => { views.push(view); },
    resetInactivityTimer: () => {},
  });
  return { ctx, container, views };
}
