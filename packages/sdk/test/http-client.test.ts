import { expect, test } from "bun:test";
import { ApiClient, HttpError, NetworkError } from "../src/http-client.ts";
import { decodeB64, encodeB64 } from "../src/b64.ts";
import type { Mutation } from "../src/types.ts";

interface Call {
  url: string;
  method: string;
  headers: Record<string, string>;
  body: unknown;
}

function fakeFetch(handler: (call: Call) => { status: number; body: unknown }): typeof fetch {
  return (async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = String(input);
    const headers: Record<string, string> = {};
    new Headers(init?.headers).forEach((v, k) => (headers[k] = v));
    const body = init?.body ? JSON.parse(String(init.body)) : undefined;
    const { status, body: respBody } = handler({ url, method: init?.method ?? "GET", headers, body });
    const text = respBody === undefined ? "" : JSON.stringify(respBody);
    return new Response(text, { status });
  }) as typeof fetch;
}

test("opaqueRegisterStep sends a b64:-prefixed clientMessage and decodes a b64:-prefixed response, matching apps/backend's codec", async () => {
  let seenCall: Call | undefined;
  const client = new ApiClient({
    baseUrl: "https://api.example",
    fetchImpl: fakeFetch((call) => {
      seenCall = call;
      return { status: 201, body: { message: encodeB64(new Uint8Array([9, 9])) } };
    }),
  });
  const result = await client.opaqueRegisterStep("acct-1", new Uint8Array([1, 2, 3]));
  expect(seenCall?.url).toBe("https://api.example/auth/opaque/register");
  expect(seenCall?.method).toBe("POST");
  expect(seenCall?.body).toEqual({ accountId: "acct-1", clientMessage: "b64:AQID" });
  expect(result).toEqual(new Uint8Array([9, 9]));
});

test("opaqueLoginStep discriminates a message response from a session response", async () => {
  let call = 0;
  const client = new ApiClient({
    baseUrl: "https://api.example",
    fetchImpl: fakeFetch(() => {
      call += 1;
      if (call === 1) return { status: 200, body: { message: encodeB64(new Uint8Array([1])) } };
      return { status: 200, body: { accessToken: "tok", expiresAt: "2030-01-01T00:00:00Z" } };
    }),
  });
  const leg1 = await client.opaqueLoginStep("acct-1", new Uint8Array([1]));
  expect(leg1.kind).toBe("message");
  const leg2 = await client.opaqueLoginStep("acct-1", new Uint8Array([1]));
  expect(leg2).toEqual({ kind: "session", session: { accessToken: "tok", expiresAt: "2030-01-01T00:00:00Z" } });
});

test("authenticated calls attach an Authorization: Bearer header and refuse without a token", async () => {
  const client = new ApiClient({
    baseUrl: "https://api.example",
    fetchImpl: fakeFetch(() => ({ status: 200, body: { devices: [] } })),
  });
  await expect(client.listDevices()).rejects.toThrow(/no access token/);
  client.setAccessToken("secret-token");
  let seenAuth: string | undefined;
  const client2 = new ApiClient({
    baseUrl: "https://api.example",
    fetchImpl: fakeFetch((call) => {
      seenAuth = call.headers.authorization;
      return { status: 200, body: { devices: [] } };
    }),
  });
  client2.setAccessToken("secret-token");
  await client2.listDevices();
  expect(seenAuth).toBe("Bearer secret-token");
});

test("registerDevice/revokeDevice match the contract's request/response shapes", async () => {
  const calls: Call[] = [];
  const client = new ApiClient({
    baseUrl: "https://api.example",
    fetchImpl: fakeFetch((call) => {
      calls.push(call);
      if (call.url.endsWith("/devices")) {
        return {
          status: 201,
          body: { deviceId: "d1", name: "Laptop", createdAt: "2030-01-01T00:00:00Z", lastSeenAt: null, revokedAt: null },
        };
      }
      return { status: 204, body: undefined };
    }),
  });
  client.setAccessToken("t");
  const device = await client.registerDevice("Laptop", new Uint8Array([7]));
  expect(device.deviceId).toBe("d1");
  expect(calls[0].body).toEqual({ name: "Laptop", publicKey: "b64:Bw==" });
  await client.revokeDevice("d1");
  expect(calls[1].url).toBe("https://api.example/devices/d1/revoke");
});

test("mutateItem returns a typed 201 outcome without throwing", async () => {
  const mutation: Mutation = {
    mutationId: "m1",
    itemId: "i1",
    vaultId: "v1",
    baseRevision: 0,
    ciphertext: "b64:AAAA",
    envelopeVersion: "crypto-envelope/v1",
    deleted: false,
  };
  const client = new ApiClient({
    baseUrl: "https://api.example",
    fetchImpl: fakeFetch(() => ({
      status: 201,
      body: {
        itemId: "i1",
        vaultId: "v1",
        ciphertext: "b64:AAAA",
        envelopeVersion: "crypto-envelope/v1",
        revision: 1,
        deleted: false,
        createdAt: "2030-01-01T00:00:00Z",
        updatedAt: "2030-01-01T00:00:00Z",
      },
    })),
  });
  client.setAccessToken("t");
  const outcome = await client.mutateItem("v1", mutation);
  expect(outcome.status).toBe(201);
});

test("mutateItem returns a typed 409 Conflict outcome without throwing", async () => {
  const mutation: Mutation = {
    mutationId: "m1",
    itemId: "i1",
    vaultId: "v1",
    baseRevision: 0,
    ciphertext: "b64:AAAA",
    envelopeVersion: "crypto-envelope/v1",
    deleted: false,
  };
  const conflictBody = {
    error: "conflict",
    mutationId: "m1",
    current: {
      itemId: "i1",
      vaultId: "v1",
      ciphertext: "b64:ZZZZ",
      envelopeVersion: "crypto-envelope/v1",
      revision: 2,
      deleted: false,
      createdAt: "2030-01-01T00:00:00Z",
      updatedAt: "2030-01-01T00:00:00Z",
    },
    attempted: mutation,
  };
  const client = new ApiClient({
    baseUrl: "https://api.example",
    fetchImpl: fakeFetch(() => ({ status: 409, body: conflictBody })),
  });
  client.setAccessToken("t");
  const outcome = await client.mutateItem("v1", mutation);
  expect(outcome.status).toBe(409);
  if (outcome.status === 409) expect(outcome.conflict).toEqual(conflictBody);
});

test("other non-2xx statuses throw HttpError, e.g. a 400 from mutateItem", async () => {
  const mutation: Mutation = {
    mutationId: "m1",
    itemId: "i1",
    vaultId: "v1",
    baseRevision: 0,
    ciphertext: "b64:AAAA",
    envelopeVersion: "crypto-envelope/v1",
    deleted: false,
  };
  const client = new ApiClient({
    baseUrl: "https://api.example",
    fetchImpl: fakeFetch(() => ({ status: 400, body: { error: "bad_request", message: "x", requestId: "r" } })),
  });
  client.setAccessToken("t");
  await expect(client.mutateItem("v1", mutation)).rejects.toThrow(HttpError);
});

test("a fetch rejection surfaces as NetworkError, distinct from HttpError", async () => {
  const client = new ApiClient({
    baseUrl: "https://api.example",
    fetchImpl: (async () => {
      throw new Error("ECONNREFUSED");
    }) as typeof fetch,
  });
  client.setAccessToken("t");
  await expect(client.listDevices()).rejects.toThrow(NetworkError);
});

test("does not bind an injected fetch implementation to ApiClient", async () => {
  const receiverSensitiveFetch = function (this: unknown) {
    if (this !== undefined) throw new TypeError("Illegal invocation");
    return Promise.resolve(new Response(JSON.stringify({ devices: [] }), { status: 200 }));
  } as unknown as typeof fetch;
  const client = new ApiClient({ baseUrl: "https://api.example", fetchImpl: receiverSensitiveFetch });
  client.setAccessToken("t");
  await expect(client.listDevices()).resolves.toEqual([]);
});

test("listChanges passes cursor/limit as query params and returns the ChangePage as-is", async () => {
  let seenUrl = "";
  const client = new ApiClient({
    baseUrl: "https://api.example",
    fetchImpl: fakeFetch((call) => {
      seenUrl = call.url;
      return { status: 200, body: { changes: [], nextCursor: "MA" } };
    }),
  });
  client.setAccessToken("t");
  const page = await client.listChanges("v1", "MA", 50);
  expect(seenUrl).toBe("https://api.example/vaults/v1/changes?cursor=MA&limit=50");
  expect(page).toEqual({ changes: [], nextCursor: "MA" });
});

test("getKeyBundle returns a typed 200 result", async () => {
  const client = new ApiClient({
    baseUrl: "https://api.example",
    fetchImpl: fakeFetch(() => ({ status: 200, body: { bundle: "b64:AA==", version: 3 } })),
  });
  client.setAccessToken("t");
  const result = await client.getKeyBundle();
  expect(result).toEqual({ status: 200, keyBundle: { bundle: "b64:AA==", version: 3 } });
});

test("getKeyBundle returns { status: 404 } as a value, not an error, when unpublished", async () => {
  const client = new ApiClient({
    baseUrl: "https://api.example",
    fetchImpl: fakeFetch(() => ({ status: 404, body: { error: "not_found", message: "x", requestId: "r" } })),
  });
  client.setAccessToken("t");
  const result = await client.getKeyBundle();
  expect(result).toEqual({ status: 404 });
});

test("getKeyBundle throws HttpError for any other non-2xx status", async () => {
  const client = new ApiClient({
    baseUrl: "https://api.example",
    fetchImpl: fakeFetch(() => ({ status: 401, body: { error: "authentication_failed", message: "x", requestId: "r" } })),
  });
  client.setAccessToken("t");
  await expect(client.getKeyBundle()).rejects.toThrow(HttpError);
});

test("putKeyBundle sends the KeyBundle body and returns 204 as a value", async () => {
  let seenCall: Call | undefined;
  const client = new ApiClient({
    baseUrl: "https://api.example",
    fetchImpl: fakeFetch((call) => {
      seenCall = call;
      return { status: 204, body: undefined };
    }),
  });
  client.setAccessToken("t");
  const result = await client.putKeyBundle({ bundle: "b64:AA==", version: 1 });
  expect(seenCall?.method).toBe("PUT");
  expect(seenCall?.url).toBe("https://api.example/account/key-bundle");
  expect(seenCall?.body).toEqual({ bundle: "b64:AA==", version: 1 });
  expect(result).toEqual({ status: 204 });
});

test("putKeyBundle returns a 409 KeyBundleConflict as a value, not a thrown error", async () => {
  const client = new ApiClient({
    baseUrl: "https://api.example",
    fetchImpl: fakeFetch(() => ({
      status: 409,
      body: { error: "key_bundle_conflict", currentVersion: 2, attemptedVersion: 1 },
    })),
  });
  client.setAccessToken("t");
  const result = await client.putKeyBundle({ bundle: "b64:AA==", version: 1 });
  expect(result).toEqual({
    status: 409,
    conflict: { error: "key_bundle_conflict", currentVersion: 2, attemptedVersion: 1 },
  });
});

test("registerBearerSessionDevice sends the disjoint enrollmentMode branch, never publicKey", async () => {
  let seenCall: Call | undefined;
  const client = new ApiClient({
    baseUrl: "https://api.example",
    fetchImpl: fakeFetch((call) => {
      seenCall = call;
      return {
        status: 201,
        body: { deviceId: "dev-1", name: "Extension", createdAt: "2026-01-01T00:00:00Z", lastSeenAt: null, revokedAt: null },
      };
    }),
  });
  client.setAccessToken("t");
  const device = await client.registerBearerSessionDevice("Extension");
  expect(seenCall?.body).toEqual({ name: "Extension", enrollmentMode: "bearer-session-v1" });
  expect("publicKey" in (seenCall?.body as object)).toBe(false);
  expect(device.deviceId).toBe("dev-1");
});

test("b64 codec round-trips and matches the fixed b64: prefix", () => {
  const bytes = new Uint8Array([0, 1, 2, 253, 254, 255]);
  const encoded = encodeB64(bytes);
  expect(encoded.startsWith("b64:")).toBe(true);
  expect(decodeB64(encoded)).toEqual(bytes);
});
