import { expect, test } from "bun:test";
import { AuthClient } from "../src/auth-client.ts";
import { ApiClient } from "../src/http-client.ts";
import { OPAQUE_CONTEXT, type OpaqueClient } from "../src/opaque-client.ts";
import { encodeB64 } from "../src/b64.ts";

/** Fake OpaqueClient standing in for packages/crypto-wasm's real binding:
 * a deterministic, non-cryptographic "protocol" that lets this test verify
 * AuthClient's HTTP choreography (which bytes go to which endpoint, in
 * which order, with which context) without needing a WASM build. The real
 * cryptographic round trip is covered by
 * packages/crypto-wasm/test/opaque-client.test.ts and (when a database is
 * available) this file's own end-to-end test below. */
function fakeOpaque(): OpaqueClient {
  const enc = new TextEncoder();
  return {
    clientRegistrationStart: (password) => ({ message: enc.encode(`reg-start:${password.length}`), state: enc.encode("reg-state") }),
    clientRegistrationFinish: () => ({ message: enc.encode("reg-finish") }),
    clientLoginStart: (password) => ({ message: enc.encode(`login-start:${password.length}`), state: enc.encode("login-state") }),
    clientLoginFinish: (_state, _password, _response, context) => ({
      message: enc.encode(`login-finish:${Buffer.from(context).toString()}`),
    }),
  };
}

function fakeFetch(handler: (url: string, body: unknown) => { status: number; body: unknown }): typeof fetch {
  return (async (input: RequestInfo | URL, init?: RequestInit) => {
    const body = init?.body ? JSON.parse(String(init.body)) : undefined;
    const { status, body: respBody } = handler(String(input), body);
    return new Response(JSON.stringify(respBody), { status });
  }) as typeof fetch;
}

test("register drives the two-leg /auth/opaque/register exchange in order", async () => {
  const calls: unknown[] = [];
  const api = new ApiClient({
    baseUrl: "https://x",
    fetchImpl: fakeFetch((url, body) => {
      calls.push({ url, body });
      return { status: 201, body: { message: encodeB64(new Uint8Array([1])) } };
    }),
  });
  const auth = new AuthClient(api, fakeOpaque());
  await auth.register("acct-1", new TextEncoder().encode("hunter2"));
  expect(calls).toHaveLength(2);
  expect((calls[0] as { url: string }).url).toBe("https://x/auth/opaque/register");
  expect((calls[1] as { url: string }).url).toBe("https://x/auth/opaque/register");
});

test("login drives the two-leg /auth/opaque/login exchange and sets the resulting access token", async () => {
  let leg = 0;
  const api = new ApiClient({
    baseUrl: "https://x",
    fetchImpl: fakeFetch(() => {
      leg += 1;
      if (leg === 1) return { status: 200, body: { message: encodeB64(new Uint8Array([2])) } };
      return { status: 200, body: { accessToken: "session-token", expiresAt: "2030-01-01T00:00:00Z" } };
    }),
  });
  const auth = new AuthClient(api, fakeOpaque());
  const session = await auth.login("acct-1", new TextEncoder().encode("hunter2"));
  expect(session.accessToken).toBe("session-token");
  expect(api.getAccessToken()).toBe("session-token");
});

test("login uses the fixed OPAQUE_CONTEXT bytes on the finish call, matching the real backend's OPAQUE_CONTEXT", async () => {
  let finishMessageBody: unknown;
  let leg = 0;
  const api = new ApiClient({
    baseUrl: "https://x",
    fetchImpl: fakeFetch((_url, body) => {
      leg += 1;
      if (leg === 1) return { status: 200, body: { message: encodeB64(new Uint8Array([2])) } };
      finishMessageBody = body;
      return { status: 200, body: { accessToken: "t", expiresAt: "2030-01-01T00:00:00Z" } };
    }),
  });
  await new AuthClient(api, fakeOpaque()).login("acct-1", new TextEncoder().encode("hunter2"));
  const expected = `login-finish:${Buffer.from(OPAQUE_CONTEXT).toString()}`;
  const decoded = Buffer.from(
    (finishMessageBody as { clientMessage: string }).clientMessage.slice(4),
    "base64",
  ).toString();
  expect(decoded).toBe(expected);
});
