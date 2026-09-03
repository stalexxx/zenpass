import { expect, test } from "bun:test";
import init, {
  client_login_finish,
  client_login_start,
  client_registration_finish,
  client_registration_start,
} from "../pkg/crypto_wasm.js";

// ADR-0007: these are the production browser OPAQUE client exports. There is
// no server counterpart inside `packages/crypto-wasm` itself (by design —
// see ARCHITECTURE-GAPS.md/ADR-0006), so a real protocol round trip is
// driven here against `packages/crypto-server`'s generated WASM module,
// purely as a test-only dependency (this file only; crypto-wasm's own
// Cargo.toml/production code gains no new dependency).
import init2, {
  generate_server_setup,
  login_finish,
  login_start,
  registration_step,
} from "../../crypto-server/pkg/crypto_server.js";

const CONTEXT = new TextEncoder().encode("zkpm-opaque-v1");
const PASSWORD = new TextEncoder().encode("CorrectHorseBatteryStaple");
const WRONG_PASSWORD = new TextEncoder().encode("WrongHorseBatteryStaple");

await init();
await init2();

function register(setup: Uint8Array, accountId: string, password: Uint8Array) {
  const start = client_registration_start(password) as Record<string, Uint8Array>;
  const stepA = registration_step(setup, accountId, start.message) as Record<string, unknown>;
  expect(stepA.step).toBe("response");
  const finish = client_registration_finish(start.state, password, stepA.message as Uint8Array) as Record<
    string,
    Uint8Array
  >;
  const stepB = registration_step(setup, accountId, finish.message) as Record<string, unknown>;
  expect(stepB.step).toBe("record");
  return stepB.message as Uint8Array;
}

test("crypto-wasm's client OPAQUE exports complete a real registration+login round trip against a real server binding", () => {
  const setup = generate_server_setup();
  const accountId = "wasm-account-1";
  const passwordFile = register(setup, accountId, PASSWORD);

  const login = client_login_start(PASSWORD) as Record<string, Uint8Array>;
  const challenge = login_start(setup, passwordFile, accountId, login.message, CONTEXT) as Record<
    string,
    Uint8Array
  >;
  expect(challenge.message).toBeInstanceOf(Uint8Array);
  expect(challenge.state).toBeInstanceOf(Uint8Array);

  const clientFinish = client_login_finish(login.state, PASSWORD, challenge.message, CONTEXT) as Record<
    string,
    Uint8Array
  >;
  // Must not throw: proves the real server accepted a genuine password proof
  // produced by crypto-wasm's client binding.
  login_finish(challenge.state, clientFinish.message, CONTEXT);
});

test("wrong password fails generically at client_login_finish", () => {
  const setup = generate_server_setup();
  const accountId = "wasm-account-2";
  const passwordFile = register(setup, accountId, PASSWORD);

  const login = client_login_start(WRONG_PASSWORD) as Record<string, Uint8Array>;
  const challenge = login_start(setup, passwordFile, accountId, login.message, CONTEXT) as Record<
    string,
    Uint8Array
  >;

  expect(() => client_login_finish(login.state, WRONG_PASSWORD, challenge.message, CONTEXT)).toThrow(
    "AuthenticationFailed",
  );
});

test("wrong context fails generically at client_login_finish", () => {
  const setup = generate_server_setup();
  const accountId = "wasm-account-3";
  const passwordFile = register(setup, accountId, PASSWORD);
  const otherContext = new TextEncoder().encode("zkpm-opaque-v1-OTHER");

  const login = client_login_start(PASSWORD) as Record<string, Uint8Array>;
  const challenge = login_start(setup, passwordFile, accountId, login.message, otherContext) as Record<
    string,
    Uint8Array
  >;

  expect(() => client_login_finish(login.state, PASSWORD, challenge.message, CONTEXT)).toThrow(
    "AuthenticationFailed",
  );
});

test("client_registration_finish rejects corrupt state bytes as InvalidEncoding", () => {
  expect(() =>
    client_registration_finish(new Uint8Array([0, 0, 0, 0]), PASSWORD, new Uint8Array(32)),
  ).toThrow("InvalidEncoding");
});

test("client_login_finish rejects corrupt state bytes as InvalidEncoding", () => {
  expect(() =>
    client_login_finish(new Uint8Array([0, 0, 0, 0]), PASSWORD, new Uint8Array(32), CONTEXT),
  ).toThrow("InvalidEncoding");
});
