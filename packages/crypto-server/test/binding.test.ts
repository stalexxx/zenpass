import { expect, test } from "bun:test";
import init, {
  generate_server_setup,
  login_finish,
  login_start,
  registration_step,
} from "../pkg/crypto_server.js";
import {
  client_login_finish,
  client_login_start,
  client_registration_finish,
  client_registration_start,
} from "../pkg/crypto_server.js";

const CONTEXT = new TextEncoder().encode("zkpm-opaque-v1");
const PASSWORD = new TextEncoder().encode("CorrectHorseBatteryStaple");
const WRONG_PASSWORD = new TextEncoder().encode("WrongHorseBatteryStaple");

await init();

function register(setup: Uint8Array, accountId: string, password: Uint8Array) {
  const start = client_registration_start(password);
  const stepA = registration_step(setup, accountId, start.message);
  expect(stepA.step).toBe("response");
  const finish = client_registration_finish(start.state, password, stepA.message);
  const stepB = registration_step(setup, accountId, finish.message);
  expect(stepB.step).toBe("record");
  return stepB.message as Uint8Array; // opaque_credentials.credential_record
}

test("registration then login round trip succeeds through the real generated WASM binding", () => {
  const setup = generate_server_setup();
  const accountId = "account-1";
  const passwordFile = register(setup, accountId, PASSWORD);

  const login = client_login_start(PASSWORD);
  const challenge = login_start(setup, passwordFile, accountId, login.message, CONTEXT);
  expect(challenge.message).toBeInstanceOf(Uint8Array);
  expect(challenge.state).toBeInstanceOf(Uint8Array);

  const clientFinish = client_login_finish(login.state, PASSWORD, challenge.message, CONTEXT);
  // Must not throw: proves the server accepted a genuine password proof.
  login_finish(challenge.state, clientFinish.message, CONTEXT);
});

test("wrong password fails generically at the client login-finish step", () => {
  const setup = generate_server_setup();
  const accountId = "account-2";
  const passwordFile = register(setup, accountId, PASSWORD);

  const login = client_login_start(WRONG_PASSWORD);
  const challenge = login_start(setup, passwordFile, accountId, login.message, CONTEXT);

  expect(() => client_login_finish(login.state, WRONG_PASSWORD, challenge.message, CONTEXT)).toThrow(
    "AuthenticationFailed"
  );
});

test("tampered KE2 fails login_finish generically", () => {
  const setup = generate_server_setup();
  const accountId = "account-3";
  const passwordFile = register(setup, accountId, PASSWORD);

  const login = client_login_start(PASSWORD);
  const challenge = login_start(setup, passwordFile, accountId, login.message, CONTEXT);
  const tampered = new Uint8Array(challenge.message);
  tampered[0] ^= 0x01;

  expect(() => client_login_finish(login.state, PASSWORD, tampered, CONTEXT)).toThrow(
    "AuthenticationFailed"
  );
});

test("context substitution fails login_finish generically", () => {
  const setup = generate_server_setup();
  const accountId = "account-4";
  const passwordFile = register(setup, accountId, PASSWORD);
  const otherContext = new TextEncoder().encode("zkpm-opaque-v1-OTHER");

  const login = client_login_start(PASSWORD);
  const challenge = login_start(setup, passwordFile, accountId, login.message, otherContext);

  expect(() => client_login_finish(login.state, PASSWORD, challenge.message, CONTEXT)).toThrow(
    "AuthenticationFailed"
  );
});

test("registration_step rejects a malformed client message generically", () => {
  const setup = generate_server_setup();
  expect(() => registration_step(setup, "account-5", new Uint8Array([1, 2, 3]))).toThrow();
});

test("login_start rejects a malformed KE1 generically", () => {
  const setup = generate_server_setup();
  expect(() =>
    login_start(setup, new Uint8Array(32).fill(7), "account-6", new Uint8Array([9, 9, 9]), CONTEXT)
  ).toThrow();
});

test("login_finish rejects corrupt state bytes as InvalidEncoding", () => {
  expect(() =>
    login_finish(new Uint8Array([0, 0, 0, 0]), new Uint8Array([0, 0, 0, 0]), CONTEXT)
  ).toThrow("InvalidEncoding");
});

test("registration_step and login_start reject setup bytes that aren't valid server setup", () => {
  const bogusSetup = new Uint8Array(4);
  expect(() => registration_step(bogusSetup, "account-7", new Uint8Array(32))).toThrow(
    "InvalidEncoding"
  );
  expect(() =>
    login_start(bogusSetup, new Uint8Array(32), "account-7", new Uint8Array(32), CONTEXT)
  ).toThrow("InvalidEncoding");
});

test("generate_server_setup returns fresh, non-empty material each call", () => {
  const a = generate_server_setup();
  const b = generate_server_setup();
  expect(a.length).toBeGreaterThan(0);
  expect(Buffer.from(a).equals(Buffer.from(b))).toBe(false);
});
