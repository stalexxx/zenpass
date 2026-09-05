import { expect, test } from "bun:test";
import {
  ACCOUNT_BUNDLE_FIELDS,
  MAX_KDF_PARAMS_BYTES,
  MAX_WRAPPER_BYTES,
  buildAccountBundle,
  parseAccountBundle,
} from "../src/account-bundle-codec.ts";

function bytes(label: string, length = label.length): Uint8Array {
  const out = new Uint8Array(length);
  for (let i = 0; i < length; i += 1) out[i] = label.charCodeAt(i % label.length);
  return out;
}

function validBytesInput() {
  return {
    accountId: "acct-01",
    vaultId: "vault-01",
    itemId: "item-01",
    kdfParametersCbor: bytes("kdf"),
    wrappedAccountKey: bytes("account-key"),
    wrappedVaultKey: bytes("vault-key"),
    wrappedItemKey: bytes("item-key"),
    wrappedRecoveryKey: bytes("recovery-key"),
  };
}

test("buildAccountBundle then parseAccountBundle round-trips exactly", () => {
  const input = validBytesInput();
  const wire = buildAccountBundle(input);
  expect(wire.startsWith("b64:")).toBe(true);
  const parsed = parseAccountBundle(wire);
  expect(parsed?.accountId).toBe("acct-01");
  expect(parsed?.vaultId).toBe("vault-01");
  expect(parsed?.itemId).toBe("item-01");
  expect(parsed?.format).toBe("c04-account-bundle/1");
});

test("rejects a non-b64:-prefixed wire value", () => {
  expect(parseAccountBundle("not-b64")).toBeNull();
});

test("rejects an unrecognized format", () => {
  const wire = buildAccountBundle(validBytesInput());
  const tampered = tamperField(wire, "format", "other/1");
  expect(parseAccountBundle(tampered)).toBeNull();
});

test("rejects duplicate keys that JSON.parse would otherwise silently collapse", () => {
  const input = validBytesInput();
  const wire = buildAccountBundle(input);
  const decoded = atob(wire.slice("b64:".length));
  // Insert a duplicate "format" key right after the opening brace.
  const injected = decoded.replace('{"format"', '{"format":"c04-account-bundle/1","format"');
  const reEncoded = "b64:" + btoa(injected);
  expect(parseAccountBundle(reEncoded)).toBeNull();
});

test("rejects an unknown extra field", () => {
  const input = validBytesInput();
  const wire = buildAccountBundle(input);
  const decoded = JSON.parse(atob(wire.slice("b64:".length)));
  decoded.extra = "nope";
  const reEncoded = "b64:" + btoa(JSON.stringify(decoded));
  expect(parseAccountBundle(reEncoded)).toBeNull();
});

test("rejects a missing field", () => {
  const input = validBytesInput();
  const wire = buildAccountBundle(input);
  const decoded = JSON.parse(atob(wire.slice("b64:".length)));
  delete decoded.wrappedRecoveryKey;
  const reEncoded = "b64:" + btoa(JSON.stringify(decoded));
  expect(parseAccountBundle(reEncoded)).toBeNull();
});

test("rejects a malformed account/vault/item id", () => {
  expect(parseAccountBundle(buildAccountBundle({ ...validBytesInput(), itemId: "has a space" }))).toBeNull();
});

test("rejects a wrapper exceeding the 64 KiB cap", () => {
  const oversized = { ...validBytesInput(), wrappedItemKey: bytes("x", MAX_WRAPPER_BYTES + 1) };
  expect(parseAccountBundle(buildAccountBundle(oversized))).toBeNull();
});

test("accepts a wrapper at exactly the 64 KiB cap", () => {
  const atCap = { ...validBytesInput(), wrappedItemKey: bytes("x", MAX_WRAPPER_BYTES) };
  expect(parseAccountBundle(buildAccountBundle(atCap))).not.toBeNull();
});

test("rejects KDF params exceeding the 512-byte cap", () => {
  const oversized = { ...validBytesInput(), kdfParametersCbor: bytes("x", MAX_KDF_PARAMS_BYTES + 1) };
  expect(parseAccountBundle(buildAccountBundle(oversized))).toBeNull();
});

test("rejects a zero-length wrapper", () => {
  const empty = { ...validBytesInput(), wrappedItemKey: new Uint8Array(0) };
  expect(parseAccountBundle(buildAccountBundle(empty))).toBeNull();
});

test("never throws on adversarial input", () => {
  const adversarial = ["b64:bnVsbA==", "b64:W10=", "b64:IjEyMyI=", "not-even-b64-shaped", ""];
  for (const value of adversarial) {
    expect(() => parseAccountBundle(value)).not.toThrow();
  }
});

test("field order in ACCOUNT_BUNDLE_FIELDS matches ADR-0011 G1", () => {
  expect(ACCOUNT_BUNDLE_FIELDS).toEqual([
    "format",
    "accountId",
    "vaultId",
    "itemId",
    "kdfParametersCbor",
    "wrappedAccountKey",
    "wrappedVaultKey",
    "wrappedItemKey",
    "wrappedRecoveryKey",
  ]);
});

function tamperField(wire: string, field: string, value: string): string {
  const decoded = JSON.parse(atob(wire.slice("b64:".length)));
  decoded[field] = value;
  return "b64:" + btoa(JSON.stringify(decoded));
}
