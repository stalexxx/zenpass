// `b64:` + standard padded base64, matching apps/backend/src/auth/codec.mjs
// exactly (docs/contracts/crypto-envelope-v1.md: "Binary API value |
// `b64:` + standard RFC 4648 base64 with padding").
const PREFIX = "b64:";

export function encodeB64(bytes: Uint8Array): string {
  let binary = "";
  for (let i = 0; i < bytes.length; i += 1) binary += String.fromCharCode(bytes[i]);
  return PREFIX + btoa(binary);
}

export function decodeB64(value: string): Uint8Array {
  if (!value.startsWith(PREFIX)) {
    throw new Error(`expected a '${PREFIX}'-prefixed base64 string`);
  }
  const binary = atob(value.slice(PREFIX.length));
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i += 1) bytes[i] = binary.charCodeAt(i);
  return bytes;
}
