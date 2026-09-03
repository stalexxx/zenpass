// Binary API value convention shared with the rest of the contract family
// (docs/contracts/crypto-envelope-v1.md: "Binary API value | `b64:` +
// standard RFC 4648 base64 with padding").
const PREFIX = 'b64:';

/** Returns a Buffer, or null if `value` isn't a well-formed `b64:` string. */
export function decodeB64(value) {
  if (typeof value !== 'string' || !value.startsWith(PREFIX)) return null;
  const body = value.slice(PREFIX.length);
  // Buffer.from('base64') silently ignores invalid characters rather than
  // throwing, so the alphabet is validated up front instead of trusted.
  if (!/^[A-Za-z0-9+/]*={0,2}$/.test(body) || body.length % 4 !== 0) return null;
  return Buffer.from(body, 'base64');
}

export function encodeB64(bytes) {
  return PREFIX + Buffer.from(bytes).toString('base64');
}
