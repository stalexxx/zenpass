# Browser extension

Chrome and Firefox packages are emitted to `dist/chrome/` and `dist/firefox/`.
They use separate MV3/MV2 manifests, no remote code, and only `activeTab`,
`storage`, and HTTPS host access. `storage` is reserved for non-secret UI
preferences; the background `ExtensionSession` never writes credentials, TOTP
values, or vault material to it.

## Autofill policy

The content script runs on HTTPS only and requests a fill only for a visible
username/password pair in the top-level document. The background rejects HTTP,
frames, hidden fields, cross-origin form actions, subdomains, look-alikes, and
all non-exact origins. It keeps decrypted values in memory only and releases a
selected entry only after a user gesture; locking clears its session.

Save/update submission is intentionally fail-closed until it is connected to a
visible, encrypted vault-save flow. Submitted fields are not retained by the
extension in the meantime.
