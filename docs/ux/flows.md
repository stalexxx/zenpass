# MVP UX flows

## Registration

1. User enters email and master password locally.
2. Client creates the account key and recovery kit; server receives only OPAQUE registration material and encrypted key bundle.
3. The user must reveal and confirm the recovery key before the vault can be used.
4. UI states clearly that support cannot recover a lost password without the recovery key.

## Unlock and lock

- Unlock runs in a Worker and reports only success/failure plus vault data needed by the current view.
- Lock clears the in-memory key handles, search index, selected item, and clipboard timer.
- Automatic lock triggers after inactivity, browser restart, explicit logout, or device security event.
- Offline unlock uses only the local encrypted snapshot and wrapped key bundle.

## Item lifecycle

- Item types in MVP: login, secure note, and TOTP-enabled login.
- Save validates required fields locally, encrypts before persistence, then queues sync mutation.
- Delete is confirmation-gated and creates a tombstone; undo is available while the tombstone remains local.

## Import/export

- Import is client-side and shows a field mapping preview plus unsupported-field warnings before writing.
- Encrypted export is the default. Plaintext export requires re-authentication, a second confirmation, and an explicit warning.

## Conflict and devices

- A sync conflict shows both versions with timestamps and a field-level comparison after local decryption.
- Device management lists name, last seen, and revoke action; revocation requires re-authentication.

## Extension autofill

- Autofill is offered only for an exact trusted origin match.
- HTTP pages, look-alike domains, ambiguous matches, hidden fields, and untrusted cross-origin frames require refusal or explicit manual action.
- Content scripts receive only the selected login fields immediately before a confirmed fill.

## Accessibility

- All flows are keyboard-operable, have visible focus, use semantic labels, and expose errors in an aria-live region.
- Destructive and irreversible actions require text confirmation, not color-only cues.

