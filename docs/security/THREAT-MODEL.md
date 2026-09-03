# Threat model

## Scope and security objective

This model covers the personal MVP: web vault, Chrome/Firefox extensions, API,
database, object storage, telemetry, and offline-capable clients. Desktop and
mobile clients inherit the same assumptions and are gated separately.

The objective is zero-knowledge confidentiality and integrity: a compromised
service, database, backup, or network must not reveal vault plaintext, keys,
master passwords, or TOTP seeds. A fully compromised client while unlocked is
outside this guarantee; exposure and persistence must still be minimized.

## Assets

| Asset | Requirement |
|---|---|
| Master password and recovery key | Never leave the user client; never log or persist plaintext |
| AccountKey, VaultKey, ItemKey | Confidential; zeroized after lock and protected at rest |
| Vault fields, notes, credentials, TOTP seeds | Confidential and authenticated; no server decryption |
| Sessions and device credentials | Confidential, revocable, and short-lived where practical |
| Encrypted records, revisions, tombstones, cursors | Integrity and anti-rollback; metadata exposure documented |
| Source, dependencies, and build outputs | Authenticity and reproducibility |

## Trust boundaries and assumptions

1. The client and crypto worker/native boundary are trusted only while not fully
   compromised. UI code has no direct raw-key access.
2. API, database, object storage, backups, support, telemetry, and network are
   untrusted with vault plaintext and keys.
3. Browser, extension host, OS, and hardware may be compromised. Secure storage
   reduces at-rest exposure, but not a live privileged compromise.
4. Primitives come from the approved Rust core and reviewed libraries.
5. Losing both master password and recovery key is permanent; support has no
   bypass.

## Threat coverage

Every threat has a mitigation and verification activity. Unaccepted
Critical/High residual risk blocks public release.

| ID / threat | Control / mitigation | Verification |
|---|---|---|
| T01 Database, backup, or object-storage theft | Client-side authenticated encryption; server stores opaque records and wrapped keys only | Isolated dump/backup restore; assert no vault field, key, seed, or plaintext password; offline extraction red-team |
| T02 Malicious API or operator | Server never receives decryption keys; AEAD context binds account/vault/item/version; authenticated authorization and device actions | Tamper ciphertext, IDs, versions, and response order; expect authentication failure; inspect logs/code for plaintext paths |
| T03 Network interception/MITM | TLS, secure session policy, replay-resistant sessions; application payloads remain encrypted | Proxy integration, invalid certificate, replay, and token-substitution tests |
| T04 XSS or compromised web dependency | Strict CSP, no eval/inline code, pinned dependencies, worker isolation, no secrets in DOM/localStorage/analytics | CSP/SAST/dependency tests; injected-script fixture; browser security review |
| T05 Extension overreach/malicious content script | Minimum permissions, no remote code, background owns session, content script gets selected fields only, origin/form checks | Chrome/Firefox hostile-page E2E, manifest review, iframe/isolation tests |
| T06 Phishing/autofill exfiltration | Exact origin matching; no HTTP autofill; confirmation for ambiguous/look-alike/cross-origin/new forms | Unicode/look-alike, redirect, HTTP, iframe, SPA, hidden-field fixtures |
| T07 Stolen/unattended device | Explicit lock, timeout, lock on suspend/logout, memory cleanup; OS secure storage for native clients | Sleep/wake, timeout, logout, crash, restart, memory/storage inspection; revoked-device sync test |
| T08 Offline/online password guessing | Argon2id with unique salt and calibrated cost; OPAQUE and server throttling; independent recovery | Target-device benchmarks; throttling and incorrect-unlock tests; KDF/OPAQUE audit |
| T09 Session theft/replay/device enrollment abuse | Short-lived tokens, refresh rotation/revocation, CSRF protection, authenticated enrollment/revoke | Replay old tokens/mutations; rotate/revoke and verify sessions stop; token-redacted logs |
| T10 Sync rollback/replay/deletion/conflict loss | Monotonic revisions/change sequence, opaque cursor, tombstones, baseRevision, idempotent mutation IDs | Two-device offline simulation; duplicate/reordered/stale/rollback/tombstone tests |
| T11 Metadata leakage | Encrypt names/URLs/usernames and sensitive fields; minimize and document size/timing/change metadata and telemetry | Wire/DB/backup/log inspection; metadata inventory and negative assertions |
| T12 Supply-chain compromise/build substitution | Pinned lockfiles, review, SBOM, signed/reproducible builds, restricted CI; Rust crypto ownership | Clean-checkout reproducible build, secret/SAST/dependency/license scans, signature verification |
| T13 Malicious update/release channel | Signed artifacts, protected release credentials, staged rollout and rollback runbook | Modified-artifact rejection; staged deployment and incident rollback exercise |
| T14 Recovery abuse/account takeover | High-entropy recovery key independently wraps AccountKey; local proof; reset revokes sessions/devices | Recovery positive/negative, lost-key, reset authorization/revocation tests; backend cannot decrypt |
| T15 Clipboard/screenshots/crash reports/logs | Minimize copying, clear clipboard where possible, redact diagnostics; never log secrets/request bodies | Redaction tests and inspection of clipboard, crash, and telemetry outputs |
| T16 Malicious import/export file | Client-side parsing, limits, validation before write, encrypted export default, explicit plaintext warning | Malformed/oversized/adversarial fixtures; no partial writes/logging; export E2E |
| T17 Enumeration/DoS/server abuse | Generic auth errors, authorization checks, rate limits, bounded payloads, pagination/quotas | Enumeration matrix, rate-limit, fuzz/boundary, load/timeout tests |
| T18 Insider/support access | Least privilege, audited admin actions, no plaintext support workflow or recovery bypass | IAM/audit review; attempt support access and unauthorized reset |
| T19 Memory disclosure/insecure zeroization | Rust zeroization, bounded key lifetime, no secret debug formatting, clear state on lock | Unit/property tests, crash/minidump review, test-build memory inspection |
| T20 Incident-response failure | Security contact/severity policy, incident/key-rotation procedures, restore drills, non-sensitive alerting | Tabletop, backup restore, rotation, and alerting exercises |

## Security invariants

- No server endpoint can decrypt or derive vault contents.
- Client persistence contains no plaintext vault data, passwords, recovery keys,
  or raw encryption keys.
- Ciphertext is authenticated and context-bound; failed authentication is a
  hard error.
- Device revocation invalidates its sessions and future synchronization.
- Protocol/crypto changes require a new version, ADR, human review, and updated
  language-neutral fixtures.

## Open questions and review gates

1. Human approval is required for envelope/v1 bytes, Argon2id calibration,
   OPAQUE suite/library, and recovery reset flow.
2. Define an accepted metadata leakage budget and user-facing disclosure.
3. Select supported browser/OS versions and verify CSP, WebAuthn, clipboard,
   secure-storage, and autofill capabilities.
4. Define backup retention/deletion across live data, replicas, object storage,
   and backup expiry.
5. External audit must cover crypto-core, auth/recovery, extension isolation,
   sync anti-rollback, and build supply chain before public release.

## Human review checklist

- [ ] Assets, boundaries, assumptions, and metadata exposure approved.
- [ ] T01–T20 rows have an owner, severity, and evidence.
- [ ] Crypto and recovery decisions have explicit human approval.
- [ ] No mitigation weakens the zero-knowledge invariant.
- [ ] Critical/High findings are fixed or formally accepted before release.
