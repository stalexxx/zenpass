# Backup and recovery runbook

- Enable encrypted PostgreSQL backups and point-in-time recovery.
- Test restore into an isolated EU project before every release.
- Verify restored ciphertext, revisions, tombstones, cursors, and device revocations.
- Record restore duration and checksum results; do not export decrypted fixtures.
- Rotate server KMS credentials independently from user vault keys.

