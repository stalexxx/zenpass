# D02-MVP manual/demo TLS fixture

`demo-cert.pem` / `demo-key.pem` are a fixed, throwaway, self-signed TLS
certificate and private key (EC P-256, CN=127.0.0.1, SAN=IP:127.0.0.1,
10-year validity), generated solely so
`apps/android/scripts/manual-emulator-fixture.mjs` can front a real backend
with a *stable* certificate that the Android app's debug-only network
security config (`app/src/main/res/xml/network_security_config.xml`) pins
directly via `@raw/demo_ca` (a copy of `demo-cert.pem`).

This exists only to let a real on-device UI-driven login/unlock/save/TOTP
run succeed against a real backend without the on-device "install a CA
certificate" Settings flow (which requires a device credential and, on
this API level's scoped storage, could not even read a pushed certificate
file — see `docs/tasks/D02-MVP.md`'s completion report for what was tried
before landing on this approach).

Both files are intentionally checked in and intentionally not secret:
this certificate is trusted by the app **only** for the literal domain
`127.0.0.1` (see the `<domain-config>` in network_security_config.xml,
never system-wide and never in a release build's trust set beyond that one
scoped domain-config entry), it identifies nothing but a developer's own
loopback interface, and its private key never leaves this fixture — the
Android app never receives or uses `demo-key.pem`, only the public
certificate embedded in the APK.

Regenerate with:

```sh
openssl req -x509 -nodes -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 \
  -keyout demo-key.pem -out demo-cert.pem -days 3650 -subj "/CN=127.0.0.1" \
  -addext "subjectAltName=IP:127.0.0.1"
cp demo-cert.pem ../app/src/main/res/raw/demo_ca.pem
```
