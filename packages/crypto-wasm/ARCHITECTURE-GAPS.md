# B03 browser unlock blocker

The core can safely unwrap `UnlockKey → AccountKey → VaultKey → ItemKey`, and
`crypto-ffi::ItemSession::unlock` implements that native capability without
exporting any key. Browser parity cannot be completed safely in B03 alone:

- B04 has no mounted OPAQUE client/server transport contract or endpoint that
  yields the authenticated password-unlock lifecycle.
- No ownership/serialization contract names the persisted account, vault, and
  item wrapper records a Worker may receive together, nor their versioning and
  authenticated fetch boundary.
- Root `bun.lock` predates these packages. B03 is forbidden from changing the
  root lockfile, so an offline frozen workspace install cannot resolve them.
- The root Cargo workspace omits `crypto-ffi`; adding it would violate B03's
  allowed paths, so root `cargo test -p crypto-ffi` cannot succeed.

Integrator options: grant B03 a root manifest/lockfile scope amendment and
dispatch the B04 OPAQUE transport + encrypted-wrapper record contract, or keep
the native unlock capability gated until that architecture exists. Neither gap
permits raw-byte key import/export or a fabricated browser session.
