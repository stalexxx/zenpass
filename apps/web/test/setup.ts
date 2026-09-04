// Test-only environment shim (see bunfig.toml). Registers a real DOM
// (happy-dom) and a real IndexedDB implementation (fake-indexeddb) as
// globals so tests can exercise actual browser-shaped APIs under `bun
// test` headlessly. Never imported by production code or the build.
//
// happy-dom's GlobalWindow intentionally leaves Node's own `crypto`
// (Web Crypto, non-configurable in Node) alone rather than overriding it —
// that's correct for us: production code uses `crypto.subtle` /
// `crypto.getRandomValues`, and Node's native implementation satisfies the
// same Web Crypto API a real browser exposes, so nothing here needs to
// touch it.
import { GlobalWindow } from "happy-dom";
import "fake-indexeddb/auto";

const window = new GlobalWindow({ url: "https://vault.test.invalid/" });
const target = globalThis as Record<string, unknown>;
// Skip identity/self-reference properties (these point back at happy-dom's
// window object and would otherwise shadow Bun's real global/runtime
// bindings, breaking Bun's own test machinery) and `crypto` (Node's native
// Web Crypto is what production code targets anyway).
// `fetch` is also skipped: happy-dom's fetch cannot load `file:` URLs, but
// Bun/Node's native fetch can, and production WASM loading
// (`crypto-wasm`'s generated `init()`) fetches its .wasm file over exactly
// that scheme in this test environment.
// `Response`/`Request`/`Headers` are skipped alongside `fetch` for the
// same reason: native fetch returns native Response instances, and
// wasm-bindgen's loader glue does `module instanceof Response` — that
// must be Node/Bun's own Response class, not happy-dom's, or the
// instanceof check fails and the WASM module fails to load.
const SKIP = new Set([
  "crypto", "global", "globalThis", "self", "top", "parent", "window",
  "fetch", "Response", "Request", "Headers", "console",
]);
for (const key of Object.getOwnPropertyNames(window)) {
  if (SKIP.has(key)) continue;
  const descriptor = Object.getOwnPropertyDescriptor(window, key);
  if (!descriptor || !descriptor.configurable) continue;
  try {
    target[key] = (window as unknown as Record<string, unknown>)[key];
  } catch {
    // Some accessors throw off-thread in happy-dom; skip rather than fail
    // test setup over a global this suite doesn't use.
  }
}

// `window` itself is deliberately excluded from the copy above (it's one
// of the "identity" properties that would otherwise shadow Bun's own
// globals). react-dom's event-priority plumbing (`resolveUpdatePriority`)
// reads `window.event`, so it needs *some* `window` binding to exist —
// exactly like a real browser, where `window === globalThis` at top
// level. Aliasing it to `globalThis` (rather than happy-dom's window
// object) gives react-dom what it needs without reintroducing the
// shadowing problem the SKIP set exists to avoid.
target.window = target;
