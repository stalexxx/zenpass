import { expect, test } from "bun:test";

async function manifest(name: string): Promise<Record<string, unknown>> {
  return JSON.parse(await Bun.file(new URL(`../${name}`, import.meta.url).pathname).text());
}

const CSP = "script-src 'self' 'wasm-unsafe-eval'; object-src 'self'";

for (const [label, file, version] of [["Chrome", "manifest.chrome.json", 3], ["Firefox", "manifest.firefox.json", 2]] as const) {
  test(`${label} manifest permits HTTPS pages only and no remote code`, async () => {
    const value = await manifest(file);
    expect(value.manifest_version).toBe(version);
    const scripts = value.content_scripts as Array<{ matches: string[] }>;
    expect(scripts).toHaveLength(1);
    expect(scripts[0]!.matches).toEqual(["https://*/*"]);
    const text = JSON.stringify(value);
    expect(text).not.toContain("http://");
    expect(text).not.toContain("https://cdn");
    expect(text).not.toContain("<all_urls>");
  });

  test(`${label} CSP allows packaged WASM only, never broad eval/inline/remote code`, async () => {
    const value = await manifest(file);
    const csp = value.manifest_version === 3
      ? (value.content_security_policy as { extension_pages: string }).extension_pages
      : (value.content_security_policy as string);
    expect(csp).toBe(CSP);
    expect(csp).not.toContain("'unsafe-eval'");
    expect(csp).not.toContain("unsafe-inline");
  });
}

test("Chrome permission budget is limited to the active tab, non-secret account/API-origin storage, and HTTPS host access", async () => {
  const value = await manifest("manifest.chrome.json");
  // `storage` (ADR-0011 D1/D4) is reserved for the extension's own
  // non-secret accountId/apiOrigin association only — see
  // apps/extension/src/storage.ts and its tests; never vault/key/password/
  // TOTP material.
  expect(value.permissions).toEqual(["activeTab", "storage"]);
  expect(value.host_permissions).toEqual(["https://*/*"]);
});

test("Firefox permission budget contains no unreviewed permissions", async () => {
  const value = await manifest("manifest.firefox.json");
  expect(value.permissions).toEqual(["activeTab", "storage", "https://*/*"]);
});
