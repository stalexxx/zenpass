import { expect, test } from "bun:test";

async function manifest(name: string): Promise<Record<string, unknown>> {
  return JSON.parse(await Bun.file(new URL(`../${name}`, import.meta.url).pathname).text());
}

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
}

test("Chrome permission budget is limited to active tab, UI storage, and HTTPS host access", async () => {
  const value = await manifest("manifest.chrome.json");
  expect(value.permissions).toEqual(["activeTab", "storage"]);
  expect(value.host_permissions).toEqual(["https://*/*"]);
});
