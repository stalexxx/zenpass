import { existsSync } from "node:fs";
import { resolve, sep } from "node:path";

const port = Number(process.env.PORT ?? 5173);
const apiOrigin = process.env.API_ORIGIN ?? "http://127.0.0.1:8787";
const webRoot = resolve(import.meta.dir, "..");
const apiPrefixes = ["/auth/", "/devices", "/health/", "/vaults/"];

function isApiPath(pathname: string): boolean {
  return apiPrefixes.some((prefix) => pathname === prefix.slice(0, -1) || pathname.startsWith(prefix));
}

function staticFile(pathname: string): Bun.BunFile | null {
  const requested = pathname === "/" ? "index.html" : pathname.replace(/^\/+/, "");
  const candidate = resolve(webRoot, requested);
  if (candidate !== webRoot && !candidate.startsWith(`${webRoot}${sep}`)) return null;
  return existsSync(candidate) ? Bun.file(candidate) : null;
}

Bun.serve({
  hostname: "127.0.0.1",
  port,
  async fetch(request) {
    const url = new URL(request.url);
    if (isApiPath(url.pathname)) {
      try {
        const body = ["GET", "HEAD"].includes(request.method) ? undefined : await request.arrayBuffer();
        return await fetch(`${apiOrigin}${url.pathname}${url.search}`, {
          method: request.method,
          headers: request.headers,
          body,
        });
      } catch {
        return Response.json({ error: "backend_unavailable" }, { status: 502 });
      }
    }
    if (url.pathname === "/") {
      const index = staticFile(url.pathname);
      if (!index) return new Response("Not found", { status: 404 });
      // Tauri's WebView must make its API requests directly in development:
      // unlike a browser it does not reliably route a relative fetch through
      // this Bun proxy. Its dev URL opts into this narrow mode explicitly.
      const apiBaseUrl = url.searchParams.has("desktop") ? apiOrigin : "";
      const html = (await index.text()).replace(
        "</head>",
        `<script>globalThis.ZKPM_API_BASE_URL = ${JSON.stringify(apiBaseUrl)};</script></head>`,
      );
      return new Response(html, {
        headers: { "content-type": "text/html; charset=utf-8", "cache-control": "no-store" },
      });
    }
    const file = staticFile(url.pathname);
    return file
      ? new Response(file, { headers: { "cache-control": "no-store" } })
      : new Response("Not found", { status: 404 });
  },
});

console.log(`Web dev server: http://127.0.0.1:${port} (API → ${apiOrigin})`);
