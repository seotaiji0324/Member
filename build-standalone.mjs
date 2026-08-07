import { mkdir, readFile, writeFile } from "node:fs/promises";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const root = dirname(fileURLToPath(import.meta.url));
const outputDir = resolve(root, ".wrangler", "standalone");
const databaseId = "e003386a-7cb8-4e99-a69e-3f29885ec384";

const [workerSource, html, adminHtml, css, clientJs, adminJs] = await Promise.all([
  readFile(resolve(root, "worker.mjs"), "utf8"),
  readFile(resolve(root, "public", "index.html"), "utf8"),
  readFile(resolve(root, "public", "admin.html"), "utf8"),
  readFile(resolve(root, "public", "styles.css"), "utf8"),
  readFile(resolve(root, "public", "script.js"), "utf8"),
  readFile(resolve(root, "public", "admin.js"), "utf8"),
]);

const staticAssets = {
  "/": { body: html, contentType: "text/html; charset=utf-8" },
  "/index.html": { body: html, contentType: "text/html; charset=utf-8" },
  "/admin.html": { body: adminHtml, contentType: "text/html; charset=utf-8" },
  "/styles.css": { body: css, contentType: "text/css; charset=utf-8" },
  "/script.js": { body: clientJs, contentType: "text/javascript; charset=utf-8" },
  "/admin.js": { body: adminJs, contentType: "text/javascript; charset=utf-8" },
};

const standaloneSource = `const STATIC_ASSETS = ${JSON.stringify(staticAssets)};\n${workerSource.replace(
  "return env.ASSETS.fetch(request);",
  `const asset = STATIC_ASSETS[url.pathname];
    if (!asset) return new Response("Not found", { status: 404 });
    return new Response(asset.body, {
      headers: {
        "Content-Type": asset.contentType,
        "Cache-Control": "no-cache",
      },
    });`,
)}`;

const metadata = {
  main_module: "worker.mjs",
  bindings: [{ type: "d1", name: "DB", database_id: databaseId }],
  compatibility_date: "2026-08-07",
  compatibility_flags: ["nodejs_compat"],
  observability: { enabled: true, head_sampling_rate: 1 },
};

await mkdir(outputDir, { recursive: true });
await Promise.all([
  writeFile(resolve(outputDir, "worker.mjs"), standaloneSource),
  writeFile(resolve(outputDir, "metadata.json"), JSON.stringify(metadata)),
]);

console.log(`Standalone Worker built in ${outputDir}`);
