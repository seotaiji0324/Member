const http = require("http");
const fs = require("fs");
const path = require("path");

const port = Number(process.env.PORT) || 4173;
const root = path.join(__dirname, "public");
const contentTypes = {
  ".html": "text/html; charset=utf-8",
  ".css": "text/css; charset=utf-8",
  ".js": "text/javascript; charset=utf-8",
};

http.createServer((request, response) => {
  const pathname = request.url === "/" ? "/index.html" : request.url.split("?")[0];
  const filePath = path.join(root, pathname);

  if (!filePath.startsWith(root)) {
    response.writeHead(403).end("Forbidden");
    return;
  }

  fs.readFile(filePath, (error, content) => {
    if (error) {
      response.writeHead(error.code === "ENOENT" ? 404 : 500).end("Not found");
      return;
    }
    response.writeHead(200, { "Content-Type": contentTypes[path.extname(filePath)] || "application/octet-stream" });
    response.end(content);
  });
}).listen(port, "127.0.0.1", () => {
  console.log(`회원가입 페이지: http://127.0.0.1:${port}`);
});
