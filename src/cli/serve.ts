import http from "node:http";
import { AgentGuardRuntime } from "../runtime.js";

/**
 * HTTP/MCP runtime server.
 *
 * POST /check — evaluate a guard event and return pipeline result.
 * GET  /health — health check.
 */
export async function run(): Promise<void> {
  const args = process.argv.slice(3);
  let configPath: string | undefined;
  let framework: string | undefined;
  let port = 3100;

  for (let i = 0; i < args.length; i++) {
    switch (args[i]) {
      case "--config":
      case "-c":
        configPath = args[++i];
        break;
      case "--adapter":
      case "-a":
        framework = args[++i];
        break;
      case "--port":
      case "-p":
        port = parseInt(args[++i] ?? "3100", 10);
        break;
    }
  }

  const runtime = new AgentGuardRuntime({
    configPath,
    framework: framework as "openclaw" | "nanobot" | "claude-telegram" | "generic" | undefined,
  });

  const server = http.createServer(async (req, res) => {
    // CORS headers for local dev
    res.setHeader("Access-Control-Allow-Origin", "*");
    res.setHeader("Access-Control-Allow-Methods", "POST, GET, OPTIONS");
    res.setHeader("Access-Control-Allow-Headers", "Content-Type");

    if (req.method === "OPTIONS") {
      res.writeHead(204);
      res.end();
      return;
    }

    if (req.method === "GET" && req.url === "/health") {
      res.writeHead(200, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ status: "ok", version: "0.2.0" }));
      return;
    }

    if (req.method === "POST" && req.url === "/check") {
      try {
        const body = await readBody(req);
        const input = JSON.parse(body);
        const result = await runtime.evaluate(input);

        res.writeHead(200, { "Content-Type": "application/json" });
        res.end(JSON.stringify(result));
      } catch (err) {
        const message = err instanceof Error ? err.message : "unknown error";
        res.writeHead(400, { "Content-Type": "application/json" });
        res.end(JSON.stringify({ error: message }));
      }
      return;
    }

    res.writeHead(404, { "Content-Type": "application/json" });
    res.end(JSON.stringify({ error: "not found" }));
  });

  server.listen(port, () => {
    console.log(`agentguard serve listening on http://localhost:${port}`);
    console.log(`  POST /check  — evaluate guard event`);
    console.log(`  GET  /health — health check`);
  });
}

function readBody(req: http.IncomingMessage): Promise<string> {
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = [];
    req.on("data", (chunk: Buffer) => chunks.push(chunk));
    req.on("end", () => resolve(Buffer.concat(chunks).toString()));
    req.on("error", reject);
  });
}
