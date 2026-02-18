import * as readline from "node:readline";
import { RadiusRuntime } from "../runtime.js";

/**
 * stdin/stdout adapter entrypoint.
 *
 * Reads line-delimited JSON from stdin, evaluates through the pipeline,
 * writes JSON response to stdout. Used for hook-based integrations
 * (OpenClaw legacy hooks, generic stdio).
 */
export async function run(): Promise<void> {
  const args = process.argv.slice(3);
  let configPath: string | undefined;
  let framework: string | undefined;

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
    }
  }

  const runtime = new RadiusRuntime({
    configPath,
    framework: framework as "openclaw" | "nanobot" | "claude-telegram" | "generic" | undefined,
  });

  const rl = readline.createInterface({
    input: process.stdin,
    terminal: false,
  });

  for await (const line of rl) {
    if (!line.trim()) continue;

    try {
      const input = JSON.parse(line);
      const result = await runtime.evaluate(input);
      process.stdout.write(JSON.stringify(result) + "\n");
    } catch (err) {
      const message = err instanceof Error ? err.message : "unknown error";
      process.stderr.write(`[radius:hook] error: ${message}\n`);
      process.stdout.write(
        JSON.stringify({ error: message }) + "\n",
      );
    }
  }
}
