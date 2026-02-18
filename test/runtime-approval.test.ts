import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { stringify as toYaml } from "yaml";
import { describe, expect, it } from "vitest";
import { AgentGuardRuntime } from "../src/runtime.js";

function telegramResponse(result: unknown): Response {
  return new Response(JSON.stringify({ ok: true, result }), {
    status: 200,
    headers: { "content-type": "application/json" },
  });
}

function makeConfig(configPath: string): void {
  const config = {
    global: {
      profile: "balanced",
      workspace: "${CWD}",
      defaultAction: "deny",
      requireSignedPolicy: false,
      onUndefinedTemplateVar: "error",
    },
    approval: {
      enabled: true,
      mode: "sync_wait",
      waitTimeoutSec: 5,
      onTimeout: "deny",
      onConnectorError: "deny",
      store: {
        engine: "sqlite",
        path: "./.agentguard/approvals.db",
      },
      channels: {
        telegram: {
          enabled: true,
          transport: "polling",
          botToken: "TEST_TOKEN",
          allowedChatIds: ["100"],
          approverUserIds: ["200"],
          pollIntervalMs: 1,
          webhookPublicUrl: "",
        },
      },
    },
    adapters: {
      openclaw: { enabled: true },
    },
    modules: ["approval_gate"],
    moduleConfig: {
      approval_gate: {
        rules: [
          {
            tool: "Bash",
            channel: "telegram",
            prompt: "Approve execution of Bash?",
            timeoutSec: 5,
          },
        ],
      },
    },
  };

  fs.writeFileSync(configPath, toYaml(config));
}

describe("Runtime Telegram approval resolution", () => {
  it("converts challenge to allow when Telegram callback approves", async () => {
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "agentguard-runtime-"));
    const configPath = path.join(tmpDir, "agentguard.yaml");
    makeConfig(configPath);

    const originalFetch = globalThis.fetch;
    let approveCallbackData = "";
    globalThis.fetch = (async (input: RequestInfo | URL, init?: RequestInit) => {
      const url = String(input);
      const method = url.split("/").pop();
      const body = init?.body ? JSON.parse(String(init.body)) : {};

      if (method === "sendMessage") {
        approveCallbackData = body.reply_markup.inline_keyboard[0][0].callback_data;
        return telegramResponse({ message_id: 1 });
      }
      if (method === "getUpdates") {
        return telegramResponse([
          {
            update_id: 1,
            callback_query: {
              id: "cb-approve",
              from: { id: 200 },
              message: { chat: { id: 100 } },
              data: approveCallbackData,
            },
          },
        ]);
      }
      if (method === "answerCallbackQuery") {
        return telegramResponse(true);
      }
      throw new Error(`Unexpected Telegram method: ${method}`);
    }) as typeof fetch;

    try {
      const runtime = new AgentGuardRuntime({
        configPath,
        framework: "openclaw",
      });

      const response = (await runtime.evaluate({
        hook_type: "PreToolUse",
        tool_name: "Bash",
        tool_input: { command: "echo hi" },
        session_id: "s-allow",
      })) as { decision: string; reason?: string };

      expect(response.decision).toBe("allow");
    } finally {
      globalThis.fetch = originalFetch;
    }
  });

  it("converts challenge to deny when Telegram callback denies", async () => {
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "agentguard-runtime-"));
    const configPath = path.join(tmpDir, "agentguard.yaml");
    makeConfig(configPath);

    const originalFetch = globalThis.fetch;
    let denyCallbackData = "";
    globalThis.fetch = (async (input: RequestInfo | URL, init?: RequestInit) => {
      const url = String(input);
      const method = url.split("/").pop();
      const body = init?.body ? JSON.parse(String(init.body)) : {};

      if (method === "sendMessage") {
        denyCallbackData = body.reply_markup.inline_keyboard[0][1].callback_data;
        return telegramResponse({ message_id: 2 });
      }
      if (method === "getUpdates") {
        return telegramResponse([
          {
            update_id: 2,
            callback_query: {
              id: "cb-deny",
              from: { id: 200 },
              message: { chat: { id: 100 } },
              data: denyCallbackData,
            },
          },
        ]);
      }
      if (method === "answerCallbackQuery") {
        return telegramResponse(true);
      }
      throw new Error(`Unexpected Telegram method: ${method}`);
    }) as typeof fetch;

    try {
      const runtime = new AgentGuardRuntime({
        configPath,
        framework: "openclaw",
      });

      const response = (await runtime.evaluate({
        hook_type: "PreToolUse",
        tool_name: "Bash",
        tool_input: { command: "echo hi" },
        session_id: "s-deny",
      })) as { decision: string; reason?: string };

      expect(response.decision).toBe("deny");
      expect(response.reason).toContain("telegram approval denied");
    } finally {
      globalThis.fetch = originalFetch;
    }
  });
});
