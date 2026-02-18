import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { stringify as toYaml } from "yaml";
import { describe, expect, it } from "vitest";
import { clearApprovalLeases } from "../src/approval/lease-store.js";
import { RadiusRuntime } from "../src/runtime.js";

function httpResponse(result: unknown): Response {
  return new Response(JSON.stringify(result), {
    status: 200,
    headers: { "content-type": "application/json" },
  });
}

function makeConfig(configPath: string): void {
  const config = {
    global: {
      profile: "standard",
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
        engine: "memory",
        required: false,
      },
      channels: {
        telegram: {
          enabled: false,
          transport: "polling",
          botToken: "",
          allowedChatIds: [],
          approverUserIds: [],
          pollIntervalMs: 1500,
          webhookPublicUrl: "",
        },
        http: {
          enabled: true,
          url: "https://approvals.example/resolve",
          timeoutMs: 5000,
          headers: {
            authorization: "Bearer test-token",
          },
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
            channel: "http",
            prompt: "Approve execution of Bash?",
            timeoutSec: 5,
          },
        ],
      },
    },
  };

  fs.writeFileSync(configPath, toYaml(config));
}

describe("Runtime HTTP approval resolution", () => {
  it("converts challenge to allow when HTTP endpoint approves", async () => {
    clearApprovalLeases();
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "radius-http-runtime-"));
    const configPath = path.join(tmpDir, "radius.yaml");
    makeConfig(configPath);

    const originalFetch = globalThis.fetch;
    globalThis.fetch = (async (input: RequestInfo | URL, init?: RequestInit) => {
      const url = String(input);
      expect(url).toBe("https://approvals.example/resolve");
      expect(init?.method).toBe("POST");
      const body = init?.body ? JSON.parse(String(init.body)) : {};
      expect(body.prompt).toBe("Approve execution of Bash?");
      return httpResponse({ status: "approved", reason: "approved by reviewer" });
    }) as typeof fetch;

    try {
      const runtime = new RadiusRuntime({
        configPath,
        framework: "openclaw",
      });

      const response = (await runtime.evaluate({
        hook_type: "PreToolUse",
        tool_name: "Bash",
        tool_input: { command: "echo hi" },
        session_id: "http-allow",
      })) as { decision: string; reason?: string };

      expect(response.decision).toBe("allow");
    } finally {
      globalThis.fetch = originalFetch;
      clearApprovalLeases();
    }
  });

  it("converts challenge to deny when HTTP endpoint denies", async () => {
    clearApprovalLeases();
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "radius-http-runtime-"));
    const configPath = path.join(tmpDir, "radius.yaml");
    makeConfig(configPath);

    const originalFetch = globalThis.fetch;
    globalThis.fetch = (async () =>
      httpResponse({ action: "deny", reason: "policy rejected by reviewer" })) as typeof fetch;

    try {
      const runtime = new RadiusRuntime({
        configPath,
        framework: "openclaw",
      });

      const response = (await runtime.evaluate({
        hook_type: "PreToolUse",
        tool_name: "Bash",
        tool_input: { command: "echo hi" },
        session_id: "http-deny",
      })) as { decision: string; reason?: string };

      expect(response.decision).toBe("deny");
      expect(response.reason).toContain("http approval denied");
    } finally {
      globalThis.fetch = originalFetch;
      clearApprovalLeases();
    }
  });

  it("grants temporary approval from HTTP endpoint and bypasses repeated prompts", async () => {
    clearApprovalLeases();
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "radius-http-runtime-"));
    const configPath = path.join(tmpDir, "radius.yaml");
    makeConfig(configPath);

    const originalFetch = globalThis.fetch;
    let resolveCalls = 0;
    globalThis.fetch = (async () => {
      resolveCalls += 1;
      return httpResponse({
        status: "approved_temporary",
        reason: "temporary reviewer grant",
        ttlSec: 120,
      });
    }) as typeof fetch;

    try {
      const runtime = new RadiusRuntime({
        configPath,
        framework: "openclaw",
      });

      const first = (await runtime.evaluate({
        hook_type: "PreToolUse",
        tool_name: "Bash",
        tool_input: { command: "echo first" },
        session_id: "http-lease",
        agent_name: "builder",
      })) as { decision: string; reason?: string };
      expect(first.decision).toBe("allow");

      const secondRuntime = new RadiusRuntime({
        configPath,
        framework: "openclaw",
      });

      const second = (await secondRuntime.evaluate({
        hook_type: "PreToolUse",
        tool_name: "Bash",
        tool_input: { command: "echo second" },
        session_id: "http-lease",
        agent_name: "builder",
      })) as { decision: string; reason?: string };
      expect(second.decision).toBe("allow");
      expect(resolveCalls).toBe(1);
    } finally {
      globalThis.fetch = originalFetch;
      clearApprovalLeases();
    }
  });
});
