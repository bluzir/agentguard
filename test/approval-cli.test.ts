import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { parse as parseYaml } from "yaml";
import { describe, expect, it } from "vitest";
import { run as initRun } from "../src/cli/init.js";
import { run as linkRun } from "../src/cli/link.js";

function withArgv(argv: string[], fn: () => Promise<void>): Promise<void> {
  const previous = process.argv;
  process.argv = argv;
  return fn().finally(() => {
    process.argv = previous;
  });
}

describe("approval onboarding CLI", () => {
  it("scaffolds and links telegram approval config", async () => {
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "agentguard-approval-cli-"));
    const configPath = path.join(tmpDir, "agentguard.yaml");

    await withArgv(
      [
        "node",
        "agentguard",
        "init",
        "--framework",
        "openclaw",
        "--profile",
        "balanced",
        "--output",
        configPath,
        "--approvals",
        "telegram",
      ],
      async () => {
        await initRun();
      },
    );

    const initial = parseYaml(fs.readFileSync(configPath, "utf-8")) as Record<string, unknown>;
    const initialApproval = initial.approval as Record<string, unknown>;
    expect(initialApproval.enabled).toBe(true);
    expect(initial.modules).toContain("approval_gate");
    expect((initial.moduleConfig as Record<string, unknown>).approval_gate).toBeDefined();

    await withArgv(
      [
        "node",
        "agentguard",
        "link",
        "telegram",
        "--config",
        configPath,
        "--chat-id",
        "100",
        "--user-id",
        "200",
      ],
      async () => {
        await linkRun();
      },
    );

    const linked = parseYaml(fs.readFileSync(configPath, "utf-8")) as Record<string, unknown>;
    const approval = linked.approval as Record<string, unknown>;
    const channels = approval.channels as Record<string, unknown>;
    const telegram = channels.telegram as Record<string, unknown>;

    expect(telegram.enabled).toBe(true);
    expect(telegram.allowedChatIds).toContain("100");
    expect(telegram.approverUserIds).toContain("200");
    expect(linked.modules).toContain("approval_gate");
  });

  it("accepts slider mode aliases in init", async () => {
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "agentguard-init-mode-"));
    const configPath = path.join(tmpDir, "agentguard.yaml");

    await withArgv(
      [
        "node",
        "agentguard",
        "init",
        "--framework",
        "nanobot",
        "--mode",
        "tactical",
        "--output",
        configPath,
      ],
      async () => {
        await initRun();
      },
    );

    const config = parseYaml(fs.readFileSync(configPath, "utf-8")) as Record<string, unknown>;
    const global = config.global as Record<string, unknown>;
    expect(global.profile).toBe("balanced");
  });
});
