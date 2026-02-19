import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { describe, expect, it } from "vitest";
import { loadConfig } from "../src/config/index.js";
import { createModules } from "../src/modules/index.js";

describe("config defaults", () => {
  it("includes approval defaults when not specified", () => {
    const config = loadConfig(
      `/tmp/radius-nonexistent-config-${Date.now()}-${Math.random()}.yaml`,
    );

    expect(config.approval.enabled).toBe(false);
    expect(config.approval.mode).toBe("sync_wait");
    expect(config.approval.store.engine).toBe("sqlite");
    expect(config.approval.channels.telegram?.enabled).toBe(false);
    expect(config.approval.channels.telegram?.pollIntervalMs).toBe(1500);
    expect(config.approval.channels.http?.enabled).toBe(false);
    expect(config.approval.channels.http?.timeoutMs).toBe(10000);
    expect(config.modules).not.toContain("self_defense");
    expect(config.modules).not.toContain("repetition_guard");
    expect(config.modules).not.toContain("tripwire_guard");
  });

  it("resolves mode aliases to canonical profiles", () => {
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "radius-config-"));
    const configPath = path.join(tmpDir, "radius.yaml");
    fs.writeFileSync(
      configPath,
      [
        "global:",
        "  profile: bunker",
        "  workspace: ${CWD}",
        "  defaultAction: deny",
        "modules:",
        "  - audit",
      ].join("\n"),
    );

    const config = loadConfig(configPath);
    expect(config.global.profile).toBe("local");
  });

  it("keeps compatibility with legacy configs that do not define new modules", () => {
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "radius-config-legacy-"));
    const configPath = path.join(tmpDir, "radius.yaml");
    fs.writeFileSync(
      configPath,
      [
        "global:",
        "  profile: standard",
        "  workspace: ${CWD}",
        "  defaultAction: deny",
        "modules:",
        "  - kill_switch",
        "  - tool_policy",
        "  - fs_guard",
        "  - command_guard",
        "  - exec_sandbox",
        "  - output_dlp",
        "  - rate_budget",
        "  - audit",
        "moduleConfig:",
        "  tool_policy:",
        "    default: deny",
        "  fs_guard:",
        "    allowedPaths:",
        "      - ${workspace}",
        "    blockedPaths: []",
        "  exec_sandbox:",
        "    engine: bwrap",
        "    required: false",
        "    shareNetwork: true",
      ].join("\n"),
    );

    const config = loadConfig(configPath);
    expect(config.modules).toEqual([
      "kill_switch",
      "tool_policy",
      "fs_guard",
      "command_guard",
      "exec_sandbox",
      "output_dlp",
      "rate_budget",
      "audit",
    ]);
    expect(config.moduleConfig.exec_sandbox?.shareNetwork).toBe(true);

    // Should instantiate without requiring any v0.5-only keys.
    const modules = createModules(config.modules, config.moduleConfig);
    expect(modules.some((m) => m.name === "exec_sandbox")).toBe(true);
    expect(modules.some((m) => m.name === "tripwire_guard")).toBe(false);
    expect(modules.some((m) => m.name === "repetition_guard")).toBe(false);
  });

  it("keeps new hardening modules opt-in across built-in profiles", () => {
    for (const profile of ["local", "standard", "unbounded"]) {
      const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), `radius-config-${profile}-`));
      const configPath = path.join(tmpDir, "radius.yaml");
      fs.writeFileSync(
        configPath,
        [
          "global:",
          `  profile: ${profile}`,
          "  workspace: ${CWD}",
          "  defaultAction: deny",
        ].join("\n"),
      );

      const config = loadConfig(configPath);
      expect(config.modules).not.toContain("self_defense");
      expect(config.modules).not.toContain("tripwire_guard");
      expect(config.modules).not.toContain("repetition_guard");
    }
  });
});
