import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { describe, expect, it } from "vitest";
import { loadConfig } from "../src/config/index.js";

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
});
