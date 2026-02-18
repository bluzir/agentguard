import fs from "node:fs";
import path from "node:path";
import { parse as parseYaml } from "yaml";
import type { AgentGuardConfig, ProfileName } from "../types.js";
import { getProfile, resolveProfileName } from "./profiles.js";

export { getProfile, PROFILES } from "./profiles.js";

const DEFAULT_CONFIG: AgentGuardConfig = {
  global: {
    profile: "balanced",
    workspace: process.cwd(),
    defaultAction: "deny",
    requireSignedPolicy: false,
    onUndefinedTemplateVar: "error",
  },
  audit: {
    sink: "file",
    path: "./agentguard-audit.jsonl",
    includeArguments: true,
    includeResults: false,
  },
  approval: {
    enabled: false,
    mode: "sync_wait",
    waitTimeoutSec: 90,
    onTimeout: "deny",
    onConnectorError: "deny",
    store: {
      engine: "sqlite",
      path: "./.agentguard/approvals.db",
    },
    channels: {
      telegram: {
        enabled: false,
        transport: "polling",
        botToken: "",
        allowedChatIds: [],
        approverUserIds: [],
        pollIntervalMs: 1500,
      },
    },
  },
  adapters: {},
  modules: [
    "tool_policy",
    "fs_guard",
    "command_guard",
    "output_dlp",
    "rate_budget",
    "audit",
  ],
  moduleConfig: {},
};

/**
 * Expand template variables: ${workspace}, ${CWD}, ${HOME}, ${ENV_VAR}
 */
function expandTemplateVars(
  value: string,
  vars: Record<string, string>,
  onUndefined: "error" | "empty",
): string {
  return value.replace(/\$\{(\w+)\}/g, (match, name: string) => {
    if (name in vars) return vars[name];
    if (name in process.env) return process.env[name] ?? "";
    if (onUndefined === "error") {
      throw new Error(`undefined template variable: ${match}`);
    }
    return "";
  });
}

function expandConfigStrings(
  obj: unknown,
  vars: Record<string, string>,
  onUndefined: "error" | "empty",
): unknown {
  if (typeof obj === "string") {
    return expandTemplateVars(obj, vars, onUndefined);
  }
  if (Array.isArray(obj)) {
    return obj.map((v) => expandConfigStrings(v, vars, onUndefined));
  }
  if (obj !== null && typeof obj === "object") {
    const result: Record<string, unknown> = {};
    for (const [k, v] of Object.entries(obj as Record<string, unknown>)) {
      result[k] = expandConfigStrings(v, vars, onUndefined);
    }
    return result;
  }
  return obj;
}

function deepMerge(base: Record<string, unknown>, override: Record<string, unknown>): Record<string, unknown> {
  const result = { ...base };
  for (const [key, val] of Object.entries(override)) {
    if (
      val !== null &&
      typeof val === "object" &&
      !Array.isArray(val) &&
      typeof result[key] === "object" &&
      result[key] !== null &&
      !Array.isArray(result[key])
    ) {
      result[key] = deepMerge(
        result[key] as Record<string, unknown>,
        val as Record<string, unknown>,
      );
    } else {
      result[key] = val;
    }
  }
  return result;
}

function normalizeAdapters(
  adapters: Record<string, Record<string, unknown>> | undefined,
): Record<string, Record<string, unknown>> {
  const normalized: Record<string, Record<string, unknown>> = {
    ...(adapters ?? {}),
  };

  // Backward compatibility with legacy key from older examples.
  if (normalized.claudeTelegram && !normalized["claude-telegram"]) {
    normalized["claude-telegram"] = normalized.claudeTelegram;
  }

  return normalized;
}

/**
 * Load and resolve agentguard config from a YAML file.
 */
export function loadConfig(configPath?: string): AgentGuardConfig {
  const filePath = configPath ?? findConfigFile();

  let rawConfig: Record<string, unknown> = {};
  if (filePath && fs.existsSync(filePath)) {
    const content = fs.readFileSync(filePath, "utf-8");
    rawConfig = parseYaml(content) as Record<string, unknown>;
  }

  // Start with defaults
  let config = deepMerge(
    DEFAULT_CONFIG as unknown as Record<string, unknown>,
    {},
  ) as unknown as AgentGuardConfig;

  // Apply profile defaults
  const profileName =
    (rawConfig.global as Record<string, unknown>)?.profile as
      | ProfileName
      | string
      | undefined;
  const resolvedProfileName = resolveProfileName(
    profileName ?? config.global.profile,
  );
  const profileDefaults = getProfile(resolvedProfileName);
  config = deepMerge(
    config as unknown as Record<string, unknown>,
    profileDefaults as Record<string, unknown>,
  ) as unknown as AgentGuardConfig;

  // Apply user config on top
  config = deepMerge(
    config as unknown as Record<string, unknown>,
    rawConfig,
  ) as unknown as AgentGuardConfig;

  // Expand template variables
  const workspace = config.global.workspace ?? process.cwd();
  const vars: Record<string, string> = {
    workspace,
    CWD: process.cwd(),
    HOME: process.env.HOME ?? process.env.USERPROFILE ?? "",
  };

  config = expandConfigStrings(
    config,
    vars,
    config.global.onUndefinedTemplateVar,
  ) as AgentGuardConfig;

  config.adapters = normalizeAdapters(config.adapters);
  config.global.profile = resolveProfileName(config.global.profile);

  return config;
}

function findConfigFile(): string | undefined {
  const candidates = [
    path.join(process.cwd(), "agentguard.yaml"),
    path.join(process.cwd(), "agentguard.yml"),
    path.join(process.cwd(), ".agentguard.yaml"),
  ];
  return candidates.find((c) => fs.existsSync(c));
}
