import fs from "node:fs";
import { createRequire } from "node:module";
import path from "node:path";
import { stringify as toYaml } from "yaml";
import { getProfile, resolveProfileName } from "../config/profiles.js";
import { generateWiringArtifacts } from "./install.js";

const require = createRequire(import.meta.url);
const FRAMEWORKS = ["openclaw", "nanobot", "claude-telegram", "generic"] as const;
const APPROVAL_CHANNELS = ["telegram", "http"] as const;

function isNodeSqliteAvailable(): boolean {
  try {
    const sqliteModule = require("node:sqlite") as {
      DatabaseSync?: unknown;
    };
    return typeof sqliteModule.DatabaseSync === "function";
  } catch {
    return false;
  }
}

function parseArgs(): {
  framework: string;
  profile: string;
  mode?: string;
  output: string;
  approvals?: string;
} {
  const args = process.argv.slice(3);
  let framework = "generic";
  let profile = "standard";
  let mode: string | undefined;
  let output = "./radius.yaml";
  let approvals: string | undefined;

  for (let i = 0; i < args.length; i++) {
    switch (args[i]) {
      case "--framework":
      case "-f":
        framework = args[++i] ?? framework;
        break;
      case "--profile":
      case "-p":
        profile = args[++i] ?? profile;
        break;
      case "--mode":
      case "-m":
        mode = args[++i] ?? mode;
        break;
      case "--output":
      case "-o":
        output = args[++i] ?? output;
        break;
      case "--approvals":
        approvals = args[++i] ?? approvals;
        break;
    }
  }

  return { framework, profile, mode, output, approvals };
}

export async function run(): Promise<void> {
  const { framework, profile, mode, output, approvals } = parseArgs();
  const sqliteAvailable = isNodeSqliteAvailable();

  if (!FRAMEWORKS.includes(framework as (typeof FRAMEWORKS)[number])) {
    throw new Error(`unknown framework: "${framework}". Available: ${FRAMEWORKS.join(", ")}`);
  }
  const profileInput = mode ?? profile;
  const resolvedProfile = resolveProfileName(profileInput);
  if (
    approvals &&
    !APPROVAL_CHANNELS.includes(approvals as (typeof APPROVAL_CHANNELS)[number])
  ) {
    throw new Error(
      `unknown approvals channel: "${approvals}". Available: ${APPROVAL_CHANNELS.join(", ")}`,
    );
  }

  const profileConfig = getProfile(resolvedProfile);
  const modules = [...(profileConfig.modules ?? [])];
  const profileFsGuard =
    (profileConfig.moduleConfig?.fs_guard as Record<string, unknown>) ?? {};
  const profileCommandGuard =
    (profileConfig.moduleConfig?.command_guard as Record<string, unknown>) ?? {};

  const defaultCommandDenyPatterns =
    resolvedProfile === "local"
      ? [
          "(^|\\s)sudo\\s",
          "rm\\s+-rf\\s+/",
          "(^|\\s)(cat|less|more|head|tail|grep|awk|sed)\\s+[^\\n]*\\.env(?:\\.|\\s|$)",
        ]
      : ["(^|\\s)sudo\\s", "rm\\s+-rf\\s+/"];

  const fsGuardBlockedBasenames =
    (profileFsGuard.blockedBasenames as string[] | undefined) ?? [
      ".env",
      ".env.local",
      ".env.development",
      ".env.production",
      ".env.test",
      ".envrc",
    ];

  const commandGuardDenyPatterns =
    (profileCommandGuard.denyPatterns as string[] | undefined) ??
    defaultCommandDenyPatterns;

  if (approvals && !modules.includes("approval_gate")) {
    const auditIndex = modules.indexOf("audit");
    if (auditIndex >= 0) {
      modules.splice(auditIndex, 0, "approval_gate");
    } else {
      modules.push("approval_gate");
    }
  }

  const approvalConfig =
    approvals === "telegram"
      ? {
          enabled: true,
          mode: "sync_wait",
          waitTimeoutSec: 90,
          temporaryGrantTtlSec: 1800,
          maxTemporaryGrantTtlSec: 1800,
          onTimeout: "deny",
          onConnectorError: "deny",
              store: {
                engine: "sqlite",
                path: "./.radius/state.db",
                required: sqliteAvailable,
              },
          channels: {
            telegram: {
              enabled: true,
              transport: "polling",
              botToken: "SET_ME",
              allowedChatIds: [],
              approverUserIds: [],
              pollIntervalMs: 1500,
              webhookPublicUrl: "",
            },
            http: {
              enabled: false,
              url: "",
              timeoutMs: 10000,
              headers: {},
            },
          },
        }
      : approvals === "http"
        ? {
            enabled: true,
            mode: "sync_wait",
            waitTimeoutSec: 90,
            temporaryGrantTtlSec: 1800,
            maxTemporaryGrantTtlSec: 1800,
            onTimeout: "deny",
            onConnectorError: "deny",
              store: {
                engine: "sqlite",
                path: "./.radius/state.db",
                required: sqliteAvailable,
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
                url: "http://127.0.0.1:3101/approvals/resolve",
                timeoutMs: 10000,
                headers: {},
              },
            },
          }
      : {
          enabled: false,
          mode: "sync_wait",
          waitTimeoutSec: 90,
          temporaryGrantTtlSec: 1800,
          maxTemporaryGrantTtlSec: 1800,
          onTimeout: "deny",
          onConnectorError: "deny",
              store: {
                engine: "sqlite",
                path: "./.radius/state.db",
                required: sqliteAvailable,
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
              enabled: false,
              url: "",
              timeoutMs: 10000,
              headers: {},
            },
          },
        };

  const approvalGateConfig =
    approvals === "telegram"
      ? {
          autoRouting: {
            defaultChannel: "telegram",
            frameworkDefaults: {
              openclaw: "telegram",
              nanobot: "telegram",
              "claude-telegram": "telegram",
              generic: "http",
            },
            metadataKeys: ["channel", "provider", "transportChannel", "messenger"],
          },
          rules: [
            {
              tool: "Bash",
              channel: "auto",
              prompt: 'Approve execution of "Bash"?',
              timeoutSec: 90,
            },
          ],
        }
      : approvals === "http"
        ? {
            autoRouting: {
              defaultChannel: "http",
              frameworkDefaults: {
                openclaw: "http",
                nanobot: "http",
                "claude-telegram": "http",
                generic: "http",
              },
              metadataKeys: ["channel", "provider", "transportChannel", "messenger"],
            },
            rules: [
              {
                tool: "Bash",
                channel: "http",
                prompt: 'Approve execution of "Bash"?',
                timeoutSec: 90,
              },
            ],
          }
        : undefined;

  // Build config with adapter enabled
  const config = {
    global: {
      profile: resolvedProfile,
      workspace: "${CWD}",
      defaultAction: profileConfig.global?.defaultAction ?? "deny",
      requireSignedPolicy: false,
      onUndefinedTemplateVar: "error",
    },
    audit: {
      sink: "file",
      path: "./radius-audit.jsonl",
      includeArguments: true,
      includeResults: false,
    },
    approval: approvalConfig,
    adapters: {
      [framework]: {
        enabled: true,
      },
    },
    modules,
    moduleConfig: {
      ...profileConfig.moduleConfig,
      ...(approvalGateConfig ? { approval_gate: approvalGateConfig } : {}),
      tool_policy: {
        ...((profileConfig.moduleConfig?.tool_policy as Record<string, unknown>) ?? {}),
        rules: [
          {
            tool: "Read",
            action: "allow",
            schema: {
              requiredArgs: ["file_path"],
              argConstraints: {
                file_path: { type: "string", maxLength: 4096 },
              },
            },
          },
          {
            tool: "Bash",
            action: "allow",
            schema: {
              requiredArgs: ["command"],
              argConstraints: {
                command: { type: "string", maxLength: 8000 },
              },
            },
          },
        ],
      },
      fs_guard: {
        ...profileFsGuard,
        allowedPaths: ["${workspace}", "/tmp"],
        blockedPaths: ["~/.ssh", "~/.aws", "/etc"],
        blockedBasenames: fsGuardBlockedBasenames,
      },
      command_guard: {
        ...profileCommandGuard,
        denyPatterns: commandGuardDenyPatterns,
      },
      rate_budget: {
        ...((profileConfig.moduleConfig?.rate_budget as Record<string, unknown>) ??
          {}),
        store: {
          engine: "sqlite",
          path: "./.radius/state.db",
          required: sqliteAvailable,
        },
      },
    },
  };

  const outputPath = path.resolve(output);
  const yaml = toYaml(config, { lineWidth: 120 });

  fs.mkdirSync(path.dirname(outputPath), { recursive: true });
  fs.writeFileSync(outputPath, yaml);

  const wiring = generateWiringArtifacts({
    framework: framework as (typeof FRAMEWORKS)[number],
    configPath: outputPath,
    outputDir: path.join(path.dirname(outputPath), ".radius"),
  });

  console.log(`Config written to ${outputPath}`);
  console.log(`  Framework: ${framework}`);
  console.log(`  Profile:   ${resolvedProfile}`);
  if (mode) {
    console.log(`  Mode:      ${mode}`);
  }
  console.log(`  Approvals: ${approvals ?? "disabled"}`);
  console.log(`  Wiring:    ${wiring.files.length} file(s) in ${wiring.outputDir}`);
  console.log(`\nNext steps:`);
  console.log(`  1. Review and customize ${output}`);
  console.log(`  2. Review wiring snippets in ./.radius/`);
  console.log(`  3. Run: agentradius doctor`);
  console.log(`  4. Run: agentradius scan`);
  if (approvals === "telegram") {
    console.log(`  5. Set TELEGRAM_BOT_TOKEN or edit approval.channels.telegram.botToken`);
    console.log(
      `  6. Run: agentradius link telegram --chat-id <chat_id> --user-id <telegram_user_id>`,
    );
  } else if (approvals === "http") {
    console.log(`  5. Configure approval.channels.http.url to your approval endpoint`);
  }
}
