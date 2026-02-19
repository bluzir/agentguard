import fs from "node:fs";
import path from "node:path";
import { execSync } from "node:child_process";
import { loadConfig } from "../config/index.js";
import { createModules } from "../modules/index.js";

function parseArgs(): { configPath?: string } {
  const args = process.argv.slice(3);
  let configPath: string | undefined;

  for (let i = 0; i < args.length; i++) {
    if (args[i] === "--config" || args[i] === "-c") {
      configPath = args[++i];
    }
  }

  return { configPath };
}

interface Check {
  name: string;
  status: "ok" | "warn" | "fail";
  message: string;
}

function nonEmpty(value: string | undefined): boolean {
  return typeof value === "string" && value.trim().length > 0;
}

function asStringArray(value: unknown): string[] {
  if (!Array.isArray(value)) return [];
  return value.filter((item): item is string => typeof item === "string");
}

export async function run(): Promise<void> {
  const { configPath } = parseArgs();
  const checks: Check[] = [];

  // 1. Config loadable
  let config;
  try {
    config = loadConfig(configPath);
    checks.push({ name: "Config", status: "ok", message: `profile: ${config.global.profile}` });
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    checks.push({ name: "Config", status: "fail", message: msg });
    printChecks(checks);
    return;
  }

  // 2. Modules instantiate
  try {
    const modules = createModules(config.modules, config.moduleConfig);
    checks.push({ name: "Modules", status: "ok", message: `${modules.length} modules loaded` });
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    checks.push({ name: "Modules", status: "fail", message: msg });
  }

  // 2.1 Critical profile posture checks
  const skillScanner = config.moduleConfig.skill_scanner as Record<string, unknown> | undefined;
  if (config.global.profile === "local") {
    const requireSignature = skillScanner?.requireSignature === true;
    const requireSbom = skillScanner?.requireSbom === true;
    const requirePinnedSource = skillScanner?.requirePinnedSource === true;
    const onProvenanceFailure = skillScanner?.onProvenanceFailure;

    checks.push({
      name: "Strict provenance policy",
      status:
        requireSignature &&
        requireSbom &&
        requirePinnedSource &&
        onProvenanceFailure === "deny"
          ? "ok"
          : "warn",
      message:
        requireSignature &&
        requireSbom &&
        requirePinnedSource &&
        onProvenanceFailure === "deny"
          ? "signature + SBOM + pinning enforced"
          : "strict profile should enforce signature/SBOM/pinning with deny on failure",
    });
  }

  // 3. Approval readiness (when enabled)
  if (config.approval.enabled) {
    checks.push({
      name: "Approvals",
      status: "ok",
      message: `enabled (${config.approval.mode})`,
    });

    if (config.modules.includes("approval_gate")) {
      checks.push({
        name: "approval_gate module",
        status: "ok",
        message: "present in modules list",
      });
    } else {
      checks.push({
        name: "approval_gate module",
        status: "fail",
        message: 'approval.enabled=true but "approval_gate" is missing from modules',
      });
    }

    const telegram = config.approval.channels.telegram;
    const http = config.approval.channels.http;
    const telegramEnabled = telegram?.enabled === true;
    const httpEnabled = http?.enabled === true;

    if (!telegramEnabled && !httpEnabled) {
      checks.push({
        name: "Approval channel",
        status: "fail",
        message: "no enabled approval channels (telegram/http)",
      });
    } else {
      checks.push({
        name: "Approval channel",
        status: "ok",
        message: [
          telegramEnabled ? "telegram" : "",
          httpEnabled ? "http" : "",
        ]
          .filter(Boolean)
          .join(", "),
      });
    }

    if (telegramEnabled && telegram) {
      if (nonEmpty(telegram.botToken) && telegram.botToken !== "SET_ME") {
        checks.push({
          name: "Telegram bot token",
          status: "ok",
          message: "configured",
        });
      } else {
        checks.push({
          name: "Telegram bot token",
          status: "fail",
          message: "missing. Set TELEGRAM_BOT_TOKEN or approval.channels.telegram.botToken",
        });
      }

      if (telegram.allowedChatIds.length > 0) {
        checks.push({
          name: "Telegram chat binding",
          status: "ok",
          message: `${telegram.allowedChatIds.length} chat id(s)`,
        });
      } else {
        checks.push({
          name: "Telegram chat binding",
          status: "fail",
          message: 'no allowedChatIds. Run: agentradius link telegram --chat-id <id> --user-id <id>',
        });
      }

      if (telegram.approverUserIds.length > 0) {
        checks.push({
          name: "Telegram approvers",
          status: "ok",
          message: `${telegram.approverUserIds.length} approver id(s)`,
        });
      } else {
        checks.push({
          name: "Telegram approvers",
          status: "fail",
          message: 'no approverUserIds. Run: agentradius link telegram --chat-id <id> --user-id <id>',
        });
      }

      if (telegram.transport === "webhook") {
        if (nonEmpty(telegram.webhookPublicUrl)) {
          checks.push({
            name: "Telegram webhook URL",
            status: "ok",
            message: telegram.webhookPublicUrl as string,
          });
        } else {
          checks.push({
            name: "Telegram webhook URL",
            status: "fail",
            message: "transport=webhook requires approval.channels.telegram.webhookPublicUrl",
          });
        }

        checks.push({
          name: "Telegram webhook runtime",
          status: "warn",
          message:
            "telegram transport=webhook is declared in config, but current resolver behavior is polling-centric. Validate topology or prefer HTTP approval bridge for single-bot setups",
        });
      } else {
        checks.push({
          name: "Telegram transport",
          status: "ok",
          message: "polling",
        });

        const claudeTelegramAdapter = (
          config.adapters?.["claude-telegram"] as Record<string, unknown> | undefined
        )?.enabled;
        if (claudeTelegramAdapter === true) {
          checks.push({
            name: "Telegram polling topology",
            status: "warn",
            message:
              "if Radius and orchestrator share the same bot token, polling consumers can race. Prefer separate bot token, webhook transport, or HTTP approvals bridge",
          });
        }
      }
    }

    if (httpEnabled && http) {
      if (nonEmpty(http.url)) {
        checks.push({
          name: "HTTP approval endpoint",
          status: "ok",
          message: http.url,
        });
      } else {
        checks.push({
          name: "HTTP approval endpoint",
          status: "fail",
          message: "missing. Set approval.channels.http.url",
        });
      }

      if (typeof http.timeoutMs === "number" && http.timeoutMs > 0) {
        checks.push({
          name: "HTTP approval timeout",
          status: "ok",
          message: `${http.timeoutMs}ms`,
        });
      } else {
        checks.push({
          name: "HTTP approval timeout",
          status: "fail",
          message: "approval.channels.http.timeoutMs must be > 0",
        });
      }
    }

    if (config.approval.store.engine === "sqlite") {
      const dbPath = config.approval.store.path;
      if (!nonEmpty(dbPath)) {
        checks.push({
          name: "Approval store",
          status: "fail",
          message: "sqlite store requires approval.store.path",
        });
      } else {
        const parentDir = path.dirname(dbPath!);
        if (fs.existsSync(parentDir)) {
          checks.push({
            name: "Approval store",
            status: "ok",
            message: `${dbPath} (sqlite)`,
          });
        } else {
          checks.push({
            name: "Approval store",
            status: "warn",
            message: `parent dir not found for ${dbPath}`,
          });
        }
      }
    } else {
      checks.push({
        name: "Approval store",
        status: "ok",
        message: `${config.approval.store.engine}`,
      });
    }
  } else {
    checks.push({
      name: "Approvals",
      status: "ok",
      message: "disabled",
    });
  }

  // 4. Workspace exists
  if (fs.existsSync(config.global.workspace)) {
    checks.push({ name: "Workspace", status: "ok", message: config.global.workspace });
  } else {
    checks.push({ name: "Workspace", status: "warn", message: `not found: ${config.global.workspace}` });
  }

  // 4.1 Secrets architecture posture
  const fsGuard = (config.moduleConfig.fs_guard ?? {}) as Record<string, unknown>;
  const blockedBasenames = asStringArray(fsGuard.blockedBasenames).map((v) =>
    v.trim().toLowerCase(),
  );
  const blocksDotEnv = blockedBasenames.includes(".env");
  checks.push({
    name: "Dotenv read policy",
    status:
      blocksDotEnv || config.global.profile !== "local" ? "ok" : "fail",
    message: blocksDotEnv
      ? '.env basename is blocked by fs_guard'
      : 'strict profile should block ".env" via fs_guard.blockedBasenames',
  });

  const dotEnvPath = path.join(config.global.workspace, ".env");
  if (fs.existsSync(dotEnvPath)) {
    checks.push({
      name: "Workspace .env",
      status: "warn",
      message:
        ".env found in workspace. Prefer ephemeral/scoped credentials for agent runtime.",
    });
  } else {
    checks.push({
      name: "Workspace .env",
      status: "ok",
      message: "not found",
    });
  }

  // 5. Audit sink writable
  if (config.audit.sink === "file" && config.audit.path) {
    try {
      fs.accessSync(config.audit.path, fs.constants.W_OK);
      checks.push({ name: "Audit sink", status: "ok", message: config.audit.path });
    } catch {
      // File may not exist yet, check parent dir
      const dir = config.audit.path.substring(0, config.audit.path.lastIndexOf("/"));
      if (!dir || fs.existsSync(dir || ".")) {
        checks.push({ name: "Audit sink", status: "ok", message: `${config.audit.path} (will be created)` });
      } else {
        checks.push({ name: "Audit sink", status: "warn", message: `parent dir not found for ${config.audit.path}` });
      }
    }
  }

  // 6. Sandbox engine
  const sandboxConfig = config.moduleConfig.exec_sandbox as Record<string, unknown> | undefined;
  if (sandboxConfig?.engine === "bwrap") {
    try {
      execSync("which bwrap", { stdio: "pipe" });
      checks.push({ name: "Sandbox (bwrap)", status: "ok", message: "bwrap found" });
    } catch {
      const status = sandboxConfig.required ? "fail" : "warn";
      checks.push({ name: "Sandbox (bwrap)", status, message: "bwrap not found" });
    }
  }

  printChecks(checks);

  const hasFail = checks.some((c) => c.status === "fail");
  if (hasFail) process.exit(1);
}

function printChecks(checks: Check[]): void {
  console.log("\nagentradius doctor\n");
  for (const c of checks) {
    const icon = c.status === "ok" ? "OK  " : c.status === "warn" ? "WARN" : "FAIL";
    console.log(`  [${icon}] ${c.name}: ${c.message}`);
  }
  console.log();
}
