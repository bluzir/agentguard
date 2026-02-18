import fs from "node:fs";
import path from "node:path";
import { parse as parseYaml, stringify as toYaml } from "yaml";

interface LinkArgs {
  channel?: string;
  configPath?: string;
  chatIds: string[];
  userIds: string[];
}

function parseListArg(value: string): string[] {
  return value
    .split(",")
    .map((part) => part.trim())
    .filter(Boolean);
}

function parseArgs(): LinkArgs {
  const args = process.argv.slice(3);
  const parsed: LinkArgs = {
    chatIds: [],
    userIds: [],
  };

  let i = 0;
  if (args[0] && !args[0].startsWith("-")) {
    parsed.channel = args[0];
    i = 1;
  }

  for (; i < args.length; i++) {
    switch (args[i]) {
      case "--channel":
      case "-a":
        parsed.channel = args[++i] ?? parsed.channel;
        break;
      case "--config":
      case "-c":
        parsed.configPath = args[++i];
        break;
      case "--chat-id":
        parsed.chatIds.push(...parseListArg(args[++i] ?? ""));
        break;
      case "--user-id":
      case "--approver-user-id":
        parsed.userIds.push(...parseListArg(args[++i] ?? ""));
        break;
    }
  }

  return parsed;
}

function resolveConfigPath(configPath?: string): string {
  if (configPath) {
    return path.resolve(configPath);
  }

  const candidates = [
    path.join(process.cwd(), "agentguard.yaml"),
    path.join(process.cwd(), "agentguard.yml"),
    path.join(process.cwd(), ".agentguard.yaml"),
  ];

  const found = candidates.find((candidate) => fs.existsSync(candidate));
  if (!found) {
    throw new Error(
      "agentguard config not found. Run: npx agentguard init --framework <name>",
    );
  }
  return found;
}

function asRecord(value: unknown): Record<string, unknown> {
  if (value !== null && typeof value === "object" && !Array.isArray(value)) {
    return value as Record<string, unknown>;
  }
  return {};
}

function ensureStringArray(value: unknown): string[] {
  if (!Array.isArray(value)) return [];
  return value
    .filter((item): item is string => typeof item === "string")
    .map((item) => item.trim())
    .filter(Boolean);
}

function appendUnique(base: string[], additions: string[]): string[] {
  const seen = new Set(base);
  for (const value of additions) {
    if (!seen.has(value)) {
      base.push(value);
      seen.add(value);
    }
  }
  return base;
}

export async function run(): Promise<void> {
  const args = parseArgs();
  const channel = args.channel ?? "telegram";
  if (channel !== "telegram") {
    throw new Error('only "telegram" channel is supported right now');
  }

  if (args.chatIds.length === 0 || args.userIds.length === 0) {
    throw new Error(
      'telegram link requires both --chat-id and --user-id. Example: agentguard link telegram --chat-id 123 --user-id 456',
    );
  }

  const configPath = resolveConfigPath(args.configPath);
  const raw = parseYaml(fs.readFileSync(configPath, "utf-8")) as
    | Record<string, unknown>
    | null;
  const config = asRecord(raw);

  const approval = asRecord(config.approval);
  approval.enabled = true;
  approval.mode = approval.mode ?? "sync_wait";
  approval.waitTimeoutSec = approval.waitTimeoutSec ?? 90;
  approval.onTimeout = approval.onTimeout ?? "deny";
  approval.onConnectorError = approval.onConnectorError ?? "deny";

  const store = asRecord(approval.store);
  store.engine = store.engine ?? "sqlite";
  store.path = store.path ?? "./.agentguard/approvals.db";
  approval.store = store;

  const channels = asRecord(approval.channels);
  const telegram = asRecord(channels.telegram);
  telegram.enabled = true;
  telegram.transport = telegram.transport ?? "polling";
  telegram.botToken = telegram.botToken ?? "SET_ME";
  telegram.pollIntervalMs = telegram.pollIntervalMs ?? 1500;

  const allowedChatIds = appendUnique(
    ensureStringArray(telegram.allowedChatIds),
    args.chatIds,
  );
  const approverUserIds = appendUnique(
    ensureStringArray(telegram.approverUserIds),
    args.userIds,
  );
  telegram.allowedChatIds = allowedChatIds;
  telegram.approverUserIds = approverUserIds;

  channels.telegram = telegram;
  approval.channels = channels;
  config.approval = approval;

  const modules = ensureStringArray(config.modules);
  if (!modules.includes("approval_gate")) {
    const auditIndex = modules.indexOf("audit");
    if (auditIndex >= 0) {
      modules.splice(auditIndex, 0, "approval_gate");
    } else {
      modules.push("approval_gate");
    }
  }
  config.modules = modules;

  const moduleConfig = asRecord(config.moduleConfig);
  const approvalGate = asRecord(moduleConfig.approval_gate);
  const rules = Array.isArray(approvalGate.rules)
    ? approvalGate.rules
    : [];
  if (rules.length === 0) {
    approvalGate.autoRouting = {
      defaultChannel: "telegram",
      frameworkDefaults: {
        openclaw: "telegram",
        nanobot: "telegram",
        "claude-telegram": "telegram",
        generic: "http",
      },
      metadataKeys: ["channel", "provider", "transportChannel", "messenger"],
    };
    approvalGate.rules = [
      {
        tool: "Bash",
        channel: "auto",
        prompt: 'Approve execution of "Bash"?',
        timeoutSec: 90,
      },
    ];
  }
  moduleConfig.approval_gate = approvalGate;
  config.moduleConfig = moduleConfig;

  fs.writeFileSync(configPath, toYaml(config, { lineWidth: 120 }));

  console.log(`Linked Telegram approvals in ${configPath}`);
  console.log(`  chatIds:   ${allowedChatIds.join(", ")}`);
  console.log(`  approvers: ${approverUserIds.join(", ")}`);

  const token = typeof telegram.botToken === "string" ? telegram.botToken.trim() : "";
  if (!token || token === "SET_ME") {
    console.log("  next: set TELEGRAM_BOT_TOKEN or approval.channels.telegram.botToken");
  }
}
