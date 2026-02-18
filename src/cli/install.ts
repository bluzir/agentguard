import fs from "node:fs";
import path from "node:path";
import { loadConfig } from "../config/index.js";

const FRAMEWORKS = ["openclaw", "nanobot", "claude-telegram", "generic"] as const;
type FrameworkName = (typeof FRAMEWORKS)[number];

interface InstallArgs {
	configPath?: string;
	framework?: string;
	outputDir: string;
	dryRun: boolean;
}

export interface WiringResult {
	framework: FrameworkName;
	outputDir: string;
	files: string[];
}

type JsonRecord = Record<string, unknown>;

function parseArgs(): InstallArgs {
	const args = process.argv.slice(3);

	let configPath: string | undefined;
	let framework: string | undefined;
	let outputDir = ".radius";
	let dryRun = false;

	for (let i = 0; i < args.length; i++) {
		switch (args[i]) {
			case "--config":
			case "-c":
				configPath = args[++i];
				break;
			case "--framework":
			case "-f":
				framework = args[++i];
				break;
			case "--output-dir":
			case "-o":
				outputDir = args[++i] ?? outputDir;
				break;
			case "--dry-run":
				dryRun = true;
				break;
		}
	}

	return { configPath, framework, outputDir, dryRun };
}

function mapFrameworkName(raw: string | undefined): FrameworkName | undefined {
	if (!raw) return undefined;
	if (raw === "claudeTelegram") return "claude-telegram";
	if (FRAMEWORKS.includes(raw as FrameworkName)) {
		return raw as FrameworkName;
	}
	return undefined;
}

function detectFrameworkFromConfig(
	adapters: Record<string, Record<string, unknown>>,
): FrameworkName {
	for (const [name, conf] of Object.entries(adapters)) {
		if (!(conf as Record<string, unknown>).enabled) continue;
		const mapped = mapFrameworkName(name);
		if (mapped) return mapped;
	}
	return "generic";
}

function writeFile(
	targetPath: string,
	content: string,
	dryRun: boolean,
	executable = false,
): void {
	if (dryRun) return;
	fs.mkdirSync(path.dirname(targetPath), { recursive: true });
	fs.writeFileSync(targetPath, content);
	if (executable) {
		fs.chmodSync(targetPath, 0o755);
	}
}

function asRecord(value: unknown): JsonRecord {
	if (value && typeof value === "object" && !Array.isArray(value)) {
		return value as JsonRecord;
	}
	return {};
}

function hasHookCommand(entry: unknown, commandPath: string): boolean {
	if (!entry || typeof entry !== "object") return false;
	const item = entry as JsonRecord;
	if (item.type === "command" && item.command === commandPath) {
		return true;
	}
	const hooks = item.hooks;
	if (!Array.isArray(hooks)) return false;
	return hooks.some((hook) => {
		if (typeof hook === "string") {
			return hook === commandPath;
		}
		if (!hook || typeof hook !== "object") return false;
		const hookItem = hook as JsonRecord;
		return hookItem.type === "command" && hookItem.command === commandPath;
	});
}

function mergeClaudeToolHooks(
	settings: JsonRecord,
	commandPath: string,
): JsonRecord {
	const hooks = asRecord(settings.hooks);
	const resultHooks: JsonRecord = { ...hooks };
	for (const event of ["PreToolUse", "PostToolUse"] as const) {
		const entries = Array.isArray(hooks[event]) ? [...hooks[event]] : [];
		const alreadyPresent = entries.some((entry) =>
			hasHookCommand(entry, commandPath),
		);
		if (!alreadyPresent) {
			entries.push({
				matcher: "*",
				hooks: [
					{
						type: "command",
						command: commandPath,
					},
				],
			});
		}
		resultHooks[event] = entries;
	}
	return {
		...settings,
		hooks: resultHooks,
	};
}

function buildHookCommandScript(
	adapter: "openclaw",
	configRef: string,
): string {
	return [
		"#!/usr/bin/env sh",
		"set -eu",
		'SCRIPT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"',
		`CONFIG_PATH="\${RADIUS_CONFIG:-$SCRIPT_DIR/${configRef}}"`,
		`exec npx agentradius hook --adapter ${adapter} --config "$CONFIG_PATH"`,
		"",
	].join("\n");
}

export function generateWiringArtifacts(options: {
	framework: FrameworkName;
	configPath: string;
	outputDir: string;
	dryRun?: boolean;
}): WiringResult {
	const framework = options.framework;
	const outputDir = path.resolve(options.outputDir);
	const projectRoot = path.dirname(outputDir);
	const dryRun = options.dryRun ?? false;
	const files: string[] = [];

	const configRef = path
		.relative(outputDir, path.resolve(options.configPath))
		.replace(/\\/g, "/");

	const addFile = (filename: string, content: string, executable = false) => {
		const target = path.join(outputDir, filename);
		writeFile(target, content, dryRun, executable);
		files.push(target);
	};

	const addProjectFile = (
		relativePath: string,
		content: string,
		executable = false,
	) => {
		const target = path.join(projectRoot, relativePath);
		writeFile(target, content, dryRun, executable);
		files.push(target);
	};

	addFile(
		"README.md",
		[
			"# radius wiring",
			"",
			`Framework: ${framework}`,
			"Generated snippets and scripts for adapter wiring.",
			"",
			"Regenerate:",
			`  npx agentradius install --framework ${framework}`,
			"",
		].join("\n"),
	);

	switch (framework) {
		case "openclaw":
			addFile(
				"openclaw-hook.command.sh",
				buildHookCommandScript("openclaw", configRef),
				true,
			);
			addFile(
				"openclaw-hooks.json",
				[
					"{",
					'  "hooks": {',
					'    "PreToolUse": [',
					'      {',
					'        "matcher": "*",',
					'        "hooks": [".radius/openclaw-hook.command.sh"]',
					"      }",
					"    ],",
					'    "PostToolUse": [',
					'      {',
					'        "matcher": "*",',
					'        "hooks": [".radius/openclaw-hook.command.sh"]',
					"      }",
					"    ]",
					"  }",
					"}",
					"",
				].join("\n"),
			);
			break;

		case "nanobot":
			addFile(
				"nanobot-hooks.yaml",
				[
					"mcpServers:",
					"  radius:",
					`    command: \"npx agentradius serve --adapter nanobot --config ${configRef}\"`,
					"",
					"  # For each server to protect:",
					"  filesystem:",
					"    command: \"...\"",
					"    hooks:",
					'      "tools/call?direction=request": ["radius/pre_tool"]',
					'      "tools/call?direction=response": ["radius/post_tool"]',
					"",
				].join("\n"),
			);
			break;

		case "claude-telegram":
			addFile(
				"claude-telegram.module.yaml",
				[
					"modules:",
					'  - import: "@agentradius/adapter-claude-telegram"',
					"    options:",
					`      config: "${configRef}"`,
					'      mode: "message_only" # message_only | message_plus_tool_hooks',
					"",
				].join("\n"),
			);
			addFile(
				"claude-tool-hook.command.sh",
				buildHookCommandScript("openclaw", configRef),
				true,
			);
			{
				const commandPath = ".radius/claude-tool-hook.command.sh";
				const settingsPath = path.join(
					projectRoot,
					".claude",
					"settings.local.json",
				);
				let settings: JsonRecord = {};
				if (fs.existsSync(settingsPath)) {
					try {
						const raw = fs.readFileSync(settingsPath, "utf-8");
						settings = asRecord(JSON.parse(raw));
					} catch (error) {
						const message =
							error instanceof Error ? error.message : String(error);
						throw new Error(
							`failed to parse ${settingsPath}: ${message}`,
						);
					}
				}
				const merged = mergeClaudeToolHooks(settings, commandPath);
				addProjectFile(
					path.join(".claude", "settings.local.json"),
					`${JSON.stringify(merged, null, 2)}\n`,
				);
			}
			break;

		case "generic":
			addFile(
				"generic-http.example.sh",
				[
					"#!/usr/bin/env sh",
					"curl -sS -X POST http://localhost:3100/check \\",
					'  -H "content-type: application/json" \\',
					"  -d '{\"phase\":\"pre_request\",\"framework\":\"generic\",\"sessionId\":\"demo\",\"requestText\":\"hello\",\"metadata\":{}}'",
					"",
				].join("\n"),
				true,
			);
			break;
	}

	return {
		framework,
		outputDir,
		files,
	};
}

export async function run(): Promise<void> {
	const args = parseArgs();
	const config = loadConfig(args.configPath);

	const fromArgs = mapFrameworkName(args.framework);
	if (args.framework && !fromArgs) {
		throw new Error(
			`unknown framework: "${args.framework}". Available: ${FRAMEWORKS.join(", ")}`,
		);
	}

	const framework =
		fromArgs ?? detectFrameworkFromConfig(config.adapters) ?? "generic";
	const configPath = path.resolve(args.configPath ?? "radius.yaml");

	const result = generateWiringArtifacts({
		framework,
		configPath,
		outputDir: args.outputDir,
		dryRun: args.dryRun,
	});

	console.log(
		`${args.dryRun ? "Planned" : "Generated"} wiring artifacts for ${framework}:`,
	);
	for (const file of result.files) {
		console.log(`  - ${file}`);
	}
}
