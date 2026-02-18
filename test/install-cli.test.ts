import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { describe, expect, it } from "vitest";
import { run as initRun } from "../src/cli/init.js";
import { generateWiringArtifacts } from "../src/cli/install.js";

function withArgv(argv: string[], fn: () => Promise<void>): Promise<void> {
	const previous = process.argv;
	process.argv = argv;
	return fn().finally(() => {
		process.argv = previous;
	});
}

describe("install wiring", () => {
	it("generates openclaw hooks with stable script path resolution", () => {
		const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "agentguard-install-openclaw-"));
		const configPath = path.join(tmpDir, "agentguard.yaml");
		fs.writeFileSync(configPath, "global:\n  profile: balanced\n");

		generateWiringArtifacts({
			framework: "openclaw",
			configPath,
			outputDir: path.join(tmpDir, ".agentguard"),
		});

		const hookScriptPath = path.join(tmpDir, ".agentguard", "openclaw-hook.command.sh");
		const hookScript = fs.readFileSync(hookScriptPath, "utf-8");
		expect(hookScript).toContain('SCRIPT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"');
		expect(hookScript).toContain('CONFIG_PATH="${AGENTGUARD_CONFIG:-$SCRIPT_DIR/../agentguard.yaml}"');
		expect(hookScript).toContain('exec npx agentguard hook --adapter openclaw --config "$CONFIG_PATH"');

		const hooksJsonPath = path.join(tmpDir, ".agentguard", "openclaw-hooks.json");
		const hooks = JSON.parse(fs.readFileSync(hooksJsonPath, "utf-8")) as Record<string, unknown>;
		const root = hooks.hooks as Record<string, unknown>;
		const preToolUse = root.PreToolUse as Array<Record<string, unknown>>;
		expect(preToolUse[0]?.matcher).toBe("*");
		expect(preToolUse[0]?.hooks).toEqual([".agentguard/openclaw-hook.command.sh"]);
	});

	it("patches .claude/settings.local.json for tool hooks without clobbering permissions", () => {
		const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "agentguard-install-claude-"));
		const configPath = path.join(tmpDir, "agentguard.yaml");
		const settingsPath = path.join(tmpDir, ".claude", "settings.local.json");
		fs.mkdirSync(path.dirname(settingsPath), { recursive: true });
		fs.writeFileSync(configPath, "global:\n  profile: balanced\n");
		fs.writeFileSync(
			settingsPath,
			JSON.stringify(
				{
					permissions: {
						allow: ["Bash(ls:*)"],
					},
				},
				null,
				2,
			),
		);

		generateWiringArtifacts({
			framework: "claude-telegram",
			configPath,
			outputDir: path.join(tmpDir, ".agentguard"),
		});
		generateWiringArtifacts({
			framework: "claude-telegram",
			configPath,
			outputDir: path.join(tmpDir, ".agentguard"),
		});

		const settings = JSON.parse(fs.readFileSync(settingsPath, "utf-8")) as Record<string, unknown>;
		expect((settings.permissions as Record<string, unknown>).allow).toEqual(["Bash(ls:*)"]);

		const hooks = settings.hooks as Record<string, unknown>;
		const pre = hooks.PreToolUse as Array<Record<string, unknown>>;
		const post = hooks.PostToolUse as Array<Record<string, unknown>>;
		expect(pre).toHaveLength(1);
		expect(post).toHaveLength(1);
		expect(pre[0]?.matcher).toBe("*");
		expect(post[0]?.matcher).toBe("*");
		expect(pre[0]?.hooks).toEqual([
			{ type: "command", command: ".agentguard/claude-tool-hook.command.sh" },
		]);
		expect(post[0]?.hooks).toEqual([
			{ type: "command", command: ".agentguard/claude-tool-hook.command.sh" },
		]);
	});

	it("init creates parent output directories before writing config", async () => {
		const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "agentguard-init-output-"));
		const configPath = path.join(tmpDir, "nested", "path", "agentguard.yaml");

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
			],
			async () => {
				await initRun();
			},
		);

		expect(fs.existsSync(configPath)).toBe(true);
		expect(
			fs.existsSync(path.join(path.dirname(configPath), ".agentguard", "openclaw-hook.command.sh")),
		).toBe(true);
	});
});

