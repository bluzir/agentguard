#!/usr/bin/env node
import readline from "node:readline";
import {
	createModules,
	GuardPhase,
	loadConfig,
	runPipeline,
} from "agentradius";

/**
 * Minimal custom adapter for Claude Code-based orchestrators that emit hook payloads:
 * - hook_event_name: PreToolUse | PostToolUse
 * - tool_name
 * - tool_input
 * - tool_response (PostToolUse)
 *
 * Output schema is Claude command-hook compatible:
 * - { "continue": true }                     -> allow
 * - { "decision": "block", "reason": "..." } -> block
 */
class ClaudeOrchestratorAdapter {
	toGuardEvent(input) {
		const payload =
			input && typeof input === "object" ? input : {};

		const hookEvent =
			payload.hook_event_name === "PostToolUse"
				? "PostToolUse"
				: "PreToolUse";

		return {
			phase:
				hookEvent === "PreToolUse"
					? GuardPhase.PRE_TOOL
					: GuardPhase.POST_TOOL,
			framework: "generic",
			sessionId:
				typeof payload.session_id === "string" && payload.session_id.length > 0
					? payload.session_id
					: typeof payload.sessionId === "string" && payload.sessionId.length > 0
						? payload.sessionId
						: "unknown",
			agentName:
				typeof payload.agent_name === "string" ? payload.agent_name : undefined,
			toolCall: {
				name:
					typeof payload.tool_name === "string" && payload.tool_name.length > 0
						? payload.tool_name
						: "unknown",
				arguments:
					payload.tool_input && typeof payload.tool_input === "object"
						? payload.tool_input
						: {},
				raw: payload,
			},
			toolResult:
				hookEvent === "PostToolUse"
					? {
							text:
								typeof payload.tool_response === "string"
									? payload.tool_response
									: JSON.stringify(payload.tool_response ?? ""),
							isError: Boolean(payload.is_error),
							raw: payload.tool_response,
						}
					: undefined,
			metadata: {
				hookEvent,
				channel:
					typeof payload.channel === "string" ? payload.channel : undefined,
				orchestrator:
					typeof payload.orchestrator === "string"
						? payload.orchestrator
						: "claude-code",
			},
		};
	}

	toResponse(result) {
		if (result.finalAction === "deny" || result.finalAction === "challenge") {
			return {
				decision: "block",
				reason: result.reason ?? "blocked by radius",
			};
		}

		return { continue: true };
	}
}

function parseArgs() {
	const args = process.argv.slice(2);
	let configPath;
	for (let i = 0; i < args.length; i++) {
		if (args[i] === "--config" || args[i] === "-c") {
			configPath = args[++i];
		}
	}
	return { configPath };
}

async function main() {
	const { configPath } = parseArgs();
	const config = loadConfig(configPath);
	const modules = createModules(config.modules, config.moduleConfig);
	const adapter = new ClaudeOrchestratorAdapter();

	const rl = readline.createInterface({
		input: process.stdin,
		terminal: false,
	});

	for await (const line of rl) {
		if (!line.trim()) continue;
		try {
			const raw = JSON.parse(line);
			const event = adapter.toGuardEvent(raw);
			const result = await runPipeline(event, modules, {
				defaultAction: config.global.defaultAction,
			});
			process.stdout.write(`${JSON.stringify(adapter.toResponse(result))}\n`);
		} catch (error) {
			const message = error instanceof Error ? error.message : String(error);
			process.stdout.write(
				`${JSON.stringify({ decision: "block", reason: `radius error: ${message}` })}\n`,
			);
		}
	}
}

main().catch((error) => {
	const message = error instanceof Error ? error.message : String(error);
	process.stderr.write(`[radius:custom-adapter] fatal: ${message}\n`);
	process.exit(1);
});

