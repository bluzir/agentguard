import { describe, expect, it } from "vitest";
import { ClaudeTelegramAdapter } from "../src/adapters/claude-telegram.js";
import { createAdapter } from "../src/adapters/index.js";
import { GenericAdapter } from "../src/adapters/generic.js";
import { NanobotAdapter } from "../src/adapters/nanobot.js";
import { OpenClawAdapter } from "../src/adapters/openclaw.js";
import { DecisionAction, GuardPhase, type PipelineResult } from "../src/types.js";

describe("Adapters malformed payload handling", () => {
	it("generic adapter returns safe defaults", () => {
		const adapter = new GenericAdapter();
		const event = adapter.toGuardEvent({});

		expect(event.phase).toBe(GuardPhase.PRE_REQUEST);
		expect(event.sessionId).toBe("unknown");
		expect(event.metadata).toEqual({});
	});

	it("claude-telegram adapter tolerates missing ctx", () => {
		const adapter = new ClaudeTelegramAdapter();
		const event = adapter.toGuardEvent({});

		expect(event.sessionId).toBe("unknown");
		expect(event.metadata).toEqual({ channel: "telegram" });
	});

	it("openclaw adapter tolerates malformed hook payload", () => {
		const adapter = new OpenClawAdapter();
		const event = adapter.toGuardEvent({});

		expect(event.sessionId).toBe("unknown");
		expect(event.toolCall?.name).toBe("unknown");
		expect(event.metadata).toEqual({});
	});

	it("openclaw adapter maps PostToolUse output into toolResult", () => {
		const adapter = new OpenClawAdapter();
		const event = adapter.toGuardEvent({
			hook_type: "PostToolUse",
			tool_name: "Bash",
			tool_input: { command: "echo hi" },
			tool_output: "hi",
		});

		expect(event.phase).toBe(GuardPhase.POST_TOOL);
		expect(event.toolResult?.text).toBe("hi");
		expect(event.toolResult?.isError).toBe(false);
	});

	it("openclaw adapter supports claude-style hook_event_name payload", () => {
		const adapter = new OpenClawAdapter();
		const event = adapter.toGuardEvent({
			hook_event_name: "PostToolUse",
			tool_name: "Bash",
			tool_input: { command: "echo hi" },
			tool_response: "hi",
			sessionId: "session-99",
		});

		expect(event.phase).toBe(GuardPhase.POST_TOOL);
		expect(event.sessionId).toBe("session-99");
		expect(event.toolResult?.text).toBe("hi");
	});

	it("openclaw adapter maps multi-agent routing hints", () => {
		const adapter = new OpenClawAdapter();
		const event = adapter.toGuardEvent({
			hook_type: "PreToolUse",
			session_id: "sess-1",
			agent_name: "deployer",
			channel: "discord",
			mode: "bunker",
			task_type: "deploy",
			tags: ["prod", "critical"],
			tool_name: "Bash",
			tool_input: { command: "echo hi" },
		});

		expect(event.sessionId).toBe("sess-1");
		expect(event.agentName).toBe("deployer");
		expect(event.metadata.channel).toBe("discord");
		expect(event.metadata.modeHint).toBe("bunker");
		expect(event.metadata.taskType).toBe("deploy");
		expect(event.metadata.routeTags).toEqual(["prod", "critical"]);
	});

	it("nanobot adapter tolerates malformed hook payload", () => {
		const adapter = new NanobotAdapter();
		const event = adapter.toGuardEvent({});

		expect(event.sessionId).toBe("unknown");
		expect(event.metadata).toEqual({});
	});

	it("nanobot adapter maps multi-agent routing hints", () => {
		const adapter = new NanobotAdapter();
		const event = adapter.toGuardEvent({
			direction: "request",
			method: "tools/call",
			sessionId: "s-123",
			channel: "telegram",
			mode: "tactical",
			taskType: "refactor",
			tags: ["dev"],
			params: {
				name: "Bash",
				arguments: { command: "echo hi" },
				agent: "worker-a",
			},
		});

		expect(event.sessionId).toBe("s-123");
		expect(event.agentName).toBe("worker-a");
		expect(event.metadata.channel).toBe("telegram");
		expect(event.metadata.direction).toBe("request");
		expect(event.metadata.method).toBe("tools/call");
		expect(event.metadata.modeHint).toBe("tactical");
		expect(event.metadata.taskType).toBe("refactor");
		expect(event.metadata.routeTags).toEqual(["dev"]);
	});

	it("claude-telegram adapter maps agent and routing hints from ctx", () => {
		const adapter = new ClaudeTelegramAdapter();
		const event = adapter.toGuardEvent({
			hook: "beforeClaude",
				ctx: {
					chatId: 42,
					userId: 7,
					agentName: "assistant-main",
					profile: "yolo",
					labels: ["research"],
				},
				message: "hello",
			});

		expect(event.agentName).toBe("assistant-main");
		expect(event.metadata.channel).toBe("telegram");
		expect(event.metadata.modeHint).toBe("yolo");
		expect(event.metadata.routeTags).toEqual(["research"]);
	});

	it("propagates challenge response for openclaw", () => {
		const adapter = new OpenClawAdapter();
		const response = adapter.toResponse(challengeResult(), {});

		expect(response.decision).toBe("challenge");
		expect(response.challenge?.prompt).toBe("approve?");
	});

	it("propagates challenge response for nanobot", () => {
		const adapter = new NanobotAdapter();
		const response = adapter.toResponse(challengeResult(), {});

		expect(response.accept).toBe(false);
		expect(response.challenge?.prompt).toBe("approve?");
	});

	it("propagates challenge response for claude-telegram", () => {
		const adapter = new ClaudeTelegramAdapter();
		const response = adapter.toResponse(challengeResult(), {});

		expect(response.allow).toBe(false);
		expect(response.challenge?.prompt).toBe("approve?");
	});

	it("supports legacy claudeTelegram adapter alias", () => {
		const adapter = createAdapter("claudeTelegram");
		expect(adapter.name).toBe("claude-telegram");
	});
});

function challengeResult(): PipelineResult {
	return {
		finalAction: DecisionAction.CHALLENGE,
		reason: "needs approval",
		transformed: {},
		alerts: [],
		decisions: [
			{
				action: DecisionAction.CHALLENGE,
				module: "approval_gate",
				reason: "needs approval",
				severity: "high",
				challenge: {
					channel: "orchestrator",
					prompt: "approve?",
					timeoutSec: 60,
				},
			},
		],
	};
}
