import { describe, expect, it } from "vitest";
import { resolveApprovalChannel } from "../src/approval/channel-bridge.js";
import { GuardPhase, type GuardEvent } from "../src/types.js";

function makeEvent(
	framework: GuardEvent["framework"],
	metadata: Record<string, unknown> = {},
): GuardEvent {
	return {
		phase: GuardPhase.PRE_TOOL,
		framework,
		sessionId: "session-1",
		toolCall: { name: "Bash", arguments: { command: "echo hi" } },
		metadata,
	};
}

describe("resolveApprovalChannel", () => {
	it("keeps explicit channel", () => {
		const resolved = resolveApprovalChannel({
			requested: "telegram",
			event: makeEvent("openclaw"),
		});
		expect(resolved.channel).toBe("telegram");
		expect(resolved.source).toBe("explicit");
	});

	it("uses metadata channel in auto mode", () => {
		const resolved = resolveApprovalChannel({
			requested: "auto",
			event: makeEvent("openclaw", { channel: "discord" }),
		});
		expect(resolved.channel).toBe("discord");
		expect(resolved.source).toBe("event_metadata");
	});

	it("uses framework default in auto mode", () => {
		const resolved = resolveApprovalChannel({
			requested: "auto",
			event: makeEvent("claude-telegram"),
		});
		expect(resolved.channel).toBe("telegram");
		expect(resolved.source).toBe("framework_default");
	});

	it("uses framework default when metadata is absent", () => {
		const resolved = resolveApprovalChannel({
			requested: "auto",
			event: makeEvent("generic"),
			autoRouting: {
				frameworkDefaults: {},
				defaultChannel: "orchestrator",
			},
		});
		expect(resolved.channel).toBe("http");
		expect(resolved.source).toBe("framework_default");
	});
});
