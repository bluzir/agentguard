import {
	type ChallengeInfo,
	type GuardEvent,
	GuardPhase,
	type PipelineResult,
} from "../types.js";
import type { Adapter } from "./base.js";

/**
 * §10.2 Nanobot Adapter
 *
 * Integration: MCP message hooks on tools/call.
 * - request direction -> PRE_TOOL
 * - response direction -> POST_TOOL
 *
 * Uses Nanobot/MCP SessionMessageHook contract (accept, message, reason).
 */

interface NanobotHookInput {
	direction: "request" | "response";
	method: string;
	session_id?: string;
	agentName?: string;
	agent_name?: string;
	agent?: string;
	channel?: string;
	provider?: string;
	profile?: string;
	mode?: string;
	taskType?: string;
	task_type?: string;
	tags?: unknown;
	labels?: unknown;
	params?: {
		name?: string;
		arguments?: Record<string, unknown>;
		agent?: string;
		agentName?: string;
		channel?: string;
		provider?: string;
		[key: string]: unknown;
	};
	result?: {
		content?: Array<{ type: string; text?: string }>;
		isError?: boolean;
		[key: string]: unknown;
	};
	sessionId?: string;
	[key: string]: unknown;
}

interface NanobotHookResponse {
	accept: boolean;
	message?: string;
	reason?: string;
	challenge?: ChallengeInfo;
}

export class NanobotAdapter implements Adapter {
	name = "nanobot";

	toGuardEvent(input: unknown): GuardEvent {
		const hook =
			input && typeof input === "object"
				? (input as Partial<NanobotHookInput>)
				: {};

		const phase =
			hook.direction === "request" ? GuardPhase.PRE_TOOL : GuardPhase.POST_TOOL;

		const event: GuardEvent = {
			phase,
			framework: "nanobot",
			sessionId:
				this.pickString(hook, ["sessionId", "session_id"]) ?? "unknown",
			agentName:
				this.pickString(hook, ["agentName", "agent_name", "agent"]) ??
				this.pickString(
					(hook.params ?? {}) as Record<string, unknown>,
					["agentName", "agent"],
				),
			metadata: this.buildMetadata(hook),
		};

		if (hook.params && typeof hook.params === "object") {
			event.toolCall = {
				name: hook.params.name ?? "unknown",
				arguments: hook.params.arguments ?? {},
				raw: hook.params,
			};
		}

		if (hook.result && typeof hook.result === "object") {
			const textParts = hook.result.content
				?.filter((c) => c.type === "text" && c.text)
				.map((c) => c.text)
				.join("\n");

			event.toolResult = {
				text: textParts ?? "",
				isError: hook.result.isError ?? false,
				raw: hook.result,
			};
		}

		return event;
	}

	toResponse(
		result: PipelineResult,
		_originalInput: unknown,
	): NanobotHookResponse {
		if (result.finalAction === "deny") {
			return {
				accept: false,
				reason: result.reason,
			};
		}

		if (result.finalAction === "challenge") {
			const challenge = this.extractChallenge(result);
			return {
				accept: false,
				reason: result.reason,
				message: challenge?.prompt,
				challenge,
			};
		}

		return {
			accept: true,
		};
	}

	private extractChallenge(result: PipelineResult): ChallengeInfo | undefined {
		for (let i = result.decisions.length - 1; i >= 0; i--) {
			const decision = result.decisions[i];
			if (decision.action === "challenge" && decision.challenge) {
				return decision.challenge;
			}
		}
		return undefined;
	}

	private buildMetadata(hook: Partial<NanobotHookInput>): Record<string, unknown> {
		const metadata: Record<string, unknown> = {};
		if (typeof hook.direction === "string") {
			metadata.direction = hook.direction;
		}
		if (typeof hook.method === "string" && hook.method.length > 0) {
			metadata.method = hook.method;
		}

		const modeHint = this.pickString(hook, ["mode", "profile"]);
		if (modeHint) {
			metadata.modeHint = modeHint;
		}

		const channel =
			this.pickString(hook, ["channel", "provider"]) ??
			this.pickString((hook.params ?? {}) as Record<string, unknown>, [
				"channel",
				"provider",
			]);
		if (channel) {
			metadata.channel = channel;
		}

		const taskType = this.pickString(hook, ["taskType", "task_type"]);
		if (taskType) {
			metadata.taskType = taskType;
		}

		const routeTags = this.pickStringArray(hook.tags ?? hook.labels);
		if (routeTags.length > 0) {
			metadata.routeTags = routeTags;
		}

		return metadata;
	}

	private pickString(
		record: Record<string, unknown>,
		keys: string[],
	): string | undefined {
		for (const key of keys) {
			const value = record[key];
			if (typeof value === "string" && value.trim().length > 0) {
				return value;
			}
			if (typeof value === "number" && Number.isFinite(value)) {
				return String(value);
			}
		}
		return undefined;
	}

	private pickStringArray(value: unknown): string[] {
		if (!Array.isArray(value)) return [];
		return value
			.map((item) => {
				if (typeof item === "string") return item.trim();
				if (typeof item === "number" && Number.isFinite(item)) {
					return String(item);
				}
				return "";
			})
			.filter((item) => item.length > 0);
	}
}
