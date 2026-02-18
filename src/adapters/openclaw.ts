import {
	type ChallengeInfo,
	type GuardEvent,
	GuardPhase,
	type PipelineResult,
} from "../types.js";
import type { Adapter } from "./base.js";

/**
 * §10.1 OpenClaw Adapter
 *
 * Modes:
 * - openclaw_legacy_hook: stdin/stdout hook protocol (PreToolUse, PostToolUse)
 * - openclaw_plugin: plugin lifecycle binding
 */

interface OpenClawHookInput {
	hook_type: "PreToolUse" | "PostToolUse";
	hook_event_name?: "PreToolUse" | "PostToolUse";
	tool_name: string;
	tool?: string;
	tool_input: Record<string, unknown>;
	tool_arguments?: Record<string, unknown>;
	tool_output?: unknown;
	tool_response?: unknown;
	tool_result?: unknown;
	is_error?: boolean;
	error?: unknown;
	session_id?: string;
	session?: string;
	sessionId?: string;
	agent_name?: string;
	agent?: string;
	agentId?: string;
	agent_id?: string;
	channel?: string;
	provider?: string;
	mode?: string;
	profile?: string;
	taskType?: string;
	task_type?: string;
	tags?: unknown;
	labels?: unknown;
	// Legacy hook fields
	[key: string]: unknown;
}

interface OpenClawHookResponse {
	decision: "allow" | "deny" | "challenge";
	reason?: string;
	updatedInput?: Record<string, unknown>;
	challenge?: ChallengeInfo;
}

export class OpenClawAdapter implements Adapter {
	name = "openclaw";

	toGuardEvent(input: unknown): GuardEvent {
		const hook =
			input && typeof input === "object"
				? (input as Partial<OpenClawHookInput>)
				: {};
		const hookType = this.resolveHookType(hook);
		const toolInput =
			hook.tool_input && typeof hook.tool_input === "object"
				? hook.tool_input
				: hook.tool_arguments && typeof hook.tool_arguments === "object"
					? hook.tool_arguments
					: {};

		const phase =
			hookType === "PreToolUse" ? GuardPhase.PRE_TOOL : GuardPhase.POST_TOOL;
		const sessionId =
			this.pickString(hook, ["session_id", "session", "sessionId"]) ?? "unknown";
		const agentName = this.pickString(hook, [
			"agent_name",
			"agent",
			"agentId",
			"agent_id",
		]);
		const metadata = this.buildMetadata(hook);

		return {
			phase,
			framework: "openclaw",
			sessionId,
			agentName,
			toolCall: {
				name: hook.tool_name ?? hook.tool ?? "unknown",
				arguments: toolInput,
				raw: hook,
			},
			toolResult: this.extractToolResult(hookType, hook),
			metadata,
		};
	}

	toResponse(
		result: PipelineResult,
		_originalInput: unknown,
	): OpenClawHookResponse {
		if (result.finalAction === "deny") {
			return {
				decision: "deny",
				reason: result.reason,
			};
		}

		if (result.finalAction === "challenge") {
			return {
				decision: "challenge",
				reason: result.reason,
				challenge: this.extractChallenge(result),
			};
		}

		const response: OpenClawHookResponse = {
			decision: "allow",
		};

		if (result.transformed.toolArguments) {
			response.updatedInput = result.transformed.toolArguments;
		}

		return response;
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

	private extractToolResult(
		hookType: OpenClawHookInput["hook_type"],
		hook: Partial<OpenClawHookInput>,
	): GuardEvent["toolResult"] {
		if (hookType !== "PostToolUse") {
			return undefined;
		}

		const source =
			hook.tool_result ??
			hook.tool_response ??
			hook.tool_output ??
			(hook as Record<string, unknown>).result ??
			(hook as Record<string, unknown>).output;
		if (source == null) {
			return undefined;
		}

		const text = this.toText(source);
		const nestedError =
			source &&
			typeof source === "object" &&
			"error" in (source as Record<string, unknown>)
				? (source as Record<string, unknown>).error
				: undefined;
		const nestedIsError =
			source &&
			typeof source === "object" &&
			"isError" in (source as Record<string, unknown>)
				? Boolean((source as Record<string, unknown>).isError)
				: false;

		return {
			text,
			isError:
				hook.is_error === true ||
				hook.error != null ||
				nestedError != null ||
				nestedIsError,
			raw: source,
		};
	}

	private resolveHookType(hook: Partial<OpenClawHookInput>): OpenClawHookInput["hook_type"] {
		const candidate = hook.hook_type ?? hook.hook_event_name;
		if (candidate === "PreToolUse" || candidate === "PostToolUse") {
			return candidate;
		}
		return "PreToolUse";
	}

	private toText(value: unknown): string {
		if (typeof value === "string") {
			return value;
		}
		if (typeof value === "number" || typeof value === "boolean") {
			return String(value);
		}
		try {
			return JSON.stringify(value);
		} catch {
			return String(value);
		}
	}

	private buildMetadata(hook: Partial<OpenClawHookInput>): Record<string, unknown> {
		const metadata: Record<string, unknown> = {};
		const channel = this.pickString(hook, ["channel", "provider"]);
		if (channel) {
			metadata.channel = channel;
		}
		const modeHint = this.pickString(hook, ["mode", "profile"]);
		if (modeHint) {
			metadata.modeHint = modeHint;
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
