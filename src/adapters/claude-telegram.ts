import {
	type ChallengeInfo,
	type GuardEvent,
	GuardPhase,
	type PipelineResult,
} from "../types.js";
import type { Adapter } from "./base.js";

/**
 * §10.3 claude-telegram Adapter (bluzir)
 *
 * Maps module hooks to guard phases:
 * - beforeClaude(ctx, message) -> PRE_REQUEST
 * - afterClaude(ctx, result) -> PRE_RESPONSE
 */

interface ClaudeTelegramInput {
	hook: "beforeClaude" | "afterClaude";
	ctx: {
		chatId?: string | number;
		userId?: string | number;
		agentName?: string;
		agent_name?: string;
		agent?: string;
		channel?: string;
		provider?: string;
		mode?: string;
		profile?: string;
		taskType?: string;
		task_type?: string;
		tags?: unknown;
		labels?: unknown;
		[key: string]: unknown;
	};
	message?: string;
	result?: string;
}

interface ClaudeTelegramResponse {
	allow: boolean;
	message?: string;
	reason?: string;
	challenge?: ChallengeInfo;
}

export class ClaudeTelegramAdapter implements Adapter {
	name = "claude-telegram";

	toGuardEvent(input: unknown): GuardEvent {
		const hook =
			input && typeof input === "object"
				? (input as Partial<ClaudeTelegramInput>)
				: {};
		const ctx = hook.ctx ?? {};
		const hookName =
			hook.hook === "beforeClaude" || hook.hook === "afterClaude"
				? hook.hook
				: "beforeClaude";

		const phase =
			hookName === "beforeClaude"
				? GuardPhase.PRE_REQUEST
				: GuardPhase.PRE_RESPONSE;

		const event: GuardEvent = {
			phase,
			framework: "claude-telegram",
			sessionId: String(ctx.chatId ?? "unknown"),
			userId: ctx.userId != null ? String(ctx.userId) : undefined,
			agentName: this.pickString(ctx, ["agentName", "agent_name", "agent"]),
			metadata: this.buildMetadata(ctx),
		};

		if (phase === GuardPhase.PRE_REQUEST) {
			event.requestText =
				typeof hook.message === "string" ? hook.message : undefined;
		}

		if (phase === GuardPhase.PRE_RESPONSE) {
			event.responseText =
				typeof hook.result === "string" ? hook.result : undefined;
		}

		return event;
	}

	toResponse(
		result: PipelineResult,
		_originalInput: unknown,
	): ClaudeTelegramResponse {
		if (result.finalAction === "deny") {
			return {
				allow: false,
				reason: result.reason,
			};
		}

		if (result.finalAction === "challenge") {
			const challenge = this.extractChallenge(result);
			return {
				allow: false,
				reason: result.reason,
				message: challenge?.prompt,
				challenge,
			};
		}

		const response: ClaudeTelegramResponse = { allow: true };

		if (result.transformed.responseText) {
			response.message = result.transformed.responseText;
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

	private buildMetadata(ctx: Record<string, unknown>): Record<string, unknown> {
		const metadata: Record<string, unknown> = {};
		const channel = this.pickString(ctx, ["channel", "provider"]) ?? "telegram";
		metadata.channel = channel;
		const modeHint = this.pickString(ctx, ["mode", "profile"]);
		if (modeHint) {
			metadata.modeHint = modeHint;
		}

		const taskType = this.pickString(ctx, ["taskType", "task_type"]);
		if (taskType) {
			metadata.taskType = taskType;
		}

		const routeTags = this.pickStringArray(ctx.tags ?? ctx.labels);
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
