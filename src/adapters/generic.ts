import { type GuardEvent, GuardPhase, type PipelineResult } from "../types.js";
import type { Adapter } from "./base.js";

/**
 * §10.4 Generic Adapter
 *
 * Modes: generic_http, generic_mcp, generic_stdio
 * Accepts canonical GuardEvent directly (no transformation needed).
 */
export class GenericAdapter implements Adapter {
	name = "generic";

	toGuardEvent(input: unknown): GuardEvent {
		const event =
			input && typeof input === "object" ? (input as Partial<GuardEvent>) : {};

		// Generic adapter accepts canonical events but also tolerates malformed input.
		return {
			phase: event.phase ?? GuardPhase.PRE_REQUEST,
			framework: "generic",
			sessionId: event.sessionId ?? "unknown",
			requestText: event.requestText,
			toolCall: event.toolCall,
			toolResult: event.toolResult,
			responseText: event.responseText,
			artifact: event.artifact,
			agentName: event.agentName,
			userId: event.userId,
			metadata: event.metadata ?? {},
		};
	}

	toResponse(result: PipelineResult, _originalInput: unknown): PipelineResult {
		return result;
	}
}
