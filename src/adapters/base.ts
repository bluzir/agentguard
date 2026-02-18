import type { GuardEvent, PipelineResult } from "../types.js";

/**
 * Base adapter interface — bridges orchestrator-specific events
 * to the canonical GuardEvent and back.
 */
export interface Adapter {
  name: string;

  /**
   * Transform orchestrator-specific input into a canonical GuardEvent.
   */
  toGuardEvent(input: unknown): GuardEvent;

  /**
   * Transform a PipelineResult back into orchestrator-specific response.
   */
  toResponse(result: PipelineResult, originalInput: unknown): unknown;
}
