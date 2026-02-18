import type {
  Decision,
  DecisionAction,
  DecisionPatch,
  GuardEvent,
  PipelineResult,
  SecurityModule,
} from "./types.js";

/**
 * Deeply merge tool arguments: later module overrides same key.
 */
function mergeToolArguments(
  base: Record<string, unknown> | undefined,
  patch: Record<string, unknown> | undefined,
): Record<string, unknown> | undefined {
  if (!patch) return base;
  if (!base) return patch;
  return deepMergeRecords(base, patch);
}

function deepMergeRecords(
  base: Record<string, unknown>,
  patch: Record<string, unknown>,
): Record<string, unknown> {
  const result: Record<string, unknown> = { ...base };

  for (const [key, patchValue] of Object.entries(patch)) {
    const baseValue = result[key];
    if (isRecord(baseValue) && isRecord(patchValue)) {
      result[key] = deepMergeRecords(baseValue, patchValue);
    } else {
      result[key] = patchValue;
    }
  }

  return result;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

/**
 * Compose a decision patch onto accumulated transforms.
 *
 * Rules from spec:
 * - requestText, toolResultText, responseText: last writer wins
 * - toolArguments: deep merge by key, later module overrides same key
 */
function composePatch(
  current: PipelineResult["transformed"],
  patch: DecisionPatch,
): PipelineResult["transformed"] {
  return {
    requestText: patch.requestText ?? current.requestText,
    toolArguments: mergeToolArguments(
      current.toolArguments,
      patch.toolArguments,
    ),
    toolResultText: patch.toolResultText ?? current.toolResultText,
    responseText: patch.responseText ?? current.responseText,
  };
}

export interface PipelineOptions {
  defaultAction: DecisionAction;
}

/**
 * Evaluate an event through an ordered list of security modules.
 *
 * Resolution rules (from spec §8):
 * 1. DENY short-circuits immediately.
 * 2. CHALLENGE short-circuits and returns pending decision.
 * 3. MODIFY patches are composed in-order.
 * 4. ALERT adds alert and continues.
 * 5. If modules were evaluated with no hard decision, runtime returns ALLOW.
 * 6. If no modules apply for phase, runtime applies defaultAction.
 *
 * Fail-safe (from spec §8):
 * - Enforce module throws -> DENY (fail-closed)
 * - Observe module throws -> ALERT + continue
 */
export async function runPipeline(
  event: GuardEvent,
  modules: SecurityModule[],
  options: PipelineOptions,
): Promise<PipelineResult> {
  const decisions: Decision[] = [];
  const alerts: string[] = [];
  let transformed: PipelineResult["transformed"] = {};

  const applicableModules = modules.filter((m) => m.phases.has(event.phase));

  for (const mod of applicableModules) {
    let decision: Decision;

    try {
      decision = await mod.evaluate(event);
    } catch (err) {
      const message =
        err instanceof Error ? err.message : "unknown module error";

      if (mod.mode === "enforce") {
        // Fail-closed: enforce module error -> DENY
        const denyDecision: Decision = {
          action: "deny" as DecisionAction,
          module: mod.name,
          reason: `module error (fail-closed): ${message}`,
          severity: "critical",
        };
        decisions.push(denyDecision);
        return {
          finalAction: "deny" as DecisionAction,
          reason: denyDecision.reason,
          transformed,
          alerts,
          decisions,
        };
      }

      // Observe module error -> ALERT + continue
      alerts.push(`[${mod.name}] observe error: ${message}`);
      continue;
    }

    decisions.push(decision);

    // Observe-mode modules never enforce hard outcomes or mutations.
    // They report what would have happened via alerts and continue.
    if (
      mod.mode === "observe" &&
      (decision.action === "deny" ||
        decision.action === "challenge" ||
        decision.action === "modify")
    ) {
      alerts.push(
        `[${decision.module}] observe-mode would ${decision.action}: ${decision.reason}`,
      );
      continue;
    }

    switch (decision.action) {
      case "deny":
        return {
          finalAction: "deny" as DecisionAction,
          reason: decision.reason,
          transformed,
          alerts,
          decisions,
        };

      case "challenge":
        return {
          finalAction: "challenge" as DecisionAction,
          reason: decision.reason,
          transformed,
          alerts,
          decisions,
        };

      case "modify":
        if (decision.patch) {
          transformed = composePatch(transformed, decision.patch);
        }
        break;

      case "alert":
        alerts.push(`[${decision.module}] ${decision.reason}`);
        break;

      case "allow":
        // No-op, continue to next module
        break;
    }
  }

  // No hard decision reached:
  // - if pipeline produced non-blocking outcomes (allow/alert/modify), allow request;
  // - if no modules applied at all, use configured default action.
  if (decisions.length > 0 || alerts.length > 0) {
    return {
      finalAction: "allow" as DecisionAction,
      reason: "allow after module evaluation",
      transformed,
      alerts,
      decisions,
    };
  }

  return {
    finalAction: options.defaultAction,
    reason: "no applicable modules",
    transformed,
    alerts,
    decisions,
  };
}
