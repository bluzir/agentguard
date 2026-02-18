import { describe, expect, it } from "vitest";
import { runPipeline } from "../src/pipeline.js";
import {
  DecisionAction,
  type GuardEvent,
  GuardPhase,
  type SecurityModule,
  type Decision,
} from "../src/types.js";

function makeEvent(overrides: Partial<GuardEvent> = {}): GuardEvent {
  return {
    phase: GuardPhase.PRE_TOOL,
    framework: "generic",
    sessionId: "test-session",
    metadata: {},
    ...overrides,
  };
}

function makeModule(
  name: string,
  decision: Decision,
  phases = new Set([GuardPhase.PRE_TOOL]),
): SecurityModule {
  return {
    name,
    phases,
    mode: "enforce",
    configure: () => {},
    evaluate: async () => decision,
  };
}

describe("pipeline", () => {
  it("returns default action when no modules match", async () => {
    const event = makeEvent({ phase: GuardPhase.PRE_REQUEST });
    const modules = [
      makeModule("test", { action: DecisionAction.ALLOW, module: "test", reason: "ok", severity: "info" }),
    ];

    const result = await runPipeline(event, modules, { defaultAction: DecisionAction.ALLOW });
    expect(result.finalAction).toBe(DecisionAction.ALLOW);
    expect(result.reason).toBe("no applicable modules");
  });

  it("returns ALLOW after module evaluation even when defaultAction is DENY", async () => {
    const event = makeEvent();
    const modules = [
      makeModule("allower", { action: DecisionAction.ALLOW, module: "allower", reason: "ok", severity: "info" }),
    ];

    const result = await runPipeline(event, modules, { defaultAction: DecisionAction.DENY });
    expect(result.finalAction).toBe(DecisionAction.ALLOW);
    expect(result.reason).toBe("allow after module evaluation");
  });

  it("short-circuits on DENY", async () => {
    const event = makeEvent();
    const modules = [
      makeModule("denier", { action: DecisionAction.DENY, module: "denier", reason: "blocked", severity: "high" }),
      makeModule("allower", { action: DecisionAction.ALLOW, module: "allower", reason: "ok", severity: "info" }),
    ];

    const result = await runPipeline(event, modules, { defaultAction: DecisionAction.ALLOW });
    expect(result.finalAction).toBe(DecisionAction.DENY);
    expect(result.decisions).toHaveLength(1);
  });

  it("short-circuits on CHALLENGE", async () => {
    const event = makeEvent();
    const result = await runPipeline(event, [
      makeModule("gate", {
        action: DecisionAction.CHALLENGE,
        module: "gate",
        reason: "need approval",
        severity: "high",
        challenge: { channel: "orchestrator", prompt: "approve?", timeoutSec: 60 },
      }),
    ], { defaultAction: DecisionAction.ALLOW });

    expect(result.finalAction).toBe(DecisionAction.CHALLENGE);
  });

  it("composes MODIFY patches in order", async () => {
    const event = makeEvent();
    const mod1: SecurityModule = {
      name: "mod1",
      phases: new Set([GuardPhase.PRE_TOOL]),
      mode: "enforce",
      configure: () => {},
      evaluate: async () => ({
        action: DecisionAction.MODIFY,
        module: "mod1",
        reason: "patch 1",
        severity: "info" as const,
        patch: { toolArguments: { key1: "val1", key2: "original" } },
      }),
    };
    const mod2: SecurityModule = {
      name: "mod2",
      phases: new Set([GuardPhase.PRE_TOOL]),
      mode: "enforce",
      configure: () => {},
      evaluate: async () => ({
        action: DecisionAction.MODIFY,
        module: "mod2",
        reason: "patch 2",
        severity: "info" as const,
        patch: { toolArguments: { key2: "overridden" }, responseText: "hello" },
      }),
    };

    const result = await runPipeline(event, [mod1, mod2], { defaultAction: DecisionAction.ALLOW });
    expect(result.finalAction).toBe(DecisionAction.ALLOW);
    expect(result.transformed.toolArguments).toEqual({ key1: "val1", key2: "overridden" });
    expect(result.transformed.responseText).toBe("hello");
  });

  it("deep-merges nested tool arguments for MODIFY patches", async () => {
    const event = makeEvent();
    const mod1: SecurityModule = {
      name: "mod1",
      phases: new Set([GuardPhase.PRE_TOOL]),
      mode: "enforce",
      configure: () => {},
      evaluate: async () => ({
        action: DecisionAction.MODIFY,
        module: "mod1",
        reason: "patch 1",
        severity: "info",
        patch: {
          toolArguments: {
            payload: { path: "/tmp", flags: { recursive: false } },
          },
        },
      }),
    };
    const mod2: SecurityModule = {
      name: "mod2",
      phases: new Set([GuardPhase.PRE_TOOL]),
      mode: "enforce",
      configure: () => {},
      evaluate: async () => ({
        action: DecisionAction.MODIFY,
        module: "mod2",
        reason: "patch 2",
        severity: "info",
        patch: {
          toolArguments: {
            payload: { flags: { recursive: true, force: true } },
          },
        },
      }),
    };

    const result = await runPipeline(event, [mod1, mod2], {
      defaultAction: DecisionAction.ALLOW,
    });
    expect(result.transformed.toolArguments).toEqual({
      payload: {
        path: "/tmp",
        flags: { recursive: true, force: true },
      },
    });
  });

  it("collects ALERT and continues", async () => {
    const event = makeEvent();
    const result = await runPipeline(event, [
      makeModule("alerter", { action: DecisionAction.ALERT, module: "alerter", reason: "heads up", severity: "medium" }),
      makeModule("allower", { action: DecisionAction.ALLOW, module: "allower", reason: "ok", severity: "info" }),
    ], { defaultAction: DecisionAction.ALLOW });

    expect(result.finalAction).toBe(DecisionAction.ALLOW);
    expect(result.alerts).toHaveLength(1);
    expect(result.alerts[0]).toContain("heads up");
  });

  it("enforce module error -> DENY (fail-closed)", async () => {
    const event = makeEvent();
    const thrower: SecurityModule = {
      name: "broken",
      phases: new Set([GuardPhase.PRE_TOOL]),
      mode: "enforce",
      configure: () => {},
      evaluate: async () => { throw new Error("boom"); },
    };

    const result = await runPipeline(event, [thrower], { defaultAction: DecisionAction.ALLOW });
    expect(result.finalAction).toBe(DecisionAction.DENY);
    expect(result.reason).toContain("boom");
  });

  it("observe module error -> ALERT + continue", async () => {
    const event = makeEvent();
    const thrower: SecurityModule = {
      name: "observer",
      phases: new Set([GuardPhase.PRE_TOOL]),
      mode: "observe",
      configure: () => {},
      evaluate: async () => { throw new Error("oops"); },
    };

    const result = await runPipeline(event, [thrower], { defaultAction: DecisionAction.DENY });
    expect(result.finalAction).toBe(DecisionAction.ALLOW);
    expect(result.alerts).toHaveLength(1);
    expect(result.alerts[0]).toContain("oops");
  });

  it("observe mode does not enforce DENY decisions", async () => {
    const event = makeEvent();
    const observer: SecurityModule = {
      name: "observer",
      phases: new Set([GuardPhase.PRE_TOOL]),
      mode: "observe",
      configure: () => {},
      evaluate: async () => ({
        action: DecisionAction.DENY,
        module: "observer",
        reason: "would block",
        severity: "high",
      }),
    };

    const result = await runPipeline(event, [observer], {
      defaultAction: DecisionAction.ALLOW,
    });
    expect(result.finalAction).toBe(DecisionAction.ALLOW);
    expect(result.alerts[0]).toContain("observe-mode would deny");
  });

  it("observe mode does not apply MODIFY patches", async () => {
    const event = makeEvent();
    const observer: SecurityModule = {
      name: "observer",
      phases: new Set([GuardPhase.PRE_TOOL]),
      mode: "observe",
      configure: () => {},
      evaluate: async () => ({
        action: DecisionAction.MODIFY,
        module: "observer",
        reason: "would redact",
        severity: "medium",
        patch: { responseText: "redacted" },
      }),
    };

    const result = await runPipeline(event, [observer], {
      defaultAction: DecisionAction.ALLOW,
    });
    expect(result.finalAction).toBe(DecisionAction.ALLOW);
    expect(result.transformed.responseText).toBeUndefined();
    expect(result.alerts[0]).toContain("observe-mode would modify");
  });
});
