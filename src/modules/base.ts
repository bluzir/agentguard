import {
  type Decision,
  DecisionAction,
  type GuardEvent,
  GuardPhase,
  type ModuleMode,
  type SecurityModule,
} from "../types.js";

/**
 * Convenience base class for security modules.
 * Subclasses must implement `evaluate()`.
 */
export abstract class BaseModule implements SecurityModule {
  abstract name: string;
  abstract phases: Set<GuardPhase>;
  mode: ModuleMode = "enforce";

  protected config: Record<string, unknown> = {};

  configure(config: Record<string, unknown>): void {
    this.config = config;
  }

  abstract evaluate(event: GuardEvent): Promise<Decision>;

  protected allow(reason = "allowed"): Decision {
    return {
      action: DecisionAction.ALLOW,
      module: this.name,
      reason,
      severity: "info",
    };
  }

  protected deny(reason: string, severity: Decision["severity"] = "high"): Decision {
    return {
      action: DecisionAction.DENY,
      module: this.name,
      reason,
      severity,
    };
  }

  protected alert(reason: string, severity: Decision["severity"] = "medium"): Decision {
    return {
      action: DecisionAction.ALERT,
      module: this.name,
      reason,
      severity,
    };
  }

  protected modify(
    reason: string,
    patch: Decision["patch"],
    severity: Decision["severity"] = "medium",
  ): Decision {
    return {
      action: DecisionAction.MODIFY,
      module: this.name,
      reason,
      severity,
      patch,
    };
  }
}
