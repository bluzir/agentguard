import fs from "node:fs";
import { type Decision, type GuardEvent, GuardPhase } from "../types.js";
import { BaseModule } from "./base.js";

interface KillSwitchConfig {
  enabled?: boolean;
  envVar?: string;
  filePath?: string;
  denyPhases?: GuardPhase[];
  reason?: string;
}

const ACTIVE_VALUES = new Set(["1", "true", "on", "yes", "enabled"]);

/**
 * kill_switch — deterministic emergency stop for agent actions.
 * Phases: PRE_LOAD, PRE_REQUEST, PRE_TOOL, POST_TOOL, PRE_RESPONSE
 */
export class KillSwitchModule extends BaseModule {
  name = "kill_switch";
  phases = new Set([
    GuardPhase.PRE_LOAD,
    GuardPhase.PRE_REQUEST,
    GuardPhase.PRE_TOOL,
    GuardPhase.POST_TOOL,
    GuardPhase.PRE_RESPONSE,
  ]);

  private enabled = true;
  private envVar = "RADIUS_KILL_SWITCH";
  private filePath = "";
  private denyPhases = new Set([GuardPhase.PRE_REQUEST, GuardPhase.PRE_TOOL]);
  private denyReason =
    "emergency kill switch active: human safety override";

  override configure(config: Record<string, unknown>): void {
    super.configure(config);
    const c = config as unknown as Partial<KillSwitchConfig>;
    this.enabled = c.enabled ?? true;
    this.envVar = c.envVar ?? "RADIUS_KILL_SWITCH";
    this.filePath = c.filePath ?? "";
    this.denyReason =
      c.reason ?? "emergency kill switch active: human safety override";
    this.denyPhases = new Set(
      c.denyPhases ?? [GuardPhase.PRE_REQUEST, GuardPhase.PRE_TOOL],
    );
  }

  async evaluate(event: GuardEvent): Promise<Decision> {
    if (!this.enabled) {
      return this.allow("kill switch disabled");
    }

    if (!this.isActive()) {
      return this.allow("kill switch inactive");
    }

    if (!this.denyPhases.has(event.phase)) {
      return this.alert(
        `kill switch active but phase ${event.phase} is observe-only`,
        "high",
      );
    }

    return this.deny(this.denyReason, "critical");
  }

  private isActive(): boolean {
    const envValue = process.env[this.envVar];
    if (typeof envValue === "string") {
      const normalized = envValue.trim().toLowerCase();
      if (ACTIVE_VALUES.has(normalized)) {
        return true;
      }
    }

    if (this.filePath) {
      try {
        return fs.existsSync(this.filePath);
      } catch {
        return false;
      }
    }

    return false;
  }
}
