import type { ModuleMode, SecurityModule } from "../types.js";
import { ApprovalGateModule } from "./approval-gate.js";
import { AuditModule } from "./audit.js";
import { CommandGuardModule } from "./command-guard.js";
import { EgressGuardModule } from "./egress-guard.js";
import { ExecSandboxModule } from "./exec-sandbox.js";
import { FsGuardModule } from "./fs-guard.js";
import { KillSwitchModule } from "./kill-switch.js";
import { OutputDlpModule } from "./output-dlp.js";
import { RateBudgetModule } from "./rate-budget.js";
import { RepetitionGuardModule } from "./repetition-guard.js";
import { SelfDefenseModule } from "./self-defense.js";
import { SkillScannerModule } from "./skill-scanner.js";
import { ToolPolicyModule } from "./tool-policy.js";
import { TripwireGuardModule } from "./tripwire-guard.js";
import { VerdictProviderModule } from "./verdict-provider.js";

export { BaseModule } from "./base.js";
export { ToolPolicyModule } from "./tool-policy.js";
export { FsGuardModule } from "./fs-guard.js";
export { CommandGuardModule } from "./command-guard.js";
export { ExecSandboxModule } from "./exec-sandbox.js";
export { EgressGuardModule } from "./egress-guard.js";
export { KillSwitchModule } from "./kill-switch.js";
export { OutputDlpModule } from "./output-dlp.js";
export { RateBudgetModule } from "./rate-budget.js";
export { RepetitionGuardModule } from "./repetition-guard.js";
export { ApprovalGateModule } from "./approval-gate.js";
export { AuditModule } from "./audit.js";
export { SelfDefenseModule } from "./self-defense.js";
export { SkillScannerModule } from "./skill-scanner.js";
export { VerdictProviderModule } from "./verdict-provider.js";
export { TripwireGuardModule } from "./tripwire-guard.js";

type ModuleFactory = () => SecurityModule;

const BUILTIN_MODULES: Record<string, ModuleFactory> = {
  kill_switch: () => new KillSwitchModule(),
  self_defense: () => new SelfDefenseModule(),
  tool_policy: () => new ToolPolicyModule(),
  fs_guard: () => new FsGuardModule(),
  command_guard: () => new CommandGuardModule(),
  exec_sandbox: () => new ExecSandboxModule(),
  egress_guard: () => new EgressGuardModule(),
  output_dlp: () => new OutputDlpModule(),
  rate_budget: () => new RateBudgetModule(),
  repetition_guard: () => new RepetitionGuardModule(),
  tripwire_guard: () => new TripwireGuardModule(),
  approval_gate: () => new ApprovalGateModule(),
  audit: () => new AuditModule(),
  skill_scanner: () => new SkillScannerModule(),
  verdict_provider: () => new VerdictProviderModule(),
};

function isRecord(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function deriveToolEgressBindings(
  moduleConfig: Record<string, Record<string, unknown>>,
): Record<string, Record<string, unknown>> {
  const toolPolicy = moduleConfig.tool_policy;
  if (!isRecord(toolPolicy)) return {};

  const rawRules = toolPolicy.rules;
  if (!Array.isArray(rawRules)) return {};

  const bindings: Record<string, Record<string, unknown>> = {};
  for (const rawRule of rawRules) {
    if (!isRecord(rawRule)) continue;

    const tool = rawRule.tool;
    const egress = rawRule.egress;
    if (typeof tool !== "string" || !isRecord(egress)) {
      continue;
    }

    // tool_policy is first-match-wins; keep first binding for deterministic behavior.
    if (!(tool in bindings)) {
      bindings[tool] = egress;
    }
  }

  return bindings;
}

/**
 * Create and configure modules from config.
 */
export function createModules(
  moduleNames: string[],
  moduleConfig: Record<string, Record<string, unknown>>,
): SecurityModule[] {
  const modules: SecurityModule[] = [];
  const derivedToolBindings = deriveToolEgressBindings(moduleConfig);

  for (const name of moduleNames) {
    const factory = BUILTIN_MODULES[name];
    if (!factory) {
      throw new Error(`unknown module: "${name}"`);
    }

    const mod = factory();
    let config = moduleConfig[name];
    if (name === "egress_guard" && Object.keys(derivedToolBindings).length > 0) {
      const currentConfig = isRecord(config) ? config : {};
      const existingToolBindings = isRecord(currentConfig.toolBindings)
        ? (currentConfig.toolBindings as Record<string, unknown>)
        : {};

      config = {
        ...currentConfig,
        toolBindings: {
          ...derivedToolBindings,
          ...existingToolBindings,
        },
      };
    }

    if (config) {
      const mode = config.mode;
      if (mode === "enforce" || mode === "observe") {
        mod.mode = mode as ModuleMode;
      }

      const { mode: _mode, ...configWithoutMode } = config;
      if (Object.keys(configWithoutMode).length > 0) {
        mod.configure(configWithoutMode);
      }
    }

    modules.push(mod);
  }

  return modules;
}
