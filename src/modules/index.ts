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
import { SkillScannerModule } from "./skill-scanner.js";
import { ToolPolicyModule } from "./tool-policy.js";
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
export { ApprovalGateModule } from "./approval-gate.js";
export { AuditModule } from "./audit.js";
export { SkillScannerModule } from "./skill-scanner.js";
export { VerdictProviderModule } from "./verdict-provider.js";

type ModuleFactory = () => SecurityModule;

const BUILTIN_MODULES: Record<string, ModuleFactory> = {
  kill_switch: () => new KillSwitchModule(),
  tool_policy: () => new ToolPolicyModule(),
  fs_guard: () => new FsGuardModule(),
  command_guard: () => new CommandGuardModule(),
  exec_sandbox: () => new ExecSandboxModule(),
  egress_guard: () => new EgressGuardModule(),
  output_dlp: () => new OutputDlpModule(),
  rate_budget: () => new RateBudgetModule(),
  approval_gate: () => new ApprovalGateModule(),
  audit: () => new AuditModule(),
  skill_scanner: () => new SkillScannerModule(),
  verdict_provider: () => new VerdictProviderModule(),
};

/**
 * Create and configure modules from config.
 */
export function createModules(
  moduleNames: string[],
  moduleConfig: Record<string, Record<string, unknown>>,
): SecurityModule[] {
  const modules: SecurityModule[] = [];

  for (const name of moduleNames) {
    const factory = BUILTIN_MODULES[name];
    if (!factory) {
      throw new Error(`unknown module: "${name}"`);
    }

    const mod = factory();
    const config = moduleConfig[name];
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
