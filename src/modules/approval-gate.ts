import {
  type Decision,
  type Framework,
  DecisionAction,
  type GuardEvent,
  GuardPhase,
  type ApprovalChannel,
} from "../types.js";
import {
  resolveApprovalChannel,
  type ApprovalChannelSelector,
} from "../approval/channel-bridge.js";
import { BaseModule } from "./base.js";

interface ApprovalRule {
  tool: string;
  channel: ApprovalChannelSelector;
  prompt?: string;
  timeoutSec?: number;
}

interface ApprovalGateConfig {
  rules: ApprovalRule[];
  defaultTimeoutSec?: number;
  autoRouting?: {
    defaultChannel?: ApprovalChannel;
    frameworkDefaults?: Partial<Record<Framework, ApprovalChannel>>;
    metadataKeys?: string[];
  };
}

/**
 * §9.8 approval_gate — require explicit human approval for high-risk actions.
 * Phase: PRE_TOOL
 *
 * Returns CHALLENGE with prompt and timeout.
 */
export class ApprovalGateModule extends BaseModule {
  name = "approval_gate";
  phases = new Set([GuardPhase.PRE_TOOL]);

  private rules: ApprovalRule[] = [];
  private defaultTimeoutSec = 300;
  private autoRouting: ApprovalGateConfig["autoRouting"] = undefined;

  override configure(config: Record<string, unknown>): void {
    super.configure(config);
    const c = config as unknown as Partial<ApprovalGateConfig>;
    this.rules = c.rules ?? [];
    this.defaultTimeoutSec = c.defaultTimeoutSec ?? 300;
    this.autoRouting = c.autoRouting;
  }

  async evaluate(event: GuardEvent): Promise<Decision> {
    const toolName = event.toolCall?.name;
    if (!toolName) return this.allow("no tool call");

    const rule = this.rules.find(
      (r) => r.tool === toolName || r.tool === "*",
    );
    if (!rule) return this.allow("no approval rule matched");
    const resolvedChannel = resolveApprovalChannel({
      requested: rule.channel ?? "auto",
      event,
      autoRouting: this.autoRouting,
    });

    return {
      action: DecisionAction.CHALLENGE,
      module: this.name,
      reason: `approval required for tool "${toolName}" (${resolvedChannel.reason})`,
      severity: "high",
      challenge: {
        channel: resolvedChannel.channel,
        prompt:
          rule.prompt ?? `Approve execution of "${toolName}"?`,
        timeoutSec: rule.timeoutSec ?? this.defaultTimeoutSec,
      },
    };
  }
}
