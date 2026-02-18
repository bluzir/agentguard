import { createAdapter, type Adapter } from "./adapters/index.js";
import { TelegramApprovalResolver } from "./approval/telegram-resolver.js";
import { loadConfig } from "./config/index.js";
import { createModules } from "./modules/index.js";
import { AuditModule } from "./modules/audit.js";
import { runPipeline } from "./pipeline.js";
import { DecisionAction } from "./types.js";
import type {
  AgentGuardConfig,
  Decision,
  Framework,
  GuardEvent,
  PipelineResult,
  SecurityModule,
} from "./types.js";

export interface RuntimeOptions {
  configPath?: string;
  framework?: Framework;
}

/**
 * AgentGuard runtime — the main entry point for evaluating events.
 *
 * Topology (§5.1):
 *   Orchestrator Event -> Adapter -> Canonical Event -> Pipeline -> Decision -> Adapter Response
 */
export class AgentGuardRuntime {
  private config: AgentGuardConfig;
  private modules: SecurityModule[];
  private adapter: Adapter;
  private auditModule: AuditModule | undefined;
  private telegramResolver: TelegramApprovalResolver | undefined;

  constructor(options: RuntimeOptions = {}) {
    this.config = loadConfig(options.configPath);

    this.modules = createModules(
      this.config.modules,
      this.config.moduleConfig,
    );

    // Find audit module for pipeline result logging
    this.auditModule = this.modules.find(
      (m): m is AuditModule => m.name === "audit",
    );

    const framework = options.framework ?? this.detectFramework();
    this.adapter = createAdapter(framework);

    const telegram = this.config.approval.channels.telegram;
    if (telegram?.enabled) {
      this.telegramResolver = new TelegramApprovalResolver(telegram);
    }
  }

  /**
   * Evaluate a raw orchestrator event through the full pipeline.
   * This is the main integration point for adapters.
   */
  async evaluate(rawInput: unknown): Promise<unknown> {
    const event = this.adapter.toGuardEvent(rawInput);
    const result = await this.evaluateEvent(event);
    const resolved = await this.resolveApprovalChallenge(event, result);
    return this.adapter.toResponse(resolved, rawInput);
  }

  /**
   * Evaluate a canonical GuardEvent directly.
   * Useful for generic/programmatic usage.
   */
  async evaluateEvent(event: GuardEvent): Promise<PipelineResult> {
    const result = await runPipeline(event, this.modules, {
      defaultAction: this.config.global.defaultAction as DecisionAction,
    });

    // Log full decision chain to audit
    this.auditModule?.logPipelineResult(event, result.decisions);

    return result;
  }

  getConfig(): AgentGuardConfig {
    return this.config;
  }

  getModules(): SecurityModule[] {
    return this.modules;
  }

  private async resolveApprovalChallenge(
    event: GuardEvent,
    result: PipelineResult,
  ): Promise<PipelineResult> {
    if (!this.config.approval.enabled) return result;
    if (result.finalAction !== DecisionAction.CHALLENGE) return result;

    const challenge = this.extractChallenge(result);
    if (!challenge) return result;

    if (challenge.channel !== "telegram") {
      return result;
    }

    if (this.config.approval.mode !== "sync_wait") {
      return this.withFinalDecision(
        result,
        DecisionAction.DENY,
        'approval.mode="async_token" is not implemented yet',
        "high",
      );
    }

    if (!this.telegramResolver) {
      return this.handleConnectorError(
        result,
        "telegram resolver is not configured",
      );
    }

    const resolution = await this.telegramResolver.resolve({
      approvalId: this.createApprovalId(),
      prompt: challenge.prompt,
      timeoutSec: challenge.timeoutSec,
      event,
    });

    switch (resolution.status) {
      case "approved":
        return this.withFinalDecision(
          result,
          DecisionAction.ALLOW,
          `telegram approval granted: ${resolution.reason}`,
          "info",
        );
      case "denied":
        return this.withFinalDecision(
          result,
          DecisionAction.DENY,
          `telegram approval denied: ${resolution.reason}`,
          "high",
        );
      case "timeout":
        if (this.config.approval.onTimeout === "deny") {
          return this.withFinalDecision(
            result,
            DecisionAction.DENY,
            `telegram approval timeout: ${resolution.reason}`,
            "high",
          );
        }
        return this.withAlert(result, resolution.reason);
      case "error":
        return this.handleConnectorError(result, resolution.reason);
    }
  }

  private handleConnectorError(
    result: PipelineResult,
    reason: string,
  ): PipelineResult {
    if (this.config.approval.onConnectorError === "deny") {
      return this.withFinalDecision(
        result,
        DecisionAction.DENY,
        `approval connector error: ${reason}`,
        "high",
      );
    }
    return this.withAlert(result, `approval connector error: ${reason}`);
  }

  private withFinalDecision(
    result: PipelineResult,
    finalAction: DecisionAction,
    reason: string,
    severity: Decision["severity"],
  ): PipelineResult {
    return {
      ...result,
      finalAction,
      reason,
      decisions: [
        ...result.decisions,
        {
          action: finalAction,
          module: "approval_resolver",
          reason,
          severity,
        },
      ],
    };
  }

  private withAlert(result: PipelineResult, alert: string): PipelineResult {
    return {
      ...result,
      alerts: [...result.alerts, `[approval_resolver] ${alert}`],
      decisions: [
        ...result.decisions,
        {
          action: DecisionAction.ALERT,
          module: "approval_resolver",
          reason: alert,
          severity: "medium",
        },
      ],
    };
  }

  private extractChallenge(
    result: PipelineResult,
  ): NonNullable<Decision["challenge"]> | undefined {
    for (let i = result.decisions.length - 1; i >= 0; i--) {
      const decision = result.decisions[i];
      if (decision.action === "challenge" && decision.challenge) {
        return decision.challenge;
      }
    }
    return undefined;
  }

  private createApprovalId(): string {
    const rand = Math.random().toString(36).slice(2, 8);
    return `${Date.now().toString(36)}${rand}`;
  }

  private detectFramework(): Framework {
    const adapters = this.config.adapters;
    for (const [name, config] of Object.entries(adapters)) {
      if ((config as Record<string, unknown>).enabled) {
        if (name === "claudeTelegram") {
          return "claude-telegram";
        }
        if (
          name === "openclaw" ||
          name === "nanobot" ||
          name === "claude-telegram" ||
          name === "generic"
        ) {
          return name;
        }
      }
    }
    return "generic";
  }
}
