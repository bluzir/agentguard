import { createAdapter, type Adapter } from "./adapters/index.js";
import {
  configureApprovalLeaseStore,
  grantApprovalLease,
} from "./approval/lease-store.js";
import { HttpApprovalResolver } from "./approval/http-resolver.js";
import { TelegramApprovalResolver } from "./approval/telegram-resolver.js";
import { loadConfig } from "./config/index.js";
import { createModules } from "./modules/index.js";
import { AuditModule } from "./modules/audit.js";
import { runPipeline } from "./pipeline.js";
import { DecisionAction } from "./types.js";
import type {
  RadiusConfig,
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
 * Radius runtime — the main entry point for evaluating events.
 *
 * Topology (§5.1):
 *   Orchestrator Event -> Adapter -> Canonical Event -> Pipeline -> Decision -> Adapter Response
 */
export class RadiusRuntime {
  private config: RadiusConfig;
  private modules: SecurityModule[];
  private adapter: Adapter;
  private auditModule: AuditModule | undefined;
  private telegramResolver: TelegramApprovalResolver | undefined;
  private httpResolver: HttpApprovalResolver | undefined;

  constructor(options: RuntimeOptions = {}) {
    this.config = loadConfig(options.configPath);
    configureApprovalLeaseStore({
      engine: this.config.approval.store.engine,
      path: this.config.approval.store.path,
      required:
        this.config.approval.store.required ??
        this.config.approval.store.engine === "sqlite",
    });

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
    const http = this.config.approval.channels.http;
    if (http?.enabled) {
      this.httpResolver = new HttpApprovalResolver(http);
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

  getConfig(): RadiusConfig {
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

    if (this.config.approval.mode !== "sync_wait") {
      return this.withFinalDecision(
        result,
        DecisionAction.DENY,
        'approval.mode="async_token" is not implemented yet',
        "high",
      );
    }

    if (challenge.channel === "telegram") {
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
      return this.applyConnectorResolution(
        "telegram",
        event,
        result,
        resolution,
      );
    }

    if (challenge.channel === "http") {
      if (!this.httpResolver) {
        return this.handleConnectorError(
          result,
          "http resolver is not configured",
        );
      }

      const resolution = await this.httpResolver.resolve({
        approvalId: this.createApprovalId(),
        prompt: challenge.prompt,
        timeoutSec: challenge.timeoutSec,
        event,
      });
      return this.applyConnectorResolution("http", event, result, resolution);
    }

    return result;
  }

  private applyConnectorResolution(
    connector: "telegram" | "http",
    event: GuardEvent,
    result: PipelineResult,
    resolution: {
      status:
        | "approved"
        | "approved_temporary"
        | "denied"
        | "timeout"
        | "error";
      reason: string;
      ttlSec?: number;
    },
  ): PipelineResult {
    switch (resolution.status) {
      case "approved":
        return this.withFinalDecision(
          result,
          DecisionAction.ALLOW,
          `${connector} approval granted: ${resolution.reason}`,
          "info",
        );
      case "approved_temporary": {
        const configuredTtl = this.config.approval.temporaryGrantTtlSec ?? 1800;
        const maxTtl = this.config.approval.maxTemporaryGrantTtlSec ?? 1800;
        const requestedTtl = resolution.ttlSec ?? configuredTtl;
        const effectiveTtl = Math.max(1, Math.min(requestedTtl, maxTtl));
        const lease = grantApprovalLease({
          sessionId: event.sessionId,
          agentName: event.agentName,
          tool: "*",
          ttlSec: effectiveTtl,
          reason: `${connector} temporary approval`,
        });
        return this.withFinalDecision(
          result,
          DecisionAction.ALLOW,
          `${connector} temporary approval granted (${effectiveTtl}s, lease ${lease.id})`,
          "info",
        );
      }
      case "denied":
        return this.withFinalDecision(
          result,
          DecisionAction.DENY,
          `${connector} approval denied: ${resolution.reason}`,
          "high",
        );
      case "timeout":
        if (this.config.approval.onTimeout === "deny") {
          return this.withFinalDecision(
            result,
            DecisionAction.DENY,
            `${connector} approval timeout: ${resolution.reason}`,
            "high",
          );
        }
        return this.withAlert(
          result,
          `${connector} approval timeout: ${resolution.reason}`,
        );
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

/** @deprecated Use RadiusRuntime */
export const AgentGuardRuntime = RadiusRuntime;
/** @deprecated Use RadiusRuntime */
export type AgentGuardRuntime = RadiusRuntime;
