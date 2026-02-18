import fs from "node:fs";
import {
  type Decision,
  DecisionAction,
  type GuardEvent,
  GuardPhase,
} from "../types.js";
import { BaseModule } from "./base.js";

interface AuditSinkConfig {
  sink: "file" | "stdout" | "webhook" | "otlp";
  path?: string;
  webhookUrl?: string;
  otlpEndpoint?: string;
  headers?: Record<string, string>;
  timeoutMs?: number;
  includeArguments?: boolean;
  includeResults?: boolean;
}

/**
 * §9.9 audit — always-on append-only event and decision log.
 * Phases: all
 *
 * Guarantees:
 * - Captures full decision chain and final action.
 * - Never blocks main decision path on sink failures.
 */
export class AuditModule extends BaseModule {
  name = "audit";
  phases = new Set([
    GuardPhase.PRE_LOAD,
    GuardPhase.PRE_REQUEST,
    GuardPhase.PRE_TOOL,
    GuardPhase.POST_TOOL,
    GuardPhase.PRE_RESPONSE,
  ]);

  private sink: AuditSinkConfig["sink"] = "file";
  private filePath?: string;
  private webhookUrl?: string;
  private otlpEndpoint?: string;
  private headers: Record<string, string> = {};
  private timeoutMs = 3000;
  private includeArguments = true;
  private includeResults = false;
  private fallbackBuffer: string[] = [];

  override configure(config: Record<string, unknown>): void {
    super.configure(config);
    const c = config as unknown as Partial<AuditSinkConfig>;
    this.sink = c.sink ?? "file";
    this.filePath = c.path;
    this.webhookUrl = c.webhookUrl;
    this.otlpEndpoint = c.otlpEndpoint;
    this.headers = c.headers ?? {};
    this.timeoutMs = c.timeoutMs ?? 3000;
    this.includeArguments = c.includeArguments ?? true;
    this.includeResults = c.includeResults ?? false;
  }

  async evaluate(event: GuardEvent): Promise<Decision> {
    // Audit always allows — it only logs
    const entry = this.buildEntry(event);
    this.writeEntry(entry);
    return this.allow("audit logged");
  }

  /**
   * Record a completed pipeline result (called by the runtime, not via evaluate).
   */
  logPipelineResult(event: GuardEvent, decisions: Decision[]): void {
    const entry = {
      ...this.buildEntry(event),
      decisions: decisions.map((d) => ({
        action: d.action,
        module: d.module,
        reason: d.reason,
        severity: d.severity,
      })),
    };
    this.writeEntry(entry);
  }

  private buildEntry(event: GuardEvent): Record<string, unknown> {
    const entry: Record<string, unknown> = {
      timestamp: new Date().toISOString(),
      phase: event.phase,
      framework: event.framework,
      sessionId: event.sessionId,
      userId: event.userId,
      agentName: event.agentName,
    };

    if (event.toolCall) {
      entry.toolName = event.toolCall.name;
      if (this.includeArguments) {
        entry.toolArguments = event.toolCall.arguments;
      }
    }

    if (event.artifact) {
      entry.artifact = {
        kind: event.artifact.kind,
        path: event.artifact.path,
        sourceUri: event.artifact.sourceUri,
        sha256: event.artifact.sha256,
        signatureVerified: event.artifact.signatureVerified,
        signer: event.artifact.signer,
        sbomUri: event.artifact.sbomUri,
        versionPinned: event.artifact.versionPinned,
      };
    }

    if (event.toolResult && this.includeResults) {
      entry.toolResult = {
        isError: event.toolResult.isError,
        textLength: event.toolResult.text.length,
      };
    }

    return entry;
  }

  private writeEntry(entry: Record<string, unknown>): void {
    const line = JSON.stringify(entry);
    let flushFallback = false;

    try {
      switch (this.sink) {
        case "stdout":
          process.stdout.write(`${line}\n`);
          flushFallback = true;
          break;

        case "file":
          if (this.filePath) {
            fs.appendFileSync(this.filePath, `${line}\n`);
          }
          flushFallback = true;
          break;

        case "webhook":
          this.dispatchWebhook(line, entry);
          break;

        case "otlp":
          this.dispatchOtlp(line, entry);
          break;
      }

      // Flush fallback buffer only after synchronous sink success.
      if (flushFallback && this.fallbackBuffer.length > 0) {
        this.flushFallbackBuffer();
      }
    } catch (err) {
      // Never block — stderr + in-memory fallback
      const message = err instanceof Error ? err.message : "unknown";
      process.stderr.write(
        `[radius:audit] sink write failed: ${message}\n`,
      );
      this.fallbackBuffer.push(line);
    }
  }

  private dispatchWebhook(
    line: string,
    entry: Record<string, unknown>,
  ): void {
    const url = this.webhookUrl ?? this.filePath;
    if (!url) {
      throw new Error("webhook sink requires webhookUrl or path");
    }

    this.dispatchJson(url, entry, line, "webhook");
  }

  private dispatchOtlp(
    line: string,
    entry: Record<string, unknown>,
  ): void {
    const endpoint = this.otlpEndpoint ?? this.filePath;
    if (!endpoint) {
      throw new Error("otlp sink requires otlpEndpoint or path");
    }

    const payload = this.toOtlpJson(entry);
    this.dispatchJson(endpoint, payload, line, "otlp");
  }

  private dispatchJson(
    url: string,
    body: Record<string, unknown>,
    fallbackLine: string,
    sink: "webhook" | "otlp",
  ): void {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), this.timeoutMs);

    void fetch(url, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        ...this.headers,
      },
      body: JSON.stringify(body),
      signal: controller.signal,
    })
      .then((response) => {
        if (!response.ok) {
          throw new Error(`HTTP ${response.status}`);
        }
      })
      .catch((err) => {
        const message = err instanceof Error ? err.message : "unknown";
        process.stderr.write(
          `[radius:audit] ${sink} sink write failed: ${message}\n`,
        );
        this.fallbackBuffer.push(fallbackLine);
      })
      .finally(() => {
        clearTimeout(timeout);
      });
  }

  private toOtlpJson(entry: Record<string, unknown>): Record<string, unknown> {
    const nowNano = `${Date.now()}000000`;
    return {
      resourceLogs: [
        {
          resource: {
            attributes: [
              { key: "service.name", value: { stringValue: "radius" } },
            ],
          },
          scopeLogs: [
            {
              scope: { name: "radius.audit" },
              logRecords: [
                {
                  timeUnixNano: nowNano,
                  severityText: "INFO",
                  body: {
                    stringValue: JSON.stringify(entry),
                  },
                },
              ],
            },
          ],
        },
      ],
    };
  }

  private flushFallbackBuffer(): void {
    if (this.sink === "file" && this.filePath) {
      try {
        fs.appendFileSync(
          this.filePath,
          this.fallbackBuffer.join("\n") + "\n",
        );
        this.fallbackBuffer = [];
      } catch {
        // Keep in buffer
      }
    }
  }
}
