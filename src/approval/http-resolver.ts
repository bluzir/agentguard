import type { GuardEvent, HttpApprovalChannelConfig } from "../types.js";

export interface HttpResolutionRequest {
  approvalId: string;
  prompt: string;
  timeoutSec: number;
  event: GuardEvent;
}

export interface HttpResolutionResult {
  status:
    | "approved"
    | "approved_temporary"
    | "denied"
    | "timeout"
    | "error";
  reason: string;
  ttlSec?: number;
}

export interface HttpResolverDependencies {
  fetchImpl?: typeof fetch;
}

interface NormalizedHttpResponse {
  status?: string;
  reason?: string;
  ttlSec?: number;
}

export class HttpApprovalResolver {
  private readonly fetchImpl: typeof fetch;

  constructor(
    private readonly config: HttpApprovalChannelConfig,
    deps: HttpResolverDependencies = {},
  ) {
    this.fetchImpl = deps.fetchImpl ?? fetch;
  }

  async resolve(
    request: HttpResolutionRequest,
  ): Promise<HttpResolutionResult> {
    const endpoint = this.config.url.trim();
    if (!endpoint) {
      return { status: "error", reason: "http approval url is missing" };
    }

    const timeoutMs = this.resolveTimeoutMs(request.timeoutSec);
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeoutMs);

    try {
      const response = await this.fetchImpl(endpoint, {
        method: "POST",
        headers: {
          "content-type": "application/json",
          ...this.config.headers,
        },
        body: JSON.stringify({
          approvalId: request.approvalId,
          prompt: request.prompt,
          timeoutSec: request.timeoutSec,
          event: request.event,
        }),
        signal: controller.signal,
      });

      if (!response.ok) {
        return {
          status: "error",
          reason: `http approval endpoint failed with HTTP ${response.status}`,
        };
      }

      const raw = (await response.json()) as unknown;
      const normalized = this.normalize(raw);
      if (!normalized.status) {
        return {
          status: "error",
          reason:
            "http approval endpoint returned unknown decision format",
        };
      }

      switch (normalized.status) {
        case "approved":
          return {
            status: "approved",
            reason: normalized.reason ?? "approved by http endpoint",
          };
        case "approved_temporary":
          return {
            status: "approved_temporary",
            reason:
              normalized.reason ??
              "approved temporary by http endpoint",
            ttlSec: normalized.ttlSec,
          };
        case "denied":
          return {
            status: "denied",
            reason: normalized.reason ?? "denied by http endpoint",
          };
        case "timeout":
          return {
            status: "timeout",
            reason: normalized.reason ?? "http approval timed out",
          };
        case "error":
          return {
            status: "error",
            reason: normalized.reason ?? "http approval endpoint returned error",
          };
        default:
          return {
            status: "error",
            reason:
              "http approval endpoint returned unknown decision format",
          };
      }
    } catch (err) {
      if (err instanceof Error && err.name === "AbortError") {
        return {
          status: "timeout",
          reason: "http approval timed out",
        };
      }
      const message = err instanceof Error ? err.message : String(err);
      return { status: "error", reason: `http resolver error: ${message}` };
    } finally {
      clearTimeout(timer);
    }
  }

  private resolveTimeoutMs(challengeTimeoutSec: number): number {
    const connectorTimeoutMs = Math.max(1, Math.floor(this.config.timeoutMs));
    const challengeTimeoutMs = Math.max(1, Math.floor(challengeTimeoutSec * 1000));
    return Math.min(connectorTimeoutMs, challengeTimeoutMs);
  }

  private normalize(raw: unknown): NormalizedHttpResponse {
    if (!raw || typeof raw !== "object") return {};
    const record = raw as Record<string, unknown>;

    const ttlSec = this.pickNumber(record, ["ttlSec", "ttl_sec", "leaseTtlSec"]);
    const reason = this.pickString(record, ["reason", "message"]);

    const statusCandidate = this.pickString(record, ["status", "decision", "action"]);
    const status = this.normalizeStatus(statusCandidate);

    return {
      status,
      reason,
      ttlSec,
    };
  }

  private normalizeStatus(
    value: string | undefined,
  ): HttpResolutionResult["status"] | undefined {
    if (!value) return undefined;
    const normalized = value.trim().toLowerCase();
    if (
      normalized === "approved" ||
      normalized === "approve" ||
      normalized === "allow" ||
      normalized === "allowed"
    ) {
      return "approved";
    }
    if (
      normalized === "approved_temporary" ||
      normalized === "approve_temporary" ||
      normalized === "grant30m" ||
      normalized === "allow30m" ||
      normalized === "allow_temporary"
    ) {
      return "approved_temporary";
    }
    if (
      normalized === "denied" ||
      normalized === "deny" ||
      normalized === "block" ||
      normalized === "blocked"
    ) {
      return "denied";
    }
    if (normalized === "timeout" || normalized === "timed_out") {
      return "timeout";
    }
    if (normalized === "error" || normalized === "failed") {
      return "error";
    }
    return undefined;
  }

  private pickString(
    record: Record<string, unknown>,
    keys: string[],
  ): string | undefined {
    for (const key of keys) {
      const value = record[key];
      if (typeof value === "string" && value.trim().length > 0) {
        return value.trim();
      }
    }
    return undefined;
  }

  private pickNumber(
    record: Record<string, unknown>,
    keys: string[],
  ): number | undefined {
    for (const key of keys) {
      const value = record[key];
      if (typeof value === "number" && Number.isFinite(value) && value > 0) {
        return Math.floor(value);
      }
    }
    return undefined;
  }
}
