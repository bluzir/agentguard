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

type HttpDecisionStatus = HttpResolutionResult["status"] | "pending";

interface NormalizedHttpResponse {
  status?: HttpDecisionStatus;
  reason?: string;
  ttlSec?: number;
  pollUrl?: string;
  retryAfterMs?: number;
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
    const startedAtMs = Date.now();
    try {
      let normalized = await this.callAndNormalize({
        endpoint,
        method: "POST",
        timeoutMs: this.remainingTimeoutMs(startedAtMs, timeoutMs),
        body: {
          approvalId: request.approvalId,
          prompt: request.prompt,
          timeoutSec: request.timeoutSec,
          event: request.event,
        },
      });

      while (normalized.status === "pending") {
        const pollUrlRaw = normalized.pollUrl?.trim();
        if (!pollUrlRaw) {
          return {
            status: "error",
            reason:
              "http approval endpoint returned pending without pollUrl",
          };
        }

        const remainingBeforeSleep = this.remainingTimeoutMs(startedAtMs, timeoutMs);
        if (remainingBeforeSleep <= 0) {
          return {
            status: "timeout",
            reason: "http approval timed out while pending",
          };
        }

        const retryAfterMs = Math.max(
          50,
          Math.min(normalized.retryAfterMs ?? 1000, remainingBeforeSleep),
        );
        await this.sleep(retryAfterMs);

        const remaining = this.remainingTimeoutMs(startedAtMs, timeoutMs);
        if (remaining <= 0) {
          return {
            status: "timeout",
            reason: "http approval timed out while pending",
          };
        }

        normalized = await this.callAndNormalize({
          endpoint: this.resolvePollUrl(endpoint, pollUrlRaw),
          method: "GET",
          timeoutMs: remaining,
        });
      }

      return this.toResolution(normalized);
    } catch (err) {
      if (err instanceof Error && err.name === "AbortError") {
        return {
          status: "timeout",
          reason: "http approval timed out",
        };
      }
      const message = err instanceof Error ? err.message : String(err);
      return { status: "error", reason: `http resolver error: ${message}` };
    }
  }

  private async callAndNormalize(input: {
    endpoint: string;
    method: "POST" | "GET";
    timeoutMs: number;
    body?: Record<string, unknown>;
  }): Promise<NormalizedHttpResponse> {
    const controller = new AbortController();
    const timer = setTimeout(
      () => controller.abort(),
      Math.max(1, Math.floor(input.timeoutMs)),
    );

    try {
      const response = await this.fetchImpl(input.endpoint, {
        method: input.method,
        headers: {
          "content-type": "application/json",
          ...this.config.headers,
        },
        body: input.body ? JSON.stringify(input.body) : undefined,
        signal: controller.signal,
      });

      if (!response.ok) {
        throw new Error(
          `http approval endpoint failed with HTTP ${response.status}`,
        );
      }

      const raw = (await response.json()) as unknown;
      return this.normalize(raw);
    } finally {
      clearTimeout(timer);
    }
  }

  private toResolution(normalized: NormalizedHttpResponse): HttpResolutionResult {
    if (!normalized.status) {
      return {
        status: "error",
        reason: "http approval endpoint returned unknown decision format",
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
      case "pending":
        return {
          status: "error",
          reason:
            "http approval endpoint returned pending without polling loop",
        };
      default:
        return {
          status: "error",
          reason: "http approval endpoint returned unknown decision format",
        };
    }
  }

  private remainingTimeoutMs(startedAtMs: number, totalTimeoutMs: number): number {
    return Math.max(0, totalTimeoutMs - (Date.now() - startedAtMs));
  }

  private resolvePollUrl(baseUrl: string, pollUrl: string): string {
    try {
      return new URL(pollUrl, baseUrl).toString();
    } catch {
      return pollUrl;
    }
  }

  private async sleep(ms: number): Promise<void> {
    await new Promise((resolve) => setTimeout(resolve, ms));
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
    const retryAfterMs = this.pickNumber(record, [
      "retryAfterMs",
      "retry_after_ms",
      "pollIntervalMs",
      "poll_interval_ms",
    ]);
    const reason = this.pickString(record, ["reason", "message"]);
    const pollUrl = this.pickString(record, [
      "pollUrl",
      "poll_url",
      "statusUrl",
      "status_url",
    ]);

    const statusCandidate = this.pickString(record, ["status", "decision", "action"]);
    const status = this.normalizeStatus(statusCandidate);

    return {
      status,
      reason,
      ttlSec,
      pollUrl,
      retryAfterMs,
    };
  }

  private normalizeStatus(
    value: string | undefined,
  ): HttpDecisionStatus | undefined {
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
    if (normalized === "pending" || normalized === "wait") {
      return "pending";
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
