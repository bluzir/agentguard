import type { GuardEvent, TelegramApprovalChannelConfig } from "../types.js";

export interface TelegramResolutionRequest {
  approvalId: string;
  prompt: string;
  timeoutSec: number;
  event: GuardEvent;
}

export interface TelegramResolutionResult {
  status: "approved" | "denied" | "timeout" | "error";
  reason: string;
}

export interface TelegramResolverDependencies {
  fetchImpl?: typeof fetch;
  sleep?: (ms: number) => Promise<void>;
  now?: () => number;
}

interface TelegramCallbackQuery {
  id: string;
  from?: { id?: number | string };
  message?: {
    chat?: { id?: number | string };
  };
  data?: string;
}

interface TelegramUpdate {
  update_id?: number;
  callback_query?: TelegramCallbackQuery;
}

interface TelegramApiResponse<T> {
  ok: boolean;
  result?: T;
  description?: string;
}

export class TelegramApprovalResolver {
  private readonly fetchImpl: typeof fetch;
  private readonly sleep: (ms: number) => Promise<void>;
  private readonly now: () => number;
  private updateOffset = 0;

  constructor(
    private readonly config: TelegramApprovalChannelConfig,
    deps: TelegramResolverDependencies = {},
  ) {
    this.fetchImpl = deps.fetchImpl ?? fetch;
    this.sleep =
      deps.sleep ??
      ((ms: number) =>
        new Promise((resolve) => {
          setTimeout(resolve, ms);
        }));
    this.now = deps.now ?? Date.now;
  }

  async resolve(
    request: TelegramResolutionRequest,
  ): Promise<TelegramResolutionResult> {
    const token = this.config.botToken.trim();
    if (!token || token === "SET_ME") {
      return { status: "error", reason: "telegram bot token is missing" };
    }
    if (this.config.allowedChatIds.length === 0) {
      return { status: "error", reason: "telegram allowedChatIds is empty" };
    }

    try {
      await this.sendChallenge(token, request);
      const decision = await this.pollDecision(token, request);
      if (decision === "approve") {
        return { status: "approved", reason: "approved from Telegram callback" };
      }
      if (decision === "deny") {
        return { status: "denied", reason: "denied from Telegram callback" };
      }
      return { status: "timeout", reason: "telegram approval timed out" };
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      return { status: "error", reason: `telegram resolver error: ${message}` };
    }
  }

  private async sendChallenge(
    token: string,
    request: TelegramResolutionRequest,
  ): Promise<void> {
    const baseText = this.buildPromptText(request);
    for (const chatId of this.config.allowedChatIds) {
      const payload = {
        chat_id: chatId,
        text: baseText,
        reply_markup: {
          inline_keyboard: [
            [
              {
                text: "Approve",
                callback_data: `ag:approve:${request.approvalId}`,
              },
              {
                text: "Deny",
                callback_data: `ag:deny:${request.approvalId}`,
              },
            ],
          ],
        },
      };
      await this.callApi(token, "sendMessage", payload);
    }
  }

  private async pollDecision(
    token: string,
    request: TelegramResolutionRequest,
  ): Promise<"approve" | "deny" | undefined> {
    const timeoutMs = Math.max(0, request.timeoutSec) * 1000;
    const deadline = this.now() + timeoutMs;

    while (this.now() <= deadline) {
      const updates = await this.fetchUpdates(token);
      for (const update of updates) {
        const query = update.callback_query;
        if (!query || typeof query.data !== "string") continue;
        const parsed = this.parseDecisionData(query.data, request.approvalId);
        if (!parsed) continue;

        if (!this.isAuthorized(query)) {
          await this.answerCallback(
            token,
            query.id,
            "Not authorized for this approval",
          );
          continue;
        }

        await this.answerCallback(token, query.id, "Decision received");
        return parsed;
      }

      const remaining = deadline - this.now();
      if (remaining <= 0) break;
      await this.sleep(Math.min(this.config.pollIntervalMs, remaining));
    }

    return undefined;
  }

  private buildPromptText(request: TelegramResolutionRequest): string {
    const tool = request.event.toolCall?.name ?? "unknown";
    const command = this.extractCommand(request.event);
    const agent = request.event.agentName ?? "unknown";
    const channel =
      typeof request.event.metadata.channel === "string"
        ? request.event.metadata.channel
        : "unknown";

    const lines = [
      "[agentguard] approval required",
      `Tool: ${tool}`,
      `Session: ${request.event.sessionId}`,
      `Agent: ${agent}`,
      `Channel: ${channel}`,
      `Request: ${request.prompt}`,
    ];
    if (command) {
      lines.push(`Command: ${command}`);
    }
    return lines.join("\n");
  }

  private extractCommand(event: GuardEvent): string | undefined {
    const command = event.toolCall?.arguments?.command;
    if (typeof command === "string" && command.trim().length > 0) {
      return command.trim();
    }
    return undefined;
  }

  private parseDecisionData(
    data: string,
    approvalId: string,
  ): "approve" | "deny" | undefined {
    const match = /^ag:(approve|deny):([A-Za-z0-9_-]+)$/.exec(data.trim());
    if (!match) return undefined;
    if (match[2] !== approvalId) return undefined;
    return match[1] === "approve" ? "approve" : "deny";
  }

  private isAuthorized(query: TelegramCallbackQuery): boolean {
    const callbackUser = String(query.from?.id ?? "");
    const callbackChat = String(query.message?.chat?.id ?? "");

    if (
      this.config.approverUserIds.length > 0 &&
      !this.config.approverUserIds.includes(callbackUser)
    ) {
      return false;
    }

    if (
      this.config.allowedChatIds.length > 0 &&
      !this.config.allowedChatIds.includes(callbackChat)
    ) {
      return false;
    }

    return true;
  }

  private async fetchUpdates(token: string): Promise<TelegramUpdate[]> {
    const payload: Record<string, unknown> = {
      timeout: 0,
      allowed_updates: ["callback_query"],
    };
    if (this.updateOffset > 0) {
      payload.offset = this.updateOffset;
    }

    const response = await this.callApi<TelegramUpdate[]>(token, "getUpdates", payload);
    const updates = Array.isArray(response) ? response : [];
    for (const update of updates) {
      if (
        typeof update.update_id === "number" &&
        update.update_id >= this.updateOffset
      ) {
        this.updateOffset = update.update_id + 1;
      }
    }
    return updates;
  }

  private async answerCallback(
    token: string,
    callbackQueryId: string,
    text: string,
  ): Promise<void> {
    if (!callbackQueryId) return;
    try {
      await this.callApi(token, "answerCallbackQuery", {
        callback_query_id: callbackQueryId,
        text,
        show_alert: false,
      });
    } catch {
      // best-effort only
    }
  }

  private async callApi<T = unknown>(
    token: string,
    method: string,
    payload: Record<string, unknown>,
  ): Promise<T> {
    const url = `https://api.telegram.org/bot${token}/${method}`;
    const response = await this.fetchImpl(url, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(payload),
    });

    if (!response.ok) {
      throw new Error(`telegram ${method} failed with HTTP ${response.status}`);
    }

    const parsed = (await response.json()) as TelegramApiResponse<T>;
    if (!parsed.ok) {
      throw new Error(parsed.description ?? `telegram ${method} failed`);
    }
    return parsed.result as T;
  }
}
