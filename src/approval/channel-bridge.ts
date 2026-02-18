import type { ApprovalChannel, Framework, GuardEvent } from "../types.js";

export type ApprovalChannelSelector = ApprovalChannel | "auto";

export interface AutoChannelRoutingConfig {
  defaultChannel?: ApprovalChannel;
  frameworkDefaults?: Partial<Record<Framework, ApprovalChannel>>;
  metadataKeys?: string[];
}

export interface ResolvedApprovalChannel {
  channel: ApprovalChannel;
  source: "explicit" | "event_metadata" | "framework_default" | "global_default";
  reason: string;
}

/**
 * Contract for future runtime channel connectors (OpenClaw-native, Telegram, Discord, HTTP).
 * Runtime currently resolves Telegram and HTTP challenges directly.
 * This bridge contract is reserved for pluggable channel connectors.
 */
export interface ChannelBridge {
  channel: ApprovalChannel;
  sendChallenge(input: {
    approvalId: string;
    prompt: string;
    sessionId: string;
    agentName?: string;
    metadata: Record<string, unknown>;
  }): Promise<{ delivered: boolean; externalId?: string; reason?: string }>;
}

const DEFAULT_FRAMEWORK_CHANNELS: Record<Framework, ApprovalChannel> = {
  openclaw: "telegram",
  nanobot: "telegram",
  "claude-telegram": "telegram",
  generic: "http",
};

function normalizeChannel(value: unknown): ApprovalChannel | undefined {
  if (typeof value !== "string") return undefined;
  const normalized = value.trim().toLowerCase();
  if (
    normalized === "orchestrator" ||
    normalized === "telegram" ||
    normalized === "discord" ||
    normalized === "http"
  ) {
    return normalized;
  }
  return undefined;
}

function pickMetadataChannel(
  event: GuardEvent,
  keys: string[],
): ApprovalChannel | undefined {
  for (const key of keys) {
    const value = event.metadata[key];
    const channel = normalizeChannel(value);
    if (channel) return channel;
  }
  return undefined;
}

export function resolveApprovalChannel(input: {
  requested: ApprovalChannelSelector;
  event: GuardEvent;
  autoRouting?: AutoChannelRoutingConfig;
}): ResolvedApprovalChannel {
  const { requested, event, autoRouting } = input;

  if (requested !== "auto") {
    return {
      channel: requested,
      source: "explicit",
      reason: `explicit channel "${requested}" from rule`,
    };
  }

  const metadataKeys = autoRouting?.metadataKeys ?? [
    "channel",
    "transportChannel",
    "messenger",
  ];
  const metadataChannel = pickMetadataChannel(event, metadataKeys);
  if (metadataChannel) {
    return {
      channel: metadataChannel,
      source: "event_metadata",
      reason: `resolved from event metadata key (${metadataKeys.join(", ")})`,
    };
  }

  const frameworkChannel =
    autoRouting?.frameworkDefaults?.[event.framework] ??
    DEFAULT_FRAMEWORK_CHANNELS[event.framework];
  if (frameworkChannel) {
    return {
      channel: frameworkChannel,
      source: "framework_default",
      reason: `framework default for ${event.framework}`,
    };
  }

  return {
    channel: autoRouting?.defaultChannel ?? "telegram",
    source: "global_default",
    reason: "auto routing fallback default",
  };
}
