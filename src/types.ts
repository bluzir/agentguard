// ── Guard Phases ──

export enum GuardPhase {
  PRE_LOAD = "pre_load",
  PRE_REQUEST = "pre_request",
  PRE_TOOL = "pre_tool",
  POST_TOOL = "post_tool",
  PRE_RESPONSE = "pre_response",
}

// ── Framework identifiers ──

export type Framework =
  | "openclaw"
  | "nanobot"
  | "claude-telegram"
  | "generic";

// ── Canonical Event ──

export interface ToolCall {
  name: string;
  arguments: Record<string, unknown>;
  raw?: unknown;
}

export interface ToolResult {
  text: string;
  isError: boolean;
  raw?: unknown;
}

export interface Artifact {
  kind: "skill" | "prompt" | "tool_metadata" | "config";
  path?: string;
  content: string;
  sourceUri?: string;
  sha256?: string;
  signatureVerified?: boolean;
  signer?: string;
  sbomUri?: string;
  versionPinned?: boolean;
}

export interface GuardEvent {
  phase: GuardPhase;
  framework: Framework;

  agentName?: string;
  sessionId: string;
  userId?: string;

  requestText?: string;

  toolCall?: ToolCall;
  toolResult?: ToolResult;
  responseText?: string;
  artifact?: Artifact;

  metadata: Record<string, unknown>;
}

// ── Decisions ──

export enum DecisionAction {
  ALLOW = "allow",
  DENY = "deny",
  MODIFY = "modify",
  CHALLENGE = "challenge",
  ALERT = "alert",
}

export type Severity = "info" | "medium" | "high" | "critical";

export type ApprovalChannel =
  | "orchestrator"
  | "telegram"
  | "discord"
  | "http";

export interface DecisionPatch {
  requestText?: string;
  toolArguments?: Record<string, unknown>;
  toolResultText?: string;
  responseText?: string;
}

export interface ChallengeInfo {
  channel: ApprovalChannel;
  prompt: string;
  timeoutSec: number;
}

export interface Decision {
  action: DecisionAction;
  module: string;
  reason: string;
  severity: Severity;

  patch?: DecisionPatch;
  challenge?: ChallengeInfo;
}

// ── Pipeline Result ──

export interface PipelineResult {
  finalAction: DecisionAction;
  reason: string;

  transformed: {
    requestText?: string;
    toolArguments?: Record<string, unknown>;
    toolResultText?: string;
    responseText?: string;
  };

  alerts: string[];
  decisions: Decision[];
}

// ── Module Contract ──

export type ModuleMode = "enforce" | "observe";

export interface SecurityModule {
  name: string;
  phases: Set<GuardPhase>;
  mode: ModuleMode;

  configure(config: Record<string, unknown>): void;
  evaluate(event: GuardEvent): Promise<Decision>;
}

// ── Config types ──

export type ProfileName = "strict" | "balanced" | "monitor";

export interface AuditConfig {
  sink: "file" | "stdout" | "webhook" | "otlp";
  path?: string;
  webhookUrl?: string;
  otlpEndpoint?: string;
  headers?: Record<string, string>;
  timeoutMs?: number;
  includeArguments: boolean;
  includeResults: boolean;
}

export interface ApprovalStoreConfig {
  engine: "sqlite" | "memory";
  path?: string;
}

export interface TelegramApprovalChannelConfig {
  enabled: boolean;
  transport: "polling" | "webhook";
  botToken: string;
  allowedChatIds: string[];
  approverUserIds: string[];
  pollIntervalMs: number;
  webhookPublicUrl?: string;
}

export interface ApprovalChannelsConfig {
  telegram?: TelegramApprovalChannelConfig;
}

export interface ApprovalConfig {
  enabled: boolean;
  mode: "sync_wait" | "async_token";
  waitTimeoutSec: number;
  onTimeout: "deny" | "alert";
  onConnectorError: "deny" | "alert";
  store: ApprovalStoreConfig;
  channels: ApprovalChannelsConfig;
}

export interface GlobalConfig {
  profile: ProfileName;
  workspace: string;
  defaultAction: "deny" | "allow";
  requireSignedPolicy: boolean;
  onUndefinedTemplateVar: "error" | "empty";
}

export interface AgentGuardConfig {
  global: GlobalConfig;
  audit: AuditConfig;
  approval: ApprovalConfig;
  adapters: Record<string, Record<string, unknown>>;
  modules: string[];
  moduleConfig: Record<string, Record<string, unknown>>;
}
