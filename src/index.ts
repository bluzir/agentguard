// Core types
export {
  GuardPhase,
  DecisionAction,
  type Framework,
  type GuardEvent,
  type ToolCall,
  type ToolResult,
  type Artifact,
  type Decision,
  type DecisionPatch,
  type ChallengeInfo,
  type Severity,
  type ApprovalChannel,
  type PipelineResult,
  type SecurityModule,
  type ModuleMode,
  type RadiusConfig,
  type AgentGuardConfig,
  type ApprovalConfig,
  type ApprovalStoreConfig,
  type ApprovalChannelsConfig,
  type TelegramApprovalChannelConfig,
  type HttpApprovalChannelConfig,
  type ProfileName,
} from "./types.js";

// Approval channel routing
export {
  type ApprovalChannelSelector,
  type AutoChannelRoutingConfig,
  type ResolvedApprovalChannel,
  type ChannelBridge,
  resolveApprovalChannel,
} from "./approval/channel-bridge.js";
export {
  type TelegramResolutionRequest,
  type TelegramResolutionResult,
  type TelegramResolverDependencies,
  TelegramApprovalResolver,
} from "./approval/telegram-resolver.js";
export {
  type HttpResolutionRequest,
  type HttpResolutionResult,
  type HttpResolverDependencies,
  HttpApprovalResolver,
} from "./approval/http-resolver.js";

// Pipeline
export { runPipeline, type PipelineOptions } from "./pipeline.js";

// Runtime
export { RadiusRuntime, AgentGuardRuntime, type RuntimeOptions } from "./runtime.js";

// Config
export { loadConfig, getProfile, PROFILES } from "./config/index.js";

// Modules
export {
  BaseModule,
  KillSwitchModule,
  SelfDefenseModule,
  ToolPolicyModule,
  FsGuardModule,
  CommandGuardModule,
  ExecSandboxModule,
  EgressGuardModule,
  OutputDlpModule,
  RateBudgetModule,
  RepetitionGuardModule,
  TripwireGuardModule,
  ApprovalGateModule,
  AuditModule,
  SkillScannerModule,
  VerdictProviderModule,
  createModules,
} from "./modules/index.js";

// Adapters
export {
  type Adapter,
  OpenClawAdapter,
  NanobotAdapter,
  ClaudeTelegramAdapter,
  GenericAdapter,
  createAdapter,
} from "./adapters/index.js";
