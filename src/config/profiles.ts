import type { AgentGuardConfig } from "../types.js";

type DeepPartial<T> = {
  [P in keyof T]?: T[P] extends object ? DeepPartial<T[P]> : T[P];
};

/**
 * §12.1 strict — default production profile.
 */
const strict: DeepPartial<AgentGuardConfig> = {
  global: {
    profile: "strict",
    defaultAction: "deny",
  },
  modules: [
    "skill_scanner",
    "tool_policy",
    "fs_guard",
    "command_guard",
    "exec_sandbox",
    "egress_guard",
    "output_dlp",
    "rate_budget",
    "audit",
  ],
  moduleConfig: {
    skill_scanner: {
      scanOnStartup: true,
      scanOnReload: true,
      actionOnCritical: "deny",
    },
    tool_policy: {
      default: "deny",
    },
    exec_sandbox: {
      engine: "bwrap",
      required: true,
    },
    output_dlp: {
      action: "deny",
    },
    rate_budget: {
      windowSec: 60,
      maxCallsPerWindow: 30,
    },
  },
};

/**
 * §12.2 balanced — developer default profile.
 */
const balanced: DeepPartial<AgentGuardConfig> = {
  global: {
    profile: "balanced",
    defaultAction: "deny",
  },
  modules: [
    "skill_scanner",
    "tool_policy",
    "fs_guard",
    "command_guard",
    "exec_sandbox",
    "output_dlp",
    "rate_budget",
    "audit",
  ],
  moduleConfig: {
    skill_scanner: {
      scanOnStartup: true,
      actionOnCritical: "challenge",
    },
    tool_policy: {
      default: "deny",
    },
    exec_sandbox: {
      engine: "bwrap",
      required: false,
    },
    output_dlp: {
      action: "redact",
    },
    rate_budget: {
      windowSec: 60,
      maxCallsPerWindow: 60,
    },
  },
};

/**
 * §12.3 monitor — migration/rollout mode.
 */
const monitor: DeepPartial<AgentGuardConfig> = {
  global: {
    profile: "monitor",
    defaultAction: "allow",
  },
  modules: [
    "skill_scanner",
    "tool_policy",
    "fs_guard",
    "command_guard",
    "output_dlp",
    "rate_budget",
    "audit",
  ],
  moduleConfig: {
    skill_scanner: {
      actionOnCritical: "alert",
      mode: "observe",
    },
    tool_policy: {
      default: "allow",
      mode: "observe",
    },
    fs_guard: {
      mode: "observe",
    },
    command_guard: {
      mode: "observe",
    },
    output_dlp: {
      action: "alert",
      mode: "observe",
    },
    rate_budget: {
      windowSec: 60,
      maxCallsPerWindow: 120,
      mode: "observe",
    },
  },
};

export const PROFILES = { strict, balanced, monitor } as const;

const PROFILE_ALIASES = {
  bunker: "strict",
  tactical: "balanced",
  yolo: "monitor",
  unleashed: "monitor",
} as const;

export type CanonicalProfileName = keyof typeof PROFILES;
export type ProfileAlias = keyof typeof PROFILE_ALIASES;
export type ProfileInput = CanonicalProfileName | ProfileAlias;

export function resolveProfileName(name: string): CanonicalProfileName {
  const normalized = name.trim().toLowerCase();
  if (normalized in PROFILES) {
    return normalized as CanonicalProfileName;
  }
  const mapped = PROFILE_ALIASES[normalized as ProfileAlias];
  if (mapped) {
    return mapped;
  }
  throw new Error(
    `unknown profile/mode: "${name}". Available profiles: strict, balanced, monitor. Available modes: bunker, tactical, yolo`,
  );
}

export function getProfile(name: string): DeepPartial<AgentGuardConfig> {
  return PROFILES[resolveProfileName(name)];
}
