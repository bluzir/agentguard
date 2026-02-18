import type { RadiusConfig } from "../types.js";

type DeepPartial<T> = {
  [P in keyof T]?: T[P] extends object ? DeepPartial<T[P]> : T[P];
};

/**
 * §12.1 local — default production profile.
 */
const local: DeepPartial<RadiusConfig> = {
  global: {
    profile: "local",
    defaultAction: "deny",
  },
  modules: [
    "kill_switch",
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
    kill_switch: {
      enabled: true,
      envVar: "RADIUS_KILL_SWITCH",
      filePath: "./.radius/KILL_SWITCH",
      denyPhases: ["pre_request", "pre_tool"],
      reason: "emergency kill switch active: human safety override",
    },
    skill_scanner: {
      scanOnStartup: true,
      scanOnReload: true,
      actionOnCritical: "deny",
      requireSignature: true,
      requireSbom: true,
      requirePinnedSource: true,
      onProvenanceFailure: "deny",
    },
    tool_policy: {
      default: "deny",
    },
    fs_guard: {
      blockedBasenames: [
        ".env",
        ".env.local",
        ".env.development",
        ".env.production",
        ".env.test",
        ".envrc",
      ],
    },
    command_guard: {
      denyPatterns: [
        "(^|\\s)sudo\\s",
        "rm\\s+-rf\\s+/",
        "(^|\\s)(cat|less|more|head|tail|grep|awk|sed)\\s+[^\\n]*\\.env(?:\\.|\\s|$)",
      ],
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
 * §12.2 standard — developer default profile.
 */
const standard: DeepPartial<RadiusConfig> = {
  global: {
    profile: "standard",
    defaultAction: "deny",
  },
  modules: [
    "kill_switch",
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
    kill_switch: {
      enabled: true,
      envVar: "RADIUS_KILL_SWITCH",
      filePath: "./.radius/KILL_SWITCH",
      denyPhases: ["pre_request", "pre_tool"],
      reason: "emergency kill switch active: human safety override",
    },
    skill_scanner: {
      scanOnStartup: true,
      actionOnCritical: "challenge",
      onProvenanceFailure: "challenge",
    },
    tool_policy: {
      default: "deny",
    },
    fs_guard: {
      blockedBasenames: [".env", ".env.local", ".envrc"],
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
 * §12.3 unbounded — migration/rollout mode.
 */
const unbounded: DeepPartial<RadiusConfig> = {
  global: {
    profile: "unbounded",
    defaultAction: "allow",
  },
  modules: [
    "kill_switch",
    "skill_scanner",
    "tool_policy",
    "fs_guard",
    "command_guard",
    "output_dlp",
    "rate_budget",
    "audit",
  ],
  moduleConfig: {
    kill_switch: {
      enabled: true,
      envVar: "RADIUS_KILL_SWITCH",
      filePath: "./.radius/KILL_SWITCH",
      denyPhases: ["pre_request", "pre_tool"],
      reason: "emergency kill switch active: human safety override",
      mode: "observe",
    },
    skill_scanner: {
      actionOnCritical: "alert",
      onProvenanceFailure: "alert",
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

export const PROFILES = { local, standard, unbounded } as const;

const PROFILE_ALIASES = {
  strict: "local",
  balanced: "standard",
  monitor: "unbounded",
  bunker: "local",
  tactical: "standard",
  yolo: "unbounded",
  unleashed: "unbounded",
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
    `unknown profile/mode: "${name}". Available profiles: local, standard, unbounded. Aliases: strict, balanced, monitor, bunker, tactical, yolo`,
  );
}

export function getProfile(name: string): DeepPartial<RadiusConfig> {
  return PROFILES[resolveProfileName(name)];
}
