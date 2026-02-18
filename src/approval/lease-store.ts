import type { GuardEvent } from "../types.js";
import {
  clearSqliteApprovalLeases,
  getSqliteStateStore,
} from "../state/sqlite.js";

export interface ApprovalLease {
  id: string;
  sessionId: string;
  agentName?: string;
  tool: string;
  expiresAtMs: number;
  reason?: string;
}

export interface ApprovalLeaseStoreConfig {
  engine?: "memory" | "sqlite";
  path?: string;
  required?: boolean;
}

const leases = new Map<string, ApprovalLease>();
let storeConfig: ApprovalLeaseStoreConfig = {
  engine: "memory",
  path: "./.radius/state.db",
  required: false,
};

function now(): number {
  return Date.now();
}

function randomId(): string {
  return Math.random().toString(36).slice(2, 8);
}

function cleanupExpired(currentTimeMs = now()): void {
  for (const [id, lease] of leases.entries()) {
    if (lease.expiresAtMs <= currentTimeMs) {
      leases.delete(id);
    }
  }
}

function getConfiguredSqliteStore() {
  if (storeConfig.engine !== "sqlite") return undefined;
  return getSqliteStateStore({
    path: storeConfig.path,
    required: storeConfig.required ?? false,
  });
}

export function configureApprovalLeaseStore(
  config: ApprovalLeaseStoreConfig,
): void {
  storeConfig = {
    engine: config.engine ?? "memory",
    path: config.path ?? "./.radius/state.db",
    required: config.required ?? false,
  };
}

export function grantApprovalLease(input: {
  sessionId: string;
  agentName?: string;
  tool?: string;
  ttlSec: number;
  reason?: string;
}): ApprovalLease {
  const ttlSec = Math.max(1, Math.floor(input.ttlSec));
  const lease: ApprovalLease = {
    id: `${Date.now().toString(36)}-${randomId()}`,
    sessionId: input.sessionId,
    agentName: input.agentName,
    tool: input.tool ?? "*",
    expiresAtMs: now() + ttlSec * 1000,
    reason: input.reason,
  };
  const sqliteStore = getConfiguredSqliteStore();
  if (sqliteStore) {
    sqliteStore.insertApprovalLease(lease);
    return lease;
  }

  leases.set(lease.id, lease);
  cleanupExpired();
  return lease;
}

export function findActiveApprovalLease(
  event: GuardEvent,
  toolName: string,
): ApprovalLease | undefined {
  const sqliteStore = getConfiguredSqliteStore();
  if (sqliteStore) {
    return sqliteStore.findActiveApprovalLease({
      sessionId: event.sessionId,
      agentName: event.agentName,
      tool: toolName,
      nowMs: now(),
    });
  }

  cleanupExpired();
  const candidates: ApprovalLease[] = [];

  for (const lease of leases.values()) {
    if (lease.sessionId !== event.sessionId) continue;

    // If lease is scoped to a specific agent, require exact match.
    if (lease.agentName && lease.agentName !== event.agentName) continue;

    if (lease.tool !== "*" && lease.tool !== toolName) continue;
    candidates.push(lease);
  }

  if (candidates.length === 0) return undefined;
  candidates.sort((a, b) => b.expiresAtMs - a.expiresAtMs);
  return candidates[0];
}

export function clearApprovalLeases(): void {
  leases.clear();
  clearSqliteApprovalLeases();
}
