import fs from "node:fs";
import { createRequire } from "node:module";
import path from "node:path";

const require = createRequire(import.meta.url);
const MISSING_AGENT_SENTINEL = "__radius_agent_missing__";
const RATE_BUDGET_RETENTION_MS = 24 * 60 * 60 * 1000;

interface SqliteStatement {
  run(...params: unknown[]): unknown;
  get<T = Record<string, unknown>>(...params: unknown[]): T | undefined;
}

interface SqliteDatabase {
  exec(sql: string): unknown;
  prepare(sql: string): SqliteStatement;
}

interface SqliteModuleShape {
  DatabaseSync?: new (filename: string) => SqliteDatabase;
}

interface ApprovalLeaseRow {
  id: string;
  sessionId: string;
  agentName: string | null;
  tool: string;
  expiresAtMs: number;
  reason: string | null;
}

interface CountRow {
  count: number | bigint;
}

export interface SqliteStoreConfig {
  path?: string;
  required?: boolean;
}

export interface StoredApprovalLease {
  id: string;
  sessionId: string;
  agentName?: string;
  tool: string;
  expiresAtMs: number;
  reason?: string;
}

export interface RateBudgetConsumeInput {
  bucketKey: string;
  nowMs: number;
  windowMs: number;
  maxCalls: number;
}

export interface RateBudgetConsumeResult {
  allowed: boolean;
  count: number;
}

export interface SqliteStateStore {
  insertApprovalLease(lease: StoredApprovalLease): void;
  findActiveApprovalLease(input: {
    sessionId: string;
    agentName?: string;
    tool: string;
    nowMs: number;
  }): StoredApprovalLease | undefined;
  clearApprovalLeases(): void;
  consumeRateBudget(
    input: RateBudgetConsumeInput,
  ): RateBudgetConsumeResult;
}

class SqliteStateStoreImpl implements SqliteStateStore {
  private deleteExpiredApprovalLeasesStmt: SqliteStatement;
  private insertApprovalLeaseStmt: SqliteStatement;
  private findApprovalLeaseStmt: SqliteStatement;
  private clearApprovalLeasesStmt: SqliteStatement;

  private pruneBudgetKeyStmt: SqliteStatement;
  private pruneBudgetRetentionStmt: SqliteStatement;
  private countBudgetStmt: SqliteStatement;
  private insertBudgetStmt: SqliteStatement;

  constructor(private readonly db: SqliteDatabase) {
    this.db.exec("PRAGMA journal_mode = WAL;");
    this.db.exec("PRAGMA synchronous = NORMAL;");
    this.db.exec("PRAGMA busy_timeout = 5000;");

    this.db.exec(`
      CREATE TABLE IF NOT EXISTS approval_leases (
        id TEXT PRIMARY KEY,
        session_id TEXT NOT NULL,
        agent_name TEXT,
        tool TEXT NOT NULL,
        expires_at_ms INTEGER NOT NULL,
        reason TEXT,
        created_at_ms INTEGER NOT NULL
      );
      CREATE INDEX IF NOT EXISTS idx_approval_leases_lookup
        ON approval_leases(session_id, agent_name, tool, expires_at_ms);
      CREATE INDEX IF NOT EXISTS idx_approval_leases_expiry
        ON approval_leases(expires_at_ms);

      CREATE TABLE IF NOT EXISTS rate_budget_events (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        bucket_key TEXT NOT NULL,
        ts_ms INTEGER NOT NULL
      );
      CREATE INDEX IF NOT EXISTS idx_rate_budget_lookup
        ON rate_budget_events(bucket_key, ts_ms);
      CREATE INDEX IF NOT EXISTS idx_rate_budget_expiry
        ON rate_budget_events(ts_ms);
    `);

    this.deleteExpiredApprovalLeasesStmt = this.db.prepare(
      "DELETE FROM approval_leases WHERE expires_at_ms <= ?",
    );
    this.insertApprovalLeaseStmt = this.db.prepare(`
      INSERT INTO approval_leases (
        id, session_id, agent_name, tool, expires_at_ms, reason, created_at_ms
      ) VALUES (?, ?, ?, ?, ?, ?, ?)
      ON CONFLICT(id) DO UPDATE SET
        session_id = excluded.session_id,
        agent_name = excluded.agent_name,
        tool = excluded.tool,
        expires_at_ms = excluded.expires_at_ms,
        reason = excluded.reason
    `);
    this.findApprovalLeaseStmt = this.db.prepare(`
      SELECT
        id,
        session_id AS sessionId,
        agent_name AS agentName,
        tool,
        expires_at_ms AS expiresAtMs,
        reason
      FROM approval_leases
      WHERE session_id = ?
        AND (agent_name IS NULL OR agent_name = ?)
        AND (tool = '*' OR tool = ?)
        AND expires_at_ms > ?
      ORDER BY expires_at_ms DESC
      LIMIT 1
    `);
    this.clearApprovalLeasesStmt = this.db.prepare(
      "DELETE FROM approval_leases",
    );

    this.pruneBudgetKeyStmt = this.db.prepare(
      "DELETE FROM rate_budget_events WHERE bucket_key = ? AND ts_ms <= ?",
    );
    this.pruneBudgetRetentionStmt = this.db.prepare(
      "DELETE FROM rate_budget_events WHERE ts_ms <= ?",
    );
    this.countBudgetStmt = this.db.prepare(
      "SELECT COUNT(*) AS count FROM rate_budget_events WHERE bucket_key = ?",
    );
    this.insertBudgetStmt = this.db.prepare(
      "INSERT INTO rate_budget_events (bucket_key, ts_ms) VALUES (?, ?)",
    );
  }

  insertApprovalLease(lease: StoredApprovalLease): void {
    this.deleteExpiredApprovalLeasesStmt.run(Date.now());
    this.insertApprovalLeaseStmt.run(
      lease.id,
      lease.sessionId,
      lease.agentName ?? null,
      lease.tool,
      lease.expiresAtMs,
      lease.reason ?? null,
      Date.now(),
    );
  }

  findActiveApprovalLease(input: {
    sessionId: string;
    agentName?: string;
    tool: string;
    nowMs: number;
  }): StoredApprovalLease | undefined {
    this.deleteExpiredApprovalLeasesStmt.run(input.nowMs);

    const row = this.findApprovalLeaseStmt.get<ApprovalLeaseRow>(
      input.sessionId,
      input.agentName ?? MISSING_AGENT_SENTINEL,
      input.tool,
      input.nowMs,
    );
    if (!row) return undefined;

    return {
      id: row.id,
      sessionId: row.sessionId,
      agentName: row.agentName ?? undefined,
      tool: row.tool,
      expiresAtMs: Number(row.expiresAtMs),
      reason: row.reason ?? undefined,
    };
  }

  clearApprovalLeases(): void {
    this.clearApprovalLeasesStmt.run();
  }

  consumeRateBudget(input: RateBudgetConsumeInput): RateBudgetConsumeResult {
    const cutoff = input.nowMs - input.windowMs;
    const retentionCutoff = input.nowMs - RATE_BUDGET_RETENTION_MS;

    this.db.exec("BEGIN IMMEDIATE");
    try {
      this.pruneBudgetKeyStmt.run(input.bucketKey, cutoff);
      this.pruneBudgetRetentionStmt.run(retentionCutoff);

      const row = this.countBudgetStmt.get<CountRow>(input.bucketKey);
      const countBefore = Number(row?.count ?? 0);
      if (countBefore >= input.maxCalls) {
        this.db.exec("COMMIT");
        return {
          allowed: false,
          count: countBefore,
        };
      }

      this.insertBudgetStmt.run(input.bucketKey, input.nowMs);
      this.db.exec("COMMIT");
      return {
        allowed: true,
        count: countBefore + 1,
      };
    } catch (error) {
      try {
        this.db.exec("ROLLBACK");
      } catch {
        // noop: rollback best-effort only
      }
      throw error;
    }
  }
}

const storeCache = new Map<string, SqliteStateStore>();
let sqliteCtor: (new (filename: string) => SqliteDatabase) | null = null;
let sqliteCtorLoaded = false;

function loadSqliteCtor():
  | (new (filename: string) => SqliteDatabase)
  | null {
  if (sqliteCtorLoaded) return sqliteCtor;
  sqliteCtorLoaded = true;

  try {
    const sqliteModule = require("node:sqlite") as SqliteModuleShape;
    if (typeof sqliteModule.DatabaseSync === "function") {
      sqliteCtor = sqliteModule.DatabaseSync;
      return sqliteCtor;
    }
  } catch {
    sqliteCtor = null;
  }

  return null;
}

function resolveDbPath(dbPath: string): string {
  if (path.isAbsolute(dbPath)) return dbPath;
  return path.resolve(process.cwd(), dbPath);
}

export function getSqliteStateStore(
  config: SqliteStoreConfig = {},
): SqliteStateStore | undefined {
  const dbPath = resolveDbPath(config.path ?? "./.radius/state.db");
  const required = config.required ?? false;

  if (storeCache.has(dbPath)) {
    return storeCache.get(dbPath);
  }

  const Ctor = loadSqliteCtor();
  if (!Ctor) {
    if (required) {
      throw new Error(
        'SQLite store requested but "node:sqlite" is not available in this Node runtime',
      );
    }
    return undefined;
  }

  try {
    fs.mkdirSync(path.dirname(dbPath), { recursive: true });
    const db = new Ctor(dbPath);
    const store = new SqliteStateStoreImpl(db);
    storeCache.set(dbPath, store);
    return store;
  } catch (error) {
    if (required) {
      throw error;
    }
    return undefined;
  }
}

export function clearSqliteApprovalLeases(): void {
  for (const store of storeCache.values()) {
    store.clearApprovalLeases();
  }
}
