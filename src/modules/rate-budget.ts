import { type Decision, type GuardEvent, GuardPhase } from "../types.js";
import { getSqliteStateStore } from "../state/sqlite.js";
import { BaseModule } from "./base.js";

interface RateBudgetStoreConfig {
  engine?: "memory" | "sqlite";
  path?: string;
  required?: boolean;
}

interface RateBudgetConfig {
  windowSec: number;
  maxCallsPerWindow: number;
  store?: RateBudgetStoreConfig;
}

interface WindowEntry {
  timestamp: number;
}

/**
 * §9.7 rate_budget — protect against runaway loops and cost spikes.
 * Phases: PRE_TOOL, optional PRE_REQUEST
 *
 * Sliding-window request/tool limits. Local in-memory by default.
 */
export class RateBudgetModule extends BaseModule {
  name = "rate_budget";
  phases = new Set([GuardPhase.PRE_TOOL, GuardPhase.PRE_REQUEST]);

  private windowSec = 60;
  private maxCallsPerWindow = 60;
  private storeEngine: "memory" | "sqlite" = "memory";
  private storePath = "./.radius/state.db";
  private storeRequired = false;

  // In-memory sliding window, keyed by sessionId
  private windows = new Map<string, WindowEntry[]>();

  override configure(config: Record<string, unknown>): void {
    super.configure(config);
    const c = config as unknown as Partial<RateBudgetConfig>;
    this.windowSec = c.windowSec ?? 60;
    this.maxCallsPerWindow = c.maxCallsPerWindow ?? 60;
    this.storeEngine = c.store?.engine ?? "memory";
    this.storePath = c.store?.path ?? "./.radius/state.db";
    this.storeRequired = c.store?.required ?? false;
  }

  async evaluate(event: GuardEvent): Promise<Decision> {
    const key = event.sessionId;
    const now = Date.now();
    const windowMs = this.windowSec * 1000;

    if (this.storeEngine === "sqlite") {
      const store = getSqliteStateStore({
        path: this.storePath,
        required: this.storeRequired,
      });
      if (store) {
        const result = store.consumeRateBudget({
          bucketKey: key,
          nowMs: now,
          windowMs,
          maxCalls: this.maxCallsPerWindow,
        });
        if (!result.allowed) {
          return this.deny(
            `rate limit exceeded: ${result.count}/${this.maxCallsPerWindow} calls in ${this.windowSec}s window`,
            "high",
          );
        }
        return this.allow(
          `rate ok: ${result.count}/${this.maxCallsPerWindow}`,
        );
      }
    }

    // Get or create window entries
    let entries = this.windows.get(key);
    if (!entries) {
      entries = [];
      this.windows.set(key, entries);
    }

    // Evict expired entries
    const cutoff = now - windowMs;
    const active = entries.filter((e) => e.timestamp > cutoff);

    if (active.length >= this.maxCallsPerWindow) {
      this.windows.set(key, active);
      return this.deny(
        `rate limit exceeded: ${active.length}/${this.maxCallsPerWindow} calls in ${this.windowSec}s window`,
        "high",
      );
    }

    active.push({ timestamp: now });
    this.windows.set(key, active);

    return this.allow(
      `rate ok: ${active.length}/${this.maxCallsPerWindow}`,
    );
  }
}
