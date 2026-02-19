import crypto from "node:crypto";
import { getSqliteStateStore } from "../state/sqlite.js";
import { type Decision, type GuardEvent, GuardPhase } from "../types.js";
import { BaseModule } from "./base.js";

interface RepetitionStoreConfig {
	engine?: "memory" | "sqlite";
	path?: string;
	required?: boolean;
}

interface RepetitionGuardConfig {
	enabled?: boolean;
	threshold?: number;
	cooldownSec?: number;
	onRepeat?: "deny" | "alert";
	store?: RepetitionStoreConfig;
}

interface RepetitionEntry {
	fingerprint: string;
	count: number;
	lastSeenMs: number;
}

/**
 * repetition_guard — blocks identical tool calls repeated in a short window.
 * Phase: PRE_TOOL
 *
 * This is a deterministic loop detector for runaway/stuck agent behavior.
 */
export class RepetitionGuardModule extends BaseModule {
	name = "repetition_guard";
	phases = new Set([GuardPhase.PRE_TOOL]);

	private enabled = true;
	private threshold = 3;
	private cooldownSec = 60;
	private onRepeat: "deny" | "alert" = "deny";

	private storeEngine: "memory" | "sqlite" = "memory";
	private storePath = "./.radius/state.db";
	private storeRequired = false;

	private entries = new Map<string, RepetitionEntry>();

	override configure(config: Record<string, unknown>): void {
		super.configure(config);
		const c = config as unknown as Partial<RepetitionGuardConfig>;
		this.enabled = c.enabled ?? true;
		this.threshold = Math.max(2, c.threshold ?? 3);
		this.cooldownSec = Math.max(1, c.cooldownSec ?? 60);
		this.onRepeat = c.onRepeat ?? "deny";
		this.storeEngine = c.store?.engine ?? "memory";
		this.storePath = c.store?.path ?? "./.radius/state.db";
		this.storeRequired = c.store?.required ?? false;
	}

	async evaluate(event: GuardEvent): Promise<Decision> {
		if (!this.enabled) {
			return this.allow("repetition guard disabled");
		}

		const toolName = event.toolCall?.name;
		if (!toolName) {
			return this.allow("no tool call");
		}

		const toolArguments = event.toolCall?.arguments ?? {};
		const bucketKey = this.bucketKey(event);
		const fingerprint = this.fingerprintFor(toolName, toolArguments);
		const nowMs = Date.now();
		const cooldownMs = this.cooldownSec * 1000;

		const count =
			this.storeEngine === "sqlite"
				? this.consumeSqlite(bucketKey, fingerprint, nowMs, cooldownMs)
				: this.consumeMemory(bucketKey, fingerprint, nowMs, cooldownMs);

		if (count >= this.threshold) {
			const reason = `REPETITION_GUARD_TRIGGER: tool "${toolName}" called with identical arguments ${count} times in a row`;
			if (this.onRepeat === "alert") {
				return this.alert(reason, "high");
			}
			return this.deny(reason, "high");
		}

		return this.allow(`repetition ok: ${count}/${this.threshold - 1}`);
	}

	private consumeSqlite(
		bucketKey: string,
		fingerprint: string,
		nowMs: number,
		cooldownMs: number,
	): number {
		const store = getSqliteStateStore({
			path: this.storePath,
			required: this.storeRequired,
		});
		if (!store) {
			return this.consumeMemory(bucketKey, fingerprint, nowMs, cooldownMs);
		}
		return store.consumeRepetition({
			bucketKey,
			fingerprint,
			nowMs,
			cooldownMs,
		}).count;
	}

	private consumeMemory(
		bucketKey: string,
		fingerprint: string,
		nowMs: number,
		cooldownMs: number,
	): number {
		const entry = this.entries.get(bucketKey);
		if (!entry) {
			this.entries.set(bucketKey, {
				fingerprint,
				count: 1,
				lastSeenMs: nowMs,
			});
			return 1;
		}

		const withinCooldown = nowMs - entry.lastSeenMs <= cooldownMs;
		const sameFingerprint = entry.fingerprint === fingerprint;
		const nextCount = sameFingerprint && withinCooldown ? entry.count + 1 : 1;

		this.entries.set(bucketKey, {
			fingerprint,
			count: nextCount,
			lastSeenMs: nowMs,
		});
		return nextCount;
	}

	private bucketKey(event: GuardEvent): string {
		return [
			event.framework,
			event.sessionId,
			event.agentName ?? "",
			event.userId ?? "",
		].join("|");
	}

	private fingerprintFor(
		toolName: string,
		argumentsObject: Record<string, unknown>,
	): string {
		const canonical = `${toolName}:${this.stableSerialize(argumentsObject)}`;
		return crypto.createHash("sha256").update(canonical).digest("hex");
	}

	private stableSerialize(value: unknown): string {
		const seen = new WeakSet<object>();
		return this.serializeValue(value, seen);
	}

	private serializeValue(value: unknown, seen: WeakSet<object>): string {
		if (value === null) return "null";
		const valueType = typeof value;
		if (valueType === "string") return JSON.stringify(value);
		if (valueType === "number" || valueType === "boolean") {
			return JSON.stringify(value);
		}
		if (valueType !== "object") {
			return JSON.stringify(String(value));
		}

		if (Array.isArray(value)) {
			return `[${value.map((v) => this.serializeValue(v, seen)).join(",")}]`;
		}

		const record = value as Record<string, unknown>;
		if (seen.has(record)) {
			return '"[Circular]"';
		}
		seen.add(record);

		const keys = Object.keys(record).sort();
		const parts: string[] = [];
		for (const key of keys) {
			parts.push(
				`${JSON.stringify(key)}:${this.serializeValue(record[key], seen)}`,
			);
		}

		seen.delete(record);
		return `{${parts.join(",")}}`;
	}
}
