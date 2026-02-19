import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import {
	DecisionAction,
	type Decision,
	type GuardEvent,
	GuardPhase,
} from "../types.js";
import { BaseModule } from "./base.js";

interface UnlockConfig {
	mode?: "disabled" | "token_file";
	filePath?: string;
	ttlSec?: number;
}

interface SelfDefenseConfig {
	enabled?: boolean;
	immutablePaths?: string[];
	includeDiscoveredConfig?: boolean;
	includeHookArtifacts?: boolean;
	monitorHashes?: boolean;
	onWriteAttempt?: "deny" | "challenge";
	onHashMismatch?: "kill_switch" | "deny";
	killSwitchFilePath?: string;
	unlock?: UnlockConfig;
}

interface ImmutableRule {
	id: string;
	raw: string;
	kind: "exact" | "prefix";
	path: string;
}

interface DigestMismatch {
	rule: ImmutableRule;
	expected: string;
	actual: string;
}

const MUTATING_TOOLS = new Set([
	"Write",
	"Edit",
	"NotebookEdit",
	"MultiEdit",
	"Delete",
	"Move",
	"Copy",
	"Rename",
	"Chmod",
	"Chown",
]);

const PATH_HINT_KEYS = new Set([
	"path",
	"file",
	"file_path",
	"notebook_path",
	"destination",
	"destination_path",
	"dest",
	"target",
	"target_path",
	"new_path",
	"to",
	"output_path",
]);

const KNOWN_CONFIG_FILES = ["radius.yaml", "radius.yml", ".radius.yaml"];

const KNOWN_HOOK_FILES = [
	".radius/openclaw-hook.command.sh",
	".radius/openclaw-hooks.json",
	".radius/claude-tool-hook.command.sh",
	".radius/claude-telegram.module.yaml",
	".radius/nanobot-hook.command.sh",
	".radius/nanobot-hooks.json",
];

function sha256(input: string | Buffer): string {
	return crypto.createHash("sha256").update(input).digest("hex");
}

/**
 * self_defense — immutable policy and control-plane tamper checks.
 *
 * Phase behavior:
 * - PRE_TOOL: block writes/edits/deletes targeting immutable paths.
 * - PRE_REQUEST + POST_TOOL: verify immutable digest baseline.
 */
export class SelfDefenseModule extends BaseModule {
	name = "self_defense";
	phases = new Set([
		GuardPhase.PRE_REQUEST,
		GuardPhase.PRE_TOOL,
		GuardPhase.POST_TOOL,
	]);

	private enabled = true;
	private includeDiscoveredConfig = true;
	private includeHookArtifacts = true;
	private monitorHashes = true;
	private onWriteAttempt: "deny" | "challenge" = "deny";
	private onHashMismatch: "kill_switch" | "deny" = "kill_switch";
	private killSwitchFilePath = path.resolve(".radius/KILL_SWITCH");
	private unlockMode: "disabled" | "token_file" = "disabled";
	private unlockFilePath = path.resolve(".radius/UNLOCK");
	private unlockTtlSec = 300;

	private immutableRules: ImmutableRule[] = [];
	private baselineDigests = new Map<string, string>();

	override configure(config: Record<string, unknown>): void {
		super.configure(config);
		const c = config as unknown as Partial<SelfDefenseConfig>;

		this.enabled = c.enabled ?? true;
		this.includeDiscoveredConfig = c.includeDiscoveredConfig ?? true;
		this.includeHookArtifacts = c.includeHookArtifacts ?? true;
		this.monitorHashes = c.monitorHashes ?? true;
		this.onWriteAttempt = c.onWriteAttempt ?? "deny";
		this.onHashMismatch = c.onHashMismatch ?? "kill_switch";
		this.killSwitchFilePath = this.resolvePath(
			c.killSwitchFilePath ?? ".radius/KILL_SWITCH",
		);

		this.unlockMode = c.unlock?.mode ?? "disabled";
		this.unlockFilePath = this.resolvePath(c.unlock?.filePath ?? ".radius/UNLOCK");
		this.unlockTtlSec = Math.max(1, c.unlock?.ttlSec ?? 300);

		this.immutableRules = this.resolveImmutableRules(c);
		this.baselineDigests = this.captureDigests();
	}

	async evaluate(event: GuardEvent): Promise<Decision> {
		if (!this.enabled) {
			return this.allow("self_defense disabled");
		}

		if (this.immutableRules.length === 0) {
			return this.allow("no immutable targets configured");
		}

		if (this.isUnlockActive()) {
			return this.allow("self_defense unlock active");
		}

		if (event.phase === GuardPhase.PRE_TOOL) {
			return this.evaluateMutationAttempt(event);
		}

		if (
			this.monitorHashes &&
			(event.phase === GuardPhase.PRE_REQUEST ||
				event.phase === GuardPhase.POST_TOOL)
		) {
			const mismatch = this.findDigestMismatch();
			if (mismatch) {
				return this.handleHashMismatch(mismatch);
			}
		}

		return this.allow("self_defense checks passed");
	}

	private evaluateMutationAttempt(event: GuardEvent): Decision {
		const toolName = event.toolCall?.name;
		if (!toolName || !MUTATING_TOOLS.has(toolName)) {
			return this.allow("not a mutating tool");
		}

		const candidatePaths = this.collectPathCandidates(event.toolCall?.arguments ?? {});
		if (candidatePaths.length === 0) {
			return this.allow("no candidate paths in mutating tool arguments");
		}

		for (const candidate of candidatePaths) {
			const canonicalPath = this.canonicalizeTargetPath(candidate);
			const matched = this.matchImmutableRule(canonicalPath);
			if (!matched) continue;

			const reason = `SELF_DEFENSE_IMMUTABLE_WRITE: tool "${toolName}" attempted to mutate immutable path "${canonicalPath}" (rule: "${matched.raw}")`;
			if (this.onWriteAttempt === "challenge") {
				return {
					action: DecisionAction.CHALLENGE,
					module: this.name,
					reason,
					severity: "high",
					challenge: {
						channel: "orchestrator",
						prompt: reason,
						timeoutSec: 60,
					},
				};
			}

			return this.deny(reason, "critical");
		}

		return this.allow("mutable target does not overlap immutable paths");
	}

	private findDigestMismatch(): DigestMismatch | undefined {
		const current = this.captureDigests();

		for (const rule of this.immutableRules) {
			const expected = this.baselineDigests.get(rule.id) ?? "__unset__";
			const actual = current.get(rule.id) ?? "__unset__";
			if (expected !== actual) {
				return { rule, expected, actual };
			}
		}

		return undefined;
	}

	private handleHashMismatch(mismatch: DigestMismatch): Decision {
		const baseReason = `SELF_DEFENSE_HASH_MISMATCH: immutable scope changed for "${mismatch.rule.raw}"`;
		if (this.onHashMismatch === "kill_switch") {
			this.triggerKillSwitch(baseReason);
			return this.deny(`${baseReason}; kill switch triggered`, "critical");
		}
		return this.deny(baseReason, "critical");
	}

	private triggerKillSwitch(reason: string): void {
		try {
			fs.mkdirSync(path.dirname(this.killSwitchFilePath), { recursive: true });
			fs.writeFileSync(
				this.killSwitchFilePath,
				`self_defense kill switch: ${reason}\n`,
				"utf8",
			);
		} catch {
			// Keep deterministic deny even when kill switch file cannot be written.
		}
	}

	private isUnlockActive(): boolean {
		if (this.unlockMode !== "token_file") {
			return false;
		}

		try {
			const stat = fs.statSync(this.unlockFilePath);
			const ageSec = (Date.now() - stat.mtimeMs) / 1000;
			return ageSec <= this.unlockTtlSec;
		} catch {
			return false;
		}
	}

	private resolveImmutableRules(config: Partial<SelfDefenseConfig>): ImmutableRule[] {
		const rawPaths = new Set<string>(config.immutablePaths ?? []);

		if (this.includeDiscoveredConfig) {
			const discovered = this.discoverConfigFiles();
			for (const p of discovered) rawPaths.add(p);
		}

		if (this.includeHookArtifacts) {
			const hooks = this.discoverHookArtifacts();
			for (const p of hooks) rawPaths.add(p);
		}

		const rules: ImmutableRule[] = [];
		for (const rawPath of rawPaths) {
			const trimmed = rawPath.trim();
			if (!trimmed) continue;

			if (trimmed.endsWith("/**")) {
				const root = trimmed.slice(0, -3);
				const canonical = this.canonicalizePolicyPath(root);
				const id = `prefix:${canonical}`;
				rules.push({ id, raw: trimmed, kind: "prefix", path: canonical });
				continue;
			}

			const canonical = this.canonicalizePolicyPath(trimmed);
			const id = `exact:${canonical}`;
			rules.push({ id, raw: trimmed, kind: "exact", path: canonical });
		}

		const deduped = new Map<string, ImmutableRule>();
		for (const rule of rules) {
			deduped.set(rule.id, rule);
		}

		return [...deduped.values()];
	}

	private discoverConfigFiles(): string[] {
		const discovered: string[] = [];
		for (const fileName of KNOWN_CONFIG_FILES) {
			const absolute = path.resolve(fileName);
			if (fs.existsSync(absolute)) {
				discovered.push(absolute);
			}
		}
		return discovered;
	}

	private discoverHookArtifacts(): string[] {
		const discovered: string[] = [];
		for (const fileName of KNOWN_HOOK_FILES) {
			const absolute = path.resolve(fileName);
			if (fs.existsSync(absolute)) {
				discovered.push(absolute);
			}
		}
		return discovered;
	}

	private captureDigests(): Map<string, string> {
		const digests = new Map<string, string>();
		for (const rule of this.immutableRules) {
			if (rule.kind === "exact") {
				digests.set(rule.id, this.hashExactPath(rule.path));
			} else {
				digests.set(rule.id, this.hashPrefix(rule.path));
			}
		}
		return digests;
	}

	private hashExactPath(targetPath: string): string {
		if (!fs.existsSync(targetPath)) return "missing";

		const stat = fs.lstatSync(targetPath);
		if (stat.isDirectory()) {
			return this.hashPrefix(targetPath);
		}
		if (!stat.isFile()) {
			return `special:${stat.mode}:${stat.size}`;
		}

		const content = fs.readFileSync(targetPath);
		return `file:${sha256(content)}`;
	}

	private hashPrefix(rootPath: string): string {
		if (!fs.existsSync(rootPath)) return "missing";

		const rootStat = fs.lstatSync(rootPath);
		if (!rootStat.isDirectory()) {
			return this.hashExactPath(rootPath);
		}

		const lines: string[] = [];
		const walk = (dir: string) => {
			const entries = fs.readdirSync(dir, { withFileTypes: true });
			entries.sort((a, b) => a.name.localeCompare(b.name));

			for (const entry of entries) {
				const absolute = path.join(dir, entry.name);
				const relative = path.relative(rootPath, absolute);
				const stat = fs.lstatSync(absolute);

				if (entry.isDirectory()) {
					lines.push(`dir:${relative}`);
					walk(absolute);
					continue;
				}

				if (entry.isFile()) {
					const digest = sha256(fs.readFileSync(absolute));
					lines.push(`file:${relative}:${digest}`);
					continue;
				}

				lines.push(`special:${relative}:${stat.mode}:${stat.size}`);
			}
		};

		walk(rootPath);
		return `prefix:${sha256(lines.join("\n"))}`;
	}

	private collectPathCandidates(
		value: unknown,
		keyHint?: string,
	): string[] {
		if (typeof value === "string") {
			if (keyHint && this.looksLikePathKey(keyHint)) {
				return [value];
			}
			return [];
		}

		if (Array.isArray(value)) {
			const out: string[] = [];
			for (const item of value) {
				out.push(...this.collectPathCandidates(item, keyHint));
			}
			return out;
		}

		if (!this.isRecord(value)) {
			return [];
		}

		const out: string[] = [];
		for (const [key, child] of Object.entries(value)) {
			out.push(...this.collectPathCandidates(child, key));
		}
		return out;
	}

	private looksLikePathKey(key: string): boolean {
		const normalized = key.trim().toLowerCase();
		if (PATH_HINT_KEYS.has(normalized)) return true;
		return normalized.includes("path");
	}

	private matchImmutableRule(canonicalPath: string): ImmutableRule | undefined {
		for (const rule of this.immutableRules) {
			if (rule.kind === "exact") {
				if (canonicalPath === rule.path) return rule;
				continue;
			}

			if (this.isWithin(canonicalPath, rule.path)) {
				return rule;
			}
		}

		return undefined;
	}

	private expandPath(p: string): string {
		const home = process.env.HOME ?? process.env.USERPROFILE ?? "";
		return path.resolve(p.replace(/^~/, home));
	}

	private resolvePath(p: string): string {
		return path.resolve(this.expandPath(p));
	}

	private canonicalizePolicyPath(p: string): string {
		const absolute = this.resolvePath(p);
		try {
			return fs.realpathSync.native(absolute);
		} catch {
			return path.normalize(absolute);
		}
	}

	private canonicalizeTargetPath(p: string): string {
		const absolute = this.resolvePath(p);
		return this.realpathWithAncestorFallback(absolute);
	}

	private realpathWithAncestorFallback(absolutePath: string): string {
		const missingSegments: string[] = [];
		let current = absolutePath;

		while (true) {
			try {
				const resolved = fs.realpathSync.native(current);
				if (missingSegments.length === 0) {
					return resolved;
				}

				let rebuilt = resolved;
				for (let i = missingSegments.length - 1; i >= 0; i--) {
					rebuilt = path.join(rebuilt, missingSegments[i]);
				}
				return path.normalize(rebuilt);
			} catch {
				const parent = path.dirname(current);
				if (parent === current) {
					return path.normalize(absolutePath);
				}
				missingSegments.push(path.basename(current));
				current = parent;
			}
		}
	}

	private isWithin(targetPath: string, basePath: string): boolean {
		const relative = path.relative(basePath, targetPath);
		return (
			relative === "" ||
			(!relative.startsWith("..") && !path.isAbsolute(relative))
		);
	}

	private isRecord(value: unknown): value is Record<string, unknown> {
		return value !== null && typeof value === "object" && !Array.isArray(value);
	}
}

