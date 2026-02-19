import fs from "node:fs";
import path from "node:path";
import { type Decision, type GuardEvent, GuardPhase } from "../types.js";
import { BaseModule } from "./base.js";

interface TripwireGuardConfig {
	enabled?: boolean;
	fileTokens?: string[];
	envTokens?: string[];
	onTrip?: "deny" | "kill_switch" | "alert";
	killSwitchFilePath?: string;
}

interface FileTokenRule {
	id: string;
	raw: string;
	kind: "exact" | "prefix";
	path: string;
}

interface FileTokenHit {
	rule: FileTokenRule;
	path: string;
}

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
const TOKEN_PATTERN = /(?:[^\s"'`]+|"[^"]*"|'[^']*')+/g;

/**
 * tripwire_guard — optional honeytoken tripwires for deterministic compromise signals.
 * Phase: PRE_TOOL
 *
 * When a configured honeytoken is touched, this module can deny, alert, or
 * trigger kill-switch behavior.
 */
export class TripwireGuardModule extends BaseModule {
	name = "tripwire_guard";
	phases = new Set([GuardPhase.PRE_TOOL]);

	private enabled = true;
	private onTrip: "deny" | "kill_switch" | "alert" = "kill_switch";
	private killSwitchFilePath = path.resolve(".radius/KILL_SWITCH");
	private fileRules: FileTokenRule[] = [];
	private envTokens = new Set<string>();

	override configure(config: Record<string, unknown>): void {
		super.configure(config);
		const c = config as unknown as Partial<TripwireGuardConfig>;
		this.enabled = c.enabled ?? true;
		this.onTrip = c.onTrip ?? "kill_switch";
		this.killSwitchFilePath = this.resolvePath(
			c.killSwitchFilePath ?? ".radius/KILL_SWITCH",
		);
		this.fileRules = this.resolveFileRules(c.fileTokens ?? []);
		this.envTokens = new Set(
			(c.envTokens ?? [])
				.map((name) => name.trim())
				.filter((name) => name.length > 0),
		);
	}

	async evaluate(event: GuardEvent): Promise<Decision> {
		if (!this.enabled) {
			return this.allow("tripwire guard disabled");
		}
		if (this.fileRules.length === 0 && this.envTokens.size === 0) {
			return this.allow("no tripwire tokens configured");
		}

		const toolName = event.toolCall?.name;
		if (!toolName) {
			return this.allow("no tool call");
		}

		const args = event.toolCall?.arguments ?? {};
		const fileHit = this.findFileTokenHit(args);
		if (fileHit) {
			return this.onTripwire(
				`TRIPWIRE_FILE_HIT: tool "${toolName}" touched tripwire path "${fileHit.path}" (token: "${fileHit.rule.raw}")`,
			);
		}

		const envHit = this.findEnvTokenHit(args);
		if (envHit) {
			return this.onTripwire(
				`TRIPWIRE_ENV_HIT: tool "${toolName}" referenced env tripwire "${envHit}"`,
			);
		}

		return this.allow("no tripwire hit");
	}

	private onTripwire(reason: string): Decision {
		if (this.onTrip === "alert") {
			return this.alert(reason, "critical");
		}
		if (this.onTrip === "deny") {
			return this.deny(reason, "critical");
		}

		this.triggerKillSwitch(reason);
		return this.deny(`${reason}; kill switch triggered`, "critical");
	}

	private triggerKillSwitch(reason: string): void {
		try {
			fs.mkdirSync(path.dirname(this.killSwitchFilePath), { recursive: true });
			fs.writeFileSync(
				this.killSwitchFilePath,
				`tripwire_guard kill switch: ${reason}\n`,
				"utf8",
			);
		} catch {
			// Keep deterministic deny even if writing kill switch file fails.
		}
	}

	private findFileTokenHit(args: Record<string, unknown>): FileTokenHit | undefined {
		if (this.fileRules.length === 0) return undefined;

		const candidates = this.collectPathCandidates(args);
		for (const candidate of candidates) {
			const canonicalPath = this.canonicalizeTargetPath(candidate);
			const rule = this.matchFileRule(canonicalPath);
			if (rule) {
				return { rule, path: canonicalPath };
			}
		}

		return undefined;
	}

	private findEnvTokenHit(args: Record<string, unknown>): string | undefined {
		if (this.envTokens.size === 0) return undefined;

		const serialized = this.serializeForSearch(args);
		for (const envToken of this.envTokens) {
			if (serialized.includes(envToken)) {
				return envToken;
			}
		}
		return undefined;
	}

	private serializeForSearch(value: unknown): string {
		try {
			return JSON.stringify(value) ?? "";
		} catch {
			return String(value);
		}
	}

	private collectPathCandidates(args: Record<string, unknown>): string[] {
		const candidates: string[] = [];

		const visit = (value: unknown, key?: string) => {
			if (typeof value === "string") {
				const normalizedKey = key?.toLowerCase();
				if (normalizedKey && PATH_HINT_KEYS.has(normalizedKey)) {
					candidates.push(value);
				}
				if (normalizedKey === "command") {
					for (const token of this.extractCommandPathTokens(value)) {
						candidates.push(token);
					}
				}
				return;
			}

			if (Array.isArray(value)) {
				for (const item of value) {
					visit(item, key);
				}
				return;
			}

			if (this.isRecord(value)) {
				for (const [entryKey, entryValue] of Object.entries(value)) {
					visit(entryValue, entryKey);
				}
			}
		};

		visit(args);

		return [...new Set(candidates)];
	}

	private extractCommandPathTokens(command: string): string[] {
		const tokens = command.match(TOKEN_PATTERN) ?? [];
		const candidates: string[] = [];
		for (const rawToken of tokens) {
			const token = this.cleanToken(rawToken);
			if (!token || token.startsWith("-")) continue;
			if (token.startsWith("~") || token.startsWith("/") || token.includes("/")) {
				candidates.push(token);
			}
		}
		return candidates;
	}

	private cleanToken(token: string): string {
		return token.replace(/^['"]|['"]$/g, "").replace(/[;,]$/, "");
	}

	private resolveFileRules(configured: string[]): FileTokenRule[] {
		const rules = new Map<string, FileTokenRule>();

		for (const rawToken of configured) {
			const trimmed = rawToken.trim();
			if (!trimmed) continue;

			if (trimmed.endsWith("/**")) {
				const root = trimmed.slice(0, -3);
				const canonical = this.canonicalizePolicyPath(root);
				const id = `prefix:${canonical}`;
				rules.set(id, {
					id,
					raw: trimmed,
					kind: "prefix",
					path: canonical,
				});
				continue;
			}

			const canonical = this.canonicalizePolicyPath(trimmed);
			const id = `exact:${canonical}`;
			rules.set(id, {
				id,
				raw: trimmed,
				kind: "exact",
				path: canonical,
			});
		}

		return [...rules.values()];
	}

	private matchFileRule(canonicalPath: string): FileTokenRule | undefined {
		for (const rule of this.fileRules) {
			if (rule.kind === "exact" && canonicalPath === rule.path) {
				return rule;
			}
			if (rule.kind === "prefix" && this.isWithin(canonicalPath, rule.path)) {
				return rule;
			}
		}
		return undefined;
	}

	private resolvePath(rawPath: string): string {
		if (path.isAbsolute(rawPath)) {
			return path.normalize(rawPath);
		}
		return path.resolve(rawPath);
	}

	private canonicalizePolicyPath(p: string): string {
		const absolute = this.expandPath(p);
		try {
			return fs.realpathSync.native(absolute);
		} catch {
			return path.normalize(absolute);
		}
	}

	private canonicalizeTargetPath(p: string): string {
		const absolute = this.expandPath(p);
		return this.realpathWithAncestorFallback(absolute);
	}

	private expandPath(p: string): string {
		const home = process.env.HOME ?? process.env.USERPROFILE ?? "";
		return path.resolve(p.replace(/^~/, home));
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

	private isRecord(value: unknown): value is Record<string, unknown> {
		return typeof value === "object" && value !== null && !Array.isArray(value);
	}

	private isWithin(targetPath: string, basePath: string): boolean {
		const relative = path.relative(basePath, targetPath);
		return (
			relative === "" ||
			(!relative.startsWith("..") && !path.isAbsolute(relative))
		);
	}
}
