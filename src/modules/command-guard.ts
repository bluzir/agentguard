import { type Decision, type GuardEvent, GuardPhase } from "../types.js";
import { BaseModule } from "./base.js";

interface CommandGuardConfig {
	denyPatterns: string[];
	allowPatterns?: string[];
}

const SHELL_TOOLS = new Set(["Bash"]);
const DEFAULT_DENY_PATTERNS = ["(^|\\s)sudo\\s", "rm\\s+-rf\\s+/"];

// Shell command separators for segment-aware scanning
const SEGMENT_SEPARATORS = /\s*(?:&&|\|\||;|\|)\s*/;

/**
 * §9.3 command_guard — shell command policy.
 * Phase: PRE_TOOL
 *
 * Key requirements:
 * - Deny regex list (blocklist).
 * - Optional allow regex list (allowlist mode).
 * - Segment-aware scan for chained commands.
 */
export class CommandGuardModule extends BaseModule {
	name = "command_guard";
	phases = new Set([GuardPhase.PRE_TOOL]);

	private denyPatterns: RegExp[] = DEFAULT_DENY_PATTERNS.map(
		(p) => new RegExp(p, "i"),
	);
	private allowPatterns: RegExp[] | null = null;

	override configure(config: Record<string, unknown>): void {
		super.configure(config);
		const c = config as unknown as Partial<CommandGuardConfig>;

		const denyPatterns =
			c.denyPatterns && c.denyPatterns.length > 0
				? c.denyPatterns
				: DEFAULT_DENY_PATTERNS;
		this.denyPatterns = denyPatterns.map((p) => new RegExp(p, "i"));

		if (c.allowPatterns && c.allowPatterns.length > 0) {
			this.allowPatterns = c.allowPatterns.map((p) => new RegExp(p, "i"));
		} else {
			this.allowPatterns = null;
		}
	}

	async evaluate(event: GuardEvent): Promise<Decision> {
		const toolName = event.toolCall?.name;
		if (!toolName || !SHELL_TOOLS.has(toolName)) {
			return this.allow("not a shell tool");
		}

		const command = event.toolCall?.arguments?.command as string | undefined;
		if (!command) {
			return this.allow("no command in arguments");
		}

		// Split into segments for chained commands
		const segments = command.split(SEGMENT_SEPARATORS).filter(Boolean);

		for (const segment of segments) {
			// Check deny patterns first
			for (const pattern of this.denyPatterns) {
				if (pattern.test(segment)) {
					return this.deny(
						`command segment "${segment}" matches deny pattern ${pattern.source}`,
						"critical",
					);
				}
			}

			// If allowlist mode, every segment must match at least one allow pattern
			if (this.allowPatterns) {
				const allowed = this.allowPatterns.some((p) => p.test(segment));
				if (!allowed) {
					return this.deny(
						`command segment "${segment}" not in allowlist`,
						"high",
					);
				}
			}
		}

		return this.allow("command passed policy checks");
	}
}
