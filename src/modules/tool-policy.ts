import { type Decision, type GuardEvent, GuardPhase } from "../types.js";
import { BaseModule } from "./base.js";

interface ToolRule {
	tool: string;
	action: "allow" | "deny";
	when?: Record<string, unknown>;
}

interface ToolPolicyConfig {
	default: "allow" | "deny";
	rules: ToolRule[];
}

/**
 * §9.1 tool_policy — explicit allow/deny by tool name and optional argument predicates.
 * Phase: PRE_TOOL
 */
export class ToolPolicyModule extends BaseModule {
	name = "tool_policy";
	phases = new Set([GuardPhase.PRE_TOOL]);

	private policyDefault: "allow" | "deny" = "deny";
	private rules: ToolRule[] = [];

	override configure(config: Record<string, unknown>): void {
		super.configure(config);
		const c = config as unknown as Partial<ToolPolicyConfig>;
		this.policyDefault = c.default ?? "deny";
		this.rules = c.rules ?? [];
	}

	async evaluate(event: GuardEvent): Promise<Decision> {
		const toolName = event.toolCall?.name;
		if (!toolName) {
			return this.allow("no tool call in event");
		}
		const args = event.toolCall?.arguments ?? {};

		// Check rules in order, first match wins
		for (const rule of this.rules) {
			if (rule.tool === toolName || rule.tool === "*") {
				if (rule.when && !this.matchesWhere(args, rule.when)) {
					continue;
				}

				if (rule.action === "deny") {
					return this.deny(`tool "${toolName}" denied by policy rule`);
				}
				return this.allow(`tool "${toolName}" allowed by policy rule`);
			}
		}

		// Fall through to default
		if (this.policyDefault === "deny") {
			return this.deny(`tool "${toolName}" denied by default policy`);
		}
		return this.allow(`tool "${toolName}" allowed by default policy`);
	}

	private matchesWhere(
		args: Record<string, unknown>,
		when: Record<string, unknown>,
	): boolean {
		return this.matchesValue(args, when);
	}

	private matchesValue(actual: unknown, expected: unknown): boolean {
		if (this.isRecord(expected)) {
			if (!this.isRecord(actual)) {
				return false;
			}

			for (const [key, value] of Object.entries(expected)) {
				if (!this.matchesValue(actual[key], value)) {
					return false;
				}
			}
			return true;
		}

		if (Array.isArray(expected)) {
			if (!Array.isArray(actual) || actual.length !== expected.length) {
				return false;
			}
			for (let i = 0; i < expected.length; i++) {
				if (!this.matchesValue(actual[i], expected[i])) {
					return false;
				}
			}
			return true;
		}

		return Object.is(actual, expected);
	}

	private isRecord(value: unknown): value is Record<string, unknown> {
		return typeof value === "object" && value !== null && !Array.isArray(value);
	}
}
