import {
	DecisionAction,
	type Decision,
	type GuardEvent,
	GuardPhase,
} from "../types.js";
import { BaseModule } from "./base.js";

type ArgType = "string" | "number" | "boolean" | "object" | "array";
type EnumValue = string | number | boolean;

interface ToolArgConstraint {
	type?: ArgType;
	pattern?: string;
	minLength?: number;
	maxLength?: number;
	min?: number;
	max?: number;
	enum?: EnumValue[];
}

interface ToolArgSchema {
	requiredArgs?: string[];
	allowedArgs?: string[];
	forbidUnknownArgs?: boolean;
	argConstraints?: Record<string, ToolArgConstraint>;
}

interface ToolEgressBinding {
	allowedDomains?: string[];
	blockedDomains?: string[];
	allowedIPs?: string[];
	blockedIPs?: string[];
	allowedPorts?: number[];
	blockedPorts?: number[];
}

interface ToolRule {
	tool: string;
	action: "allow" | "deny" | "challenge";
	when?: Record<string, unknown>;
	schema?: ToolArgSchema;
	egress?: ToolEgressBinding;
	challenge?: {
		channel?: "orchestrator" | "telegram" | "discord" | "http";
		prompt?: string;
		timeoutSec?: number;
	};
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

				if (rule.schema) {
					const violation = this.validateSchema(args, rule.schema);
					if (violation) {
						return this.deny(
							`tool "${toolName}" denied by schema: ${violation}`,
						);
					}
				}

				if (rule.action === "deny") {
					return this.deny(`tool "${toolName}" denied by policy rule`);
				}
				if (rule.action === "challenge") {
					const channel = rule.challenge?.channel ?? "orchestrator";
					const timeoutSec = Math.max(1, rule.challenge?.timeoutSec ?? 300);
					return {
						action: DecisionAction.CHALLENGE,
						module: this.name,
						reason: `tool "${toolName}" requires approval by policy rule`,
						severity: "high",
						challenge: {
							channel,
							prompt:
								rule.challenge?.prompt ??
								`Approve execution of "${toolName}"?`,
							timeoutSec,
						},
					};
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

	private validateSchema(
		args: Record<string, unknown>,
		schema: ToolArgSchema,
	): string | undefined {
		const requiredArgs = schema.requiredArgs ?? [];
		for (const name of requiredArgs) {
			if (!(name in args)) {
				return `missing required arg "${name}"`;
			}
		}

		let allowedArgs = schema.allowedArgs;
		if (
			(!allowedArgs || allowedArgs.length === 0) &&
			schema.forbidUnknownArgs
		) {
			const inferred = new Set<string>(requiredArgs);
			for (const key of Object.keys(schema.argConstraints ?? {})) {
				inferred.add(key);
			}
			allowedArgs = [...inferred];
		}

		if (allowedArgs && allowedArgs.length > 0) {
			const allowSet = new Set(allowedArgs);
			for (const key of Object.keys(args)) {
				if (!allowSet.has(key)) {
					return `arg "${key}" is not allowlisted`;
				}
			}
		}

		for (const [argName, constraint] of Object.entries(
			schema.argConstraints ?? {},
		)) {
			if (!(argName in args)) continue;

			const value = args[argName];
			const mismatch = this.validateConstraint(argName, value, constraint);
			if (mismatch) return mismatch;
		}

		return undefined;
	}

	private validateConstraint(
		argName: string,
		value: unknown,
		constraint: ToolArgConstraint,
	): string | undefined {
		if (constraint.type && !this.matchesType(value, constraint.type)) {
			return `arg "${argName}" expected type ${constraint.type}`;
		}

		if (constraint.enum && constraint.enum.length > 0) {
			const isAllowed = constraint.enum.some((candidate) =>
				Object.is(candidate, value),
			);
			if (!isAllowed) {
				return `arg "${argName}" must be one of [${constraint.enum.join(", ")}]`;
			}
		}

		if (typeof value === "string") {
			if (constraint.pattern) {
				try {
					const re = new RegExp(constraint.pattern);
					if (!re.test(value)) {
						return `arg "${argName}" does not match required pattern`;
					}
				} catch {
					return `invalid schema pattern for arg "${argName}"`;
				}
			}

			if (
				typeof constraint.minLength === "number" &&
				value.length < constraint.minLength
			) {
				return `arg "${argName}" shorter than minLength=${constraint.minLength}`;
			}
			if (
				typeof constraint.maxLength === "number" &&
				value.length > constraint.maxLength
			) {
				return `arg "${argName}" exceeds maxLength=${constraint.maxLength}`;
			}
		}

		if (typeof value === "number") {
			if (typeof constraint.min === "number" && value < constraint.min) {
				return `arg "${argName}" below min=${constraint.min}`;
			}
			if (typeof constraint.max === "number" && value > constraint.max) {
				return `arg "${argName}" above max=${constraint.max}`;
			}
		}

		return undefined;
	}

	private matchesType(value: unknown, expected: ArgType): boolean {
		switch (expected) {
			case "array":
				return Array.isArray(value);
			case "object":
				return this.isRecord(value);
			case "string":
			case "number":
			case "boolean":
				return typeof value === expected;
		}
	}
}
