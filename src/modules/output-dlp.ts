import { type Decision, type GuardEvent, GuardPhase } from "../types.js";
import { BaseModule } from "./base.js";

interface OutputDlpConfig {
	action: "redact" | "alert" | "deny";
	customPatterns?: string[];
	knownSecrets?: string[];
}

// Built-in regex signatures for common secret patterns
const SECRET_PATTERNS: Array<{ name: string; pattern: RegExp }> = [
	{ name: "AWS Access Key", pattern: /AKIA[0-9A-Z]{16}/ },
	{ name: "AWS Secret Key", pattern: /[0-9a-zA-Z/+]{40}/ },
	{ name: "GitHub Token", pattern: /gh[ps]_[A-Za-z0-9_]{36,}/ },
	{
		name: "Generic API Key",
		pattern: /(?:api[_-]?key|apikey)\s*[:=]\s*["']?[A-Za-z0-9\-_.]{20,}["']?/i,
	},
	{ name: "Bearer Token", pattern: /Bearer\s+[A-Za-z0-9\-_.~+/]+=*/i },
	{
		name: "Private Key",
		pattern: /-----BEGIN (?:RSA |EC |DSA )?PRIVATE KEY-----/,
	},
	{ name: "Slack Token", pattern: /xox[bpors]-[0-9]{10,}-[A-Za-z0-9-]+/ },
	{
		name: "Generic Secret",
		pattern: /(?:secret|password|passwd|token)\s*[:=]\s*["']?[^\s"']{8,}["']?/i,
	},
];

const REDACT_PLACEHOLDER = "[REDACTED]";

function ensureGlobal(pattern: RegExp): RegExp {
	const flags = pattern.flags.includes("g")
		? pattern.flags
		: `${pattern.flags}g`;
	return new RegExp(pattern.source, flags);
}

/**
 * §9.6 output_dlp — detect and redact secrets in tool outputs and responses.
 * Phases: POST_TOOL, PRE_RESPONSE
 */
export class OutputDlpModule extends BaseModule {
	name = "output_dlp";
	phases = new Set([GuardPhase.POST_TOOL, GuardPhase.PRE_RESPONSE]);

	private dlpAction: "redact" | "alert" | "deny" = "redact";
	private customPatterns: RegExp[] = [];
	private knownSecrets: string[] = [];

	override configure(config: Record<string, unknown>): void {
		super.configure(config);
		const c = config as unknown as Partial<OutputDlpConfig>;
		this.dlpAction = c.action ?? "redact";
		this.customPatterns = (c.customPatterns ?? []).map(
			(p) => new RegExp(p, "gi"),
		);
		this.knownSecrets = c.knownSecrets ?? [];
	}

	async evaluate(event: GuardEvent): Promise<Decision> {
		const text = this.getTextToScan(event);
		if (!text) {
			return this.allow("no text to scan");
		}

		const findings = this.scan(text);
		if (findings.length === 0) {
			return this.allow("no secrets detected");
		}

		const summary = findings.map((f) => f.name).join(", ");

		switch (this.dlpAction) {
			case "deny":
				return this.deny(
					`secret(s) detected in output: ${summary}`,
					"critical",
				);

			case "alert":
				return this.alert(`secret(s) detected in output: ${summary}`, "high");

			case "redact": {
				let redacted = text;
				for (const finding of findings) {
					redacted = redacted.replace(finding.match, REDACT_PLACEHOLDER);
				}

				const patch =
					event.phase === GuardPhase.POST_TOOL
						? { toolResultText: redacted }
						: { responseText: redacted };

				return this.modify(`redacted secret(s): ${summary}`, patch);
			}
		}
	}

	private getTextToScan(event: GuardEvent): string | undefined {
		if (event.phase === GuardPhase.POST_TOOL) {
			return event.toolResult?.text;
		}
		if (event.phase === GuardPhase.PRE_RESPONSE) {
			return event.responseText;
		}
		return undefined;
	}

	private scan(text: string): Array<{ name: string; match: string }> {
		const findings: Array<{ name: string; match: string }> = [];

		// Check known secrets (exact match)
		for (const secret of this.knownSecrets) {
			if (text.includes(secret)) {
				findings.push({ name: "Known Secret", match: secret });
			}
		}

		// Check built-in patterns
		for (const { name, pattern } of SECRET_PATTERNS) {
			const re = ensureGlobal(pattern);
			while (true) {
				const match = re.exec(text);
				if (match === null) break;
				findings.push({ name, match: match[0] });
			}
		}

		// Check custom patterns
		for (const pattern of this.customPatterns) {
			const re = ensureGlobal(pattern);
			while (true) {
				const match = re.exec(text);
				if (match === null) break;
				findings.push({ name: "Custom Pattern", match: match[0] });
			}
		}

		return findings;
	}
}
