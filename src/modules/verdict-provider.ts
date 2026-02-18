import { type Decision, type GuardEvent, GuardPhase } from "../types.js";
import { BaseModule } from "./base.js";

interface ProviderConfig {
	type: string;
	apiKey?: string;
	endpoint?: string;
	categories?: string[];
	headers?: Record<string, string>;
}

interface VerdictProviderConfig {
	enabled?: boolean;
	providers?: ProviderConfig[];
	minConfidence?: number;
	onProviderError?: "alert" | "deny";
	timeoutMs?: number;
}

interface NormalizedVerdict {
	action: "allow" | "deny" | "alert";
	confidence: number;
	category: string;
	provider: string;
	reason?: string;
}

const DEFAULT_ENDPOINTS: Record<string, string> = {
	lakera: "https://api.lakera.ai/v2/guard/results",
	pangea_prompt_guard:
		"https://ai-guard.aws.us.pangea.cloud/v1beta/prompt/guard",
};

/**
 * §9.11 verdict_provider — bridge to external detector providers.
 * Phases: PRE_REQUEST, PRE_TOOL, PRE_RESPONSE
 */
export class VerdictProviderModule extends BaseModule {
	name = "verdict_provider";
	phases = new Set([
		GuardPhase.PRE_REQUEST,
		GuardPhase.PRE_TOOL,
		GuardPhase.PRE_RESPONSE,
	]);

	private enabled = false;
	private providers: ProviderConfig[] = [];
	private minConfidence = 0.9;
	private onProviderError: "alert" | "deny" = "alert";
	private timeoutMs = 3000;

	override configure(config: Record<string, unknown>): void {
		super.configure(config);
		const c = config as unknown as Partial<VerdictProviderConfig>;
		this.enabled = c.enabled ?? false;
		this.providers = c.providers ?? [];
		this.minConfidence = c.minConfidence ?? 0.9;
		this.onProviderError = c.onProviderError ?? "alert";
		this.timeoutMs = c.timeoutMs ?? 3000;
	}

	async evaluate(event: GuardEvent): Promise<Decision> {
		if (!this.enabled || this.providers.length === 0) {
			return this.allow("verdict provider disabled");
		}

		const content = this.extractText(event);
		if (!content) {
			return this.allow("no content for provider evaluation");
		}

		const errors: string[] = [];
		const findings: NormalizedVerdict[] = [];

		for (const provider of this.providers) {
			try {
				const verdict = await this.queryProvider(provider, content, event);
				if (verdict) {
					findings.push(verdict);
				}
			} catch (err) {
				const message = err instanceof Error ? err.message : String(err);
				errors.push(`${provider.type}: ${message}`);
				if (this.onProviderError === "deny") {
					return this.deny(
						`verdict provider error (fail-closed): ${provider.type}: ${message}`,
						"critical",
					);
				}
			}
		}

		const denied = findings.find(
			(f) => f.action === "deny" && f.confidence >= this.minConfidence,
		);
		if (denied) {
			return this.deny(
				`${denied.provider} flagged ${denied.category} (confidence=${denied.confidence.toFixed(2)})`,
				"high",
			);
		}

		const alerting = findings.filter(
			(f) =>
				f.action === "alert" ||
				(f.action === "deny" && f.confidence < this.minConfidence),
		);
		if (alerting.length > 0 || errors.length > 0) {
			const messages = [
				...alerting.map(
					(f) =>
						`${f.provider}:${f.category}:${f.action}@${f.confidence.toFixed(2)}`,
				),
				...errors.map((e) => `error:${e}`),
			];
			return this.alert(`verdict provider findings: ${messages.join(", ")}`, "high");
		}

		return this.allow("no provider findings");
	}

	private extractText(event: GuardEvent): string | undefined {
		switch (event.phase) {
			case GuardPhase.PRE_REQUEST:
				return event.requestText;
			case GuardPhase.PRE_RESPONSE:
				return event.responseText;
			case GuardPhase.PRE_TOOL: {
				if (!event.toolCall) return undefined;
				return JSON.stringify({
					tool: event.toolCall.name,
					arguments: event.toolCall.arguments,
				});
			}
			default:
				return undefined;
		}
	}

	private async queryProvider(
		provider: ProviderConfig,
		text: string,
		event: GuardEvent,
	): Promise<NormalizedVerdict | undefined> {
		const endpoint = provider.endpoint ?? DEFAULT_ENDPOINTS[provider.type];
		if (!endpoint) {
			throw new Error(
				`provider "${provider.type}" requires endpoint (or known provider type)`,
			);
		}

		const controller = new AbortController();
		const timeout = setTimeout(() => controller.abort(), this.timeoutMs);

		try {
			const response = await fetch(endpoint, {
				method: "POST",
				headers: {
					"content-type": "application/json",
					...(provider.apiKey
						? { authorization: `Bearer ${provider.apiKey}` }
						: {}),
					...(provider.headers ?? {}),
				},
				body: JSON.stringify({
					input: text,
					phase: event.phase,
					framework: event.framework,
					tool: event.toolCall?.name,
					categories: provider.categories,
					metadata: event.metadata,
				}),
				signal: controller.signal,
			});

			if (!response.ok) {
				throw new Error(`HTTP ${response.status}`);
			}

			const json = (await response.json()) as Record<string, unknown>;
			const verdict = this.normalizeVerdict(provider.type, json);
			if (!verdict) return undefined;

			if (
				provider.categories &&
				provider.categories.length > 0 &&
				!provider.categories.includes(verdict.category)
			) {
				return undefined;
			}

			return verdict;
		} finally {
			clearTimeout(timeout);
		}
	}

	private normalizeVerdict(
		provider: string,
		raw: Record<string, unknown>,
	): NormalizedVerdict | undefined {
		if (typeof raw.action === "string") {
			const action = raw.action.toLowerCase();
			if (action === "allow" || action === "deny" || action === "alert") {
				return {
					action,
					confidence: this.normalizeConfidence(raw.confidence),
					category:
						typeof raw.category === "string" ? raw.category : "unknown",
					provider,
					reason: typeof raw.reason === "string" ? raw.reason : undefined,
				};
			}
		}

		if (typeof raw.blocked === "boolean") {
			return {
				action: raw.blocked ? "deny" : "allow",
				confidence: this.normalizeConfidence(raw.confidence, raw.blocked ? 1 : 0),
				category: typeof raw.category === "string" ? raw.category : "unknown",
				provider,
				reason: typeof raw.reason === "string" ? raw.reason : undefined,
			};
		}

		if (
			raw.verdict &&
			typeof raw.verdict === "object" &&
			typeof (raw.verdict as Record<string, unknown>).blocked === "boolean"
		) {
			const nested = raw.verdict as Record<string, unknown>;
			return {
				action: nested.blocked ? "deny" : "allow",
				confidence: this.normalizeConfidence(
					nested.confidence,
					nested.blocked ? 1 : 0,
				),
				category:
					typeof nested.category === "string" ? nested.category : "unknown",
				provider,
				reason: typeof nested.reason === "string" ? nested.reason : undefined,
			};
		}

		return undefined;
	}

	private normalizeConfidence(value: unknown, fallback = 0.5): number {
		if (typeof value === "number" && Number.isFinite(value)) {
			if (value < 0) return 0;
			if (value > 1) return 1;
			return value;
		}
		return fallback;
	}
}
