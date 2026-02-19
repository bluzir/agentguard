import net from "node:net";
import { type Decision, type GuardEvent, GuardPhase } from "../types.js";
import { BaseModule } from "./base.js";

interface EgressPolicyInput {
	allowedDomains?: string[];
	blockedDomains?: string[];
	allowedIPs?: string[];
	blockedIPs?: string[];
	allowedPorts?: number[];
	blockedPorts?: number[];
}

interface EgressGuardConfig extends EgressPolicyInput {
	bindingMode?: "intersect" | "global_only";
	toolBindings?: Record<string, EgressPolicyInput>;
}

interface EgressPolicy {
	allowedDomains: string[];
	blockedDomains: string[];
	allowedIPs: string[];
	blockedIPs: string[];
	allowedPorts: number[];
	blockedPorts: number[];
}

interface Endpoint {
	host: string;
	domain?: string;
	ip?: string;
	port?: number;
}

// Tools and command patterns that can make outbound requests.
const NETWORK_TOOLS = new Set(["WebFetch", "WebSearch"]);
const NETWORK_COMMANDS = /\b(curl|wget|nc|ncat|ssh|scp|rsync|ftp|telnet)\b/;
const URL_PATTERN = /https?:\/\/[^\s"'`]+/gi;
const TOKEN_PATTERN = /(?:[^\s"'`]+|"[^"]*"|'[^']*')+/g;
const URL_ARG_KEYS = new Set([
	"url",
	"uri",
	"endpoint",
	"api_url",
	"base_url",
	"webhook_url",
	"webhook",
]);
const HOST_ARG_KEYS = new Set(["host", "hostname", "domain", "address"]);

/**
 * §9.5 egress_guard — outbound network restrictions.
 * Phase: PRE_TOOL
 */
export class EgressGuardModule extends BaseModule {
	name = "egress_guard";
	phases = new Set([GuardPhase.PRE_TOOL]);

	private globalPolicy: EgressPolicy = this.emptyPolicy();
	private bindingMode: "intersect" | "global_only" = "global_only";
	private toolBindings: Record<string, EgressPolicy> = {};

	override configure(config: Record<string, unknown>): void {
		super.configure(config);
		const c = config as unknown as Partial<EgressGuardConfig>;
		this.globalPolicy = this.normalizePolicy(c);
		this.bindingMode = c.bindingMode ?? "global_only";
		this.toolBindings = this.normalizeToolBindings(c.toolBindings);
	}

	async evaluate(event: GuardEvent): Promise<Decision> {
		const toolName = event.toolCall?.name;
		if (!toolName) return this.allow("no tool call");

		const toolBinding = this.resolveToolBinding(toolName);
		const enforceBindings =
			Boolean(toolBinding) && this.bindingMode === "intersect";
		const endpoints = this.extractEndpoints(event, enforceBindings);
		if (
			enforceBindings &&
			endpoints.length === 0
		) {
			return this.deny(
				`EGRESS_TOOL_BINDING_DENY: bound tool "${toolName}" endpoint could not be determined`,
				"high",
			);
		}

		if (endpoints.length === 0) {
			return this.allow("no outbound network detected");
		}

		for (const endpoint of endpoints) {
			const globalBlock = this.findBlockedReason(endpoint, this.globalPolicy);
			if (globalBlock) {
				return this.deny(globalBlock, "high");
			}

			if (enforceBindings && toolBinding) {
				const bindingBlock = this.findBlockedReason(endpoint, toolBinding);
				if (bindingBlock) {
					return this.deny(`EGRESS_TOOL_BINDING_DENY: ${bindingBlock}`, "high");
				}
			}
		}

		for (const endpoint of endpoints) {
			const globalAllowIssue = this.findAllowlistViolation(
				endpoint,
				this.globalPolicy,
			);
			if (globalAllowIssue) {
				return this.deny(globalAllowIssue, "high");
			}

			if (enforceBindings && toolBinding) {
				const bindingAllowIssue = this.findAllowlistViolation(endpoint, toolBinding);
				if (bindingAllowIssue) {
					return this.deny(
						`EGRESS_TOOL_BINDING_DENY: ${bindingAllowIssue}`,
						"high",
					);
				}
			}
		}

		return this.allow("egress allowed");
	}

	private extractEndpoints(event: GuardEvent, includeStructuredArgs = false): Endpoint[] {
		const toolName = event.toolCall?.name;
		if (!toolName) return [];

		const endpoints: Endpoint[] = [];
		const pushEndpoint = (endpoint: Endpoint | undefined) => {
			if (!endpoint) return;
			const exists = endpoints.some(
				(e) =>
					e.host === endpoint.host &&
					e.port === endpoint.port &&
					e.ip === endpoint.ip &&
					e.domain === endpoint.domain,
			);
			if (!exists) {
				endpoints.push(endpoint);
			}
		};

		if (includeStructuredArgs) {
			for (const endpoint of this.extractEndpointsFromArgs(event.toolCall?.arguments)) {
				pushEndpoint(endpoint);
			}
		}

		// Shell tools — scan command for URLs and host-style tokens.
		if (toolName === "Bash") {
			const command = event.toolCall?.arguments?.command as string | undefined;
			if (!command || !NETWORK_COMMANDS.test(command)) {
				return endpoints;
			}

			for (const match of command.matchAll(URL_PATTERN)) {
				pushEndpoint(this.parseUrlToEndpoint(match[0]));
			}

			const tokens = command.match(TOKEN_PATTERN) ?? [];
			const portHint = this.extractPortHint(tokens);

			for (const rawToken of tokens) {
				const token = this.cleanToken(rawToken);
				const endpoint = this.parseHostToken(token, portHint);
				if (endpoint) {
					pushEndpoint(endpoint);
				}
			}
		}

		// Compatibility: keep explicit URL handling for known network tools.
		if (NETWORK_TOOLS.has(toolName)) {
			const url = event.toolCall?.arguments?.url as string | undefined;
			if (typeof url === "string") {
				pushEndpoint(this.parseUrlToEndpoint(url));
			}
		}

		return endpoints;
	}

	private extractEndpointsFromArgs(args: unknown): Endpoint[] {
		if (!this.isRecord(args)) return [];

		const endpoints: Endpoint[] = [];
		const pushEndpoint = (endpoint: Endpoint | undefined) => {
			if (!endpoint) return;
			const exists = endpoints.some(
				(e) =>
					e.host === endpoint.host &&
					e.port === endpoint.port &&
					e.ip === endpoint.ip &&
					e.domain === endpoint.domain,
			);
			if (!exists) {
				endpoints.push(endpoint);
			}
		};

		const visit = (value: unknown) => {
			if (Array.isArray(value)) {
				for (const item of value) visit(item);
				return;
			}
			if (!this.isRecord(value)) return;

			const explicitPort = this.readPort(value.port);
			for (const [key, entry] of Object.entries(value)) {
				if (typeof entry === "string") {
					const normalizedKey = key.toLowerCase();
					if (URL_ARG_KEYS.has(normalizedKey)) {
						pushEndpoint(this.parseUrlToEndpoint(entry));
					}
					if (HOST_ARG_KEYS.has(normalizedKey)) {
						pushEndpoint(this.parseHostToken(entry, explicitPort));
					}
				}

				if (this.isRecord(entry) || Array.isArray(entry)) {
					visit(entry);
				}
			}
		};

		visit(args);
		return endpoints;
	}

	private parseUrlToEndpoint(url: string): Endpoint | undefined {
		try {
			const parsed = new URL(url);
			const host = this.normalizeHost(parsed.hostname);
			if (!host) return undefined;

			const port = parsed.port
				? this.parsePort(parsed.port)
				: this.defaultPortForProtocol(parsed.protocol);
			const ip = this.isIP(host) ? host : undefined;
			const domain = ip ? undefined : host;

			return { host, domain, ip, port };
		} catch {
			return undefined;
		}
	}

	private parseHostToken(
		token: string,
		portHint?: number,
	): Endpoint | undefined {
		if (!token || token.startsWith("-")) return undefined;
		if (/^[a-z][a-z0-9+.-]*:\/\//i.test(token)) {
			return this.parseUrlToEndpoint(token);
		}

		const atHost = token.match(/^[^@\s]+@([^:\s/]+)(?::.*)?$/);
		if (atHost?.[1]) {
			return this.hostToEndpoint(atHost[1], portHint);
		}

		const hostPort = token.match(
			/^([A-Za-z0-9.-]+|\d{1,3}(?:\.\d{1,3}){3}):(\d{1,5})$/,
		);
		if (hostPort?.[1] && hostPort[2]) {
			return this.hostToEndpoint(hostPort[1], this.parsePort(hostPort[2]));
		}

		const scpHost = token.match(/^([A-Za-z0-9.-]+|\d{1,3}(?:\.\d{1,3}){3}):/);
		if (scpHost?.[1]) {
			return this.hostToEndpoint(scpHost[1], portHint);
		}

		if (this.looksLikeHost(token)) {
			return this.hostToEndpoint(token, portHint);
		}

		return undefined;
	}

	private hostToEndpoint(rawHost: string, port?: number): Endpoint | undefined {
		const host = this.normalizeHost(rawHost);
		if (!host) return undefined;
		const ip = this.isIP(host) ? host : undefined;
		const domain = ip ? undefined : host;
		return { host, domain, ip, port };
	}

	private readPort(value: unknown): number | undefined {
		if (typeof value === "number") {
			if (Number.isInteger(value) && value > 0 && value <= 65535) {
				return value;
			}
			return undefined;
		}
		if (typeof value === "string") {
			return this.parsePort(value);
		}
		return undefined;
	}

	private extractPortHint(tokens: string[]): number | undefined {
		for (let i = 0; i < tokens.length; i++) {
			const token = this.cleanToken(tokens[i]);

			if ((token === "-p" || token === "-P") && i + 1 < tokens.length) {
				const parsed = this.parsePort(this.cleanToken(tokens[i + 1]));
				if (parsed != null) return parsed;
			}

			const compact = token.match(/^-(?:p|P)(\d{1,5})$/);
			if (compact?.[1]) {
				const parsed = this.parsePort(compact[1]);
				if (parsed != null) return parsed;
			}
		}
		return undefined;
	}

	private cleanToken(token: string): string {
		return token.replace(/^['"]|['"]$/g, "").replace(/[;,]$/, "");
	}

	private looksLikeHost(token: string): boolean {
		if (this.isIP(token)) return true;
		if (token.includes("/") || token.includes(":")) return false;
		if (!token.includes(".")) return false;
		return /^[a-z0-9.-]+$/i.test(token);
	}

	private findBlockedReason(
		endpoint: Endpoint,
		policy: EgressPolicy,
	): string | undefined {
		if (endpoint.ip && policy.blockedIPs.includes(endpoint.ip)) {
			return `outbound to blocked ip: ${endpoint.ip}`;
		}

		if (
			endpoint.domain &&
			policy.blockedDomains.some((blocked) =>
				this.matchesDomain(endpoint.domain as string, blocked),
			)
		) {
			return `outbound to blocked domain: ${endpoint.domain}`;
		}

		if (endpoint.port != null && policy.blockedPorts.includes(endpoint.port)) {
			return `outbound to blocked port: ${endpoint.port}`;
		}

		return undefined;
	}

	private findAllowlistViolation(
		endpoint: Endpoint,
		policy: EgressPolicy,
	): string | undefined {
		if (policy.allowedDomains.length > 0 || policy.allowedIPs.length > 0) {
			const hostAllowed =
				(endpoint.domain &&
					policy.allowedDomains.some((allowed) =>
						this.matchesDomain(endpoint.domain as string, allowed),
					)) ||
				(endpoint.ip && policy.allowedIPs.includes(endpoint.ip));

			if (!hostAllowed) {
				return `outbound host not allowlisted: ${endpoint.host}`;
			}
		}

		if (policy.allowedPorts.length > 0) {
			if (endpoint.port == null) {
				return `outbound port unknown for host: ${endpoint.host}`;
			}

			if (!policy.allowedPorts.includes(endpoint.port)) {
				return `outbound to non-allowlisted port: ${endpoint.port}`;
			}
		}

		return undefined;
	}

	private resolveToolBinding(toolName: string): EgressPolicy | undefined {
		return this.toolBindings[toolName] ?? this.toolBindings["*"];
	}

	private normalizeToolBindings(
		bindings: Record<string, EgressPolicyInput> | undefined,
	): Record<string, EgressPolicy> {
		if (!bindings) return {};

		const normalized: Record<string, EgressPolicy> = {};
		for (const [tool, policy] of Object.entries(bindings)) {
			if (!tool.trim() || !this.isRecord(policy)) continue;
			normalized[tool] = this.normalizePolicy(policy);
		}
		return normalized;
	}

	private normalizePolicy(policy: Partial<EgressPolicyInput>): EgressPolicy {
		return {
			allowedDomains: this.normalizeDomains(policy.allowedDomains),
			blockedDomains: this.normalizeDomains(policy.blockedDomains),
			allowedIPs: this.normalizeIPs(policy.allowedIPs),
			blockedIPs: this.normalizeIPs(policy.blockedIPs),
			allowedPorts: this.normalizePorts(policy.allowedPorts),
			blockedPorts: this.normalizePorts(policy.blockedPorts),
		};
	}

	private emptyPolicy(): EgressPolicy {
		return {
			allowedDomains: [],
			blockedDomains: [],
			allowedIPs: [],
			blockedIPs: [],
			allowedPorts: [],
			blockedPorts: [],
		};
	}

	private normalizeDomains(domains: string[] | undefined): string[] {
		return [
			...new Set(
				(domains ?? []).map((d) => this.normalizeHost(d)).filter(Boolean),
			),
		] as string[];
	}

	private normalizeHost(host: string): string {
		return host.trim().toLowerCase().replace(/\.$/, "");
	}

	private normalizeIPs(ips: string[] | undefined): string[] {
		return [...new Set((ips ?? []).filter((ip) => this.isIP(ip)))];
	}

	private normalizePorts(ports: number[] | undefined): number[] {
		return [
			...new Set(
				(ports ?? []).filter((p) => Number.isInteger(p) && p > 0 && p <= 65535),
			),
		];
	}

	private parsePort(value: string): number | undefined {
		const parsed = Number.parseInt(value, 10);
		if (Number.isNaN(parsed) || parsed < 1 || parsed > 65535) {
			return undefined;
		}
		return parsed;
	}

	private defaultPortForProtocol(protocol: string): number | undefined {
		if (protocol === "https:") return 443;
		if (protocol === "http:") return 80;
		return undefined;
	}

	private matchesDomain(domain: string, candidate: string): boolean {
		if (candidate.startsWith("*.")) {
			const base = candidate.slice(2);
			if (!base) return false;
			// "*.example.com" matches subdomains, but not the root domain itself.
			return domain.endsWith(`.${base}`);
		}
		return domain === candidate || domain.endsWith(`.${candidate}`);
	}

	private isIP(value: string): boolean {
		return net.isIP(value) !== 0;
	}

	private isRecord(value: unknown): value is Record<string, unknown> {
		return value !== null && typeof value === "object" && !Array.isArray(value);
	}
}
