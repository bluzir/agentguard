import net from "node:net";
import { type Decision, type GuardEvent, GuardPhase } from "../types.js";
import { BaseModule } from "./base.js";

interface EgressGuardConfig {
	allowedDomains?: string[];
	blockedDomains?: string[];
	allowedIPs?: string[];
	blockedIPs?: string[];
	allowedPorts?: number[];
	blockedPorts?: number[];
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

/**
 * §9.5 egress_guard — outbound network restrictions.
 * Phase: PRE_TOOL
 */
export class EgressGuardModule extends BaseModule {
	name = "egress_guard";
	phases = new Set([GuardPhase.PRE_TOOL]);

	private allowedDomains: string[] = [];
	private blockedDomains: string[] = [];
	private allowedIPs: string[] = [];
	private blockedIPs: string[] = [];
	private allowedPorts: number[] = [];
	private blockedPorts: number[] = [];

	override configure(config: Record<string, unknown>): void {
		super.configure(config);
		const c = config as unknown as Partial<EgressGuardConfig>;
		this.allowedDomains = this.normalizeDomains(c.allowedDomains);
		this.blockedDomains = this.normalizeDomains(c.blockedDomains);
		this.allowedIPs = this.normalizeIPs(c.allowedIPs);
		this.blockedIPs = this.normalizeIPs(c.blockedIPs);
		this.allowedPorts = this.normalizePorts(c.allowedPorts);
		this.blockedPorts = this.normalizePorts(c.blockedPorts);
	}

	async evaluate(event: GuardEvent): Promise<Decision> {
		const toolName = event.toolCall?.name;
		if (!toolName) return this.allow("no tool call");

		const endpoints = this.extractEndpoints(event);
		if (endpoints.length === 0) {
			return this.allow("no outbound network detected");
		}

		// Blocked lists first.
		for (const endpoint of endpoints) {
			if (endpoint.ip && this.blockedIPs.includes(endpoint.ip)) {
				return this.deny(`outbound to blocked ip: ${endpoint.ip}`, "high");
			}

			if (
				endpoint.domain &&
				this.blockedDomains.some((blocked) =>
					this.matchesDomain(endpoint.domain as string, blocked),
				)
			) {
				return this.deny(
					`outbound to blocked domain: ${endpoint.domain}`,
					"high",
				);
			}

			if (endpoint.port != null && this.blockedPorts.includes(endpoint.port)) {
				return this.deny(`outbound to blocked port: ${endpoint.port}`, "high");
			}
		}

		// Allowlist checks.
		for (const endpoint of endpoints) {
			if (this.allowedDomains.length > 0 || this.allowedIPs.length > 0) {
				const hostAllowed =
					(endpoint.domain &&
						this.allowedDomains.some((allowed) =>
							this.matchesDomain(endpoint.domain as string, allowed),
						)) ||
					(endpoint.ip && this.allowedIPs.includes(endpoint.ip));

				if (!hostAllowed) {
					return this.deny(
						`outbound host not allowlisted: ${endpoint.host}`,
						"high",
					);
				}
			}

			if (this.allowedPorts.length > 0) {
				if (endpoint.port == null) {
					return this.deny(
						`outbound port unknown for host: ${endpoint.host}`,
						"high",
					);
				}

				if (!this.allowedPorts.includes(endpoint.port)) {
					return this.deny(
						`outbound to non-allowlisted port: ${endpoint.port}`,
						"high",
					);
				}
			}
		}

		return this.allow("egress allowed");
	}

	private extractEndpoints(event: GuardEvent): Endpoint[] {
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

		// Network tools — extract URL from arguments.
		if (NETWORK_TOOLS.has(toolName)) {
			const url = event.toolCall?.arguments?.url as string | undefined;
			if (typeof url === "string") {
				pushEndpoint(this.parseUrlToEndpoint(url));
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
		return domain === candidate || domain.endsWith(`.${candidate}`);
	}

	private isIP(value: string): boolean {
		return net.isIP(value) !== 0;
	}
}
