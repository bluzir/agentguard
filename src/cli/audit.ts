import fs from "node:fs";
import path from "node:path";
import { loadConfig } from "../config/index.js";

interface AuditArgs {
	configPath?: string;
	filePath?: string;
	tail: number;
	sessionId?: string;
	json: boolean;
}

interface AuditDecisionEntry {
	action?: string;
	module?: string;
	reason?: string;
	severity?: string;
}

interface AuditEntry {
	timestamp?: string;
	phase?: string;
	framework?: string;
	sessionId?: string;
	decisions?: AuditDecisionEntry[];
	[key: string]: unknown;
}

interface ParsedAudit {
	entries: AuditEntry[];
	invalidLines: number;
}

export interface AuditSummary {
	totalEntries: number;
	invalidLines: number;
	uniqueSessions: number;
	phaseCounts: Record<string, number>;
	frameworkCounts: Record<string, number>;
	decisionActionCounts: Record<string, number>;
	decisionSeverityCounts: Record<string, number>;
	moduleCounts: Record<string, number>;
	denyCount: number;
	challengeCount: number;
}

function parseArgs(): AuditArgs {
	const args = process.argv.slice(3);

	let configPath: string | undefined;
	let filePath: string | undefined;
	let tail = 20;
	let sessionId: string | undefined;
	let json = false;

	for (let i = 0; i < args.length; i++) {
		switch (args[i]) {
			case "--config":
			case "-c":
				configPath = args[++i];
				break;
			case "--file":
			case "-f":
				filePath = args[++i];
				break;
			case "--tail":
			case "-n": {
				const parsed = Number.parseInt(args[++i] ?? "20", 10);
				tail = Number.isNaN(parsed) || parsed < 0 ? 20 : parsed;
				break;
			}
			case "--session":
			case "-s":
				sessionId = args[++i];
				break;
			case "--json":
				json = true;
				break;
		}
	}

	return {
		configPath,
		filePath,
		tail,
		sessionId,
		json,
	};
}

export function parseAuditLines(content: string): ParsedAudit {
	const lines = content.split(/\r?\n/).filter((line) => line.trim().length > 0);
	const entries: AuditEntry[] = [];
	let invalidLines = 0;

	for (const line of lines) {
		try {
			const parsed = JSON.parse(line) as unknown;
			if (parsed && typeof parsed === "object") {
				entries.push(parsed as AuditEntry);
			} else {
				invalidLines++;
			}
		} catch {
			invalidLines++;
		}
	}

	return { entries, invalidLines };
}

export function summarizeAuditEntries(
	entries: AuditEntry[],
	invalidLines: number,
): AuditSummary {
	const phaseCounts: Record<string, number> = {};
	const frameworkCounts: Record<string, number> = {};
	const decisionActionCounts: Record<string, number> = {};
	const decisionSeverityCounts: Record<string, number> = {};
	const moduleCounts: Record<string, number> = {};
	const sessions = new Set<string>();

	let denyCount = 0;
	let challengeCount = 0;

	for (const entry of entries) {
		if (entry.sessionId) {
			sessions.add(entry.sessionId);
		}

		if (entry.phase) {
			phaseCounts[entry.phase] = (phaseCounts[entry.phase] ?? 0) + 1;
		}

		if (entry.framework) {
			frameworkCounts[entry.framework] =
				(frameworkCounts[entry.framework] ?? 0) + 1;
		}

		if (Array.isArray(entry.decisions)) {
			for (const decision of entry.decisions) {
				if (!decision || typeof decision !== "object") continue;

				if (decision.action) {
					decisionActionCounts[decision.action] =
						(decisionActionCounts[decision.action] ?? 0) + 1;
					if (decision.action === "deny") denyCount++;
					if (decision.action === "challenge") challengeCount++;
				}

				if (decision.severity) {
					decisionSeverityCounts[decision.severity] =
						(decisionSeverityCounts[decision.severity] ?? 0) + 1;
				}

				if (decision.module) {
					moduleCounts[decision.module] =
						(moduleCounts[decision.module] ?? 0) + 1;
				}
			}
		}
	}

	return {
		totalEntries: entries.length,
		invalidLines,
		uniqueSessions: sessions.size,
		phaseCounts,
		frameworkCounts,
		decisionActionCounts,
		decisionSeverityCounts,
		moduleCounts,
		denyCount,
		challengeCount,
	};
}

function formatMap(title: string, values: Record<string, number>): string[] {
	const rows = Object.entries(values).sort((a, b) => b[1] - a[1]);
	if (rows.length === 0) {
		return [`${title}: (none)`];
	}

	return [title, ...rows.map(([key, count]) => `  ${key}: ${count}`)];
}

function tailEntries(entries: AuditEntry[], count: number): AuditEntry[] {
	if (count <= 0) return [];
	return entries.slice(Math.max(0, entries.length - count));
}

function printHumanSummary(
	filePath: string,
	summary: AuditSummary,
	recentEntries: AuditEntry[],
): void {
	console.log("\nagentguard audit\n");
	console.log(`File: ${filePath}`);
	console.log(`Total entries: ${summary.totalEntries}`);
	console.log(`Invalid lines: ${summary.invalidLines}`);
	console.log(`Unique sessions: ${summary.uniqueSessions}`);
	console.log(
		`Decisions deny/challenge: ${summary.denyCount}/${summary.challengeCount}`,
	);
	console.log();

	for (const line of formatMap("By phase", summary.phaseCounts)) {
		console.log(line);
	}
	console.log();

	for (const line of formatMap("By framework", summary.frameworkCounts)) {
		console.log(line);
	}
	console.log();

	for (const line of formatMap(
		"Decision actions",
		summary.decisionActionCounts,
	)) {
		console.log(line);
	}
	console.log();

	for (const line of formatMap(
		"Decision severity",
		summary.decisionSeverityCounts,
	)) {
		console.log(line);
	}
	console.log();

	for (const line of formatMap("Top modules", summary.moduleCounts)) {
		console.log(line);
	}
	console.log();

	if (recentEntries.length === 0) {
		console.log("Recent entries: (none)");
		return;
	}

	console.log(`Recent entries (${recentEntries.length}):`);
	for (const entry of recentEntries) {
		const decisions = Array.isArray(entry.decisions) ? entry.decisions : [];
		const finalDecision =
			decisions.length > 0 ? decisions[decisions.length - 1] : undefined;
		const finalAction = finalDecision?.action ?? "-";
		const module = finalDecision?.module ?? "-";

		console.log(
			`  ${entry.timestamp ?? "-"} phase=${entry.phase ?? "-"} framework=${entry.framework ?? "-"} session=${entry.sessionId ?? "-"} final=${finalAction} module=${module}`,
		);
	}
}

export async function run(): Promise<void> {
	const args = parseArgs();
	const config = loadConfig(args.configPath);

	const configuredPath = config.audit.path;
	const filePath = args.filePath ?? configuredPath;
	if (!filePath) {
		throw new Error(
			"audit file path is not configured. Use --file or set audit.path",
		);
	}

	const resolvedPath = path.resolve(filePath);
	if (!fs.existsSync(resolvedPath)) {
		throw new Error(`audit file not found: ${resolvedPath}`);
	}

	const content = fs.readFileSync(resolvedPath, "utf-8");
	const parsed = parseAuditLines(content);
	const filteredEntries = args.sessionId
		? parsed.entries.filter((entry) => entry.sessionId === args.sessionId)
		: parsed.entries;

	const summary = summarizeAuditEntries(filteredEntries, parsed.invalidLines);
	const recentEntries = tailEntries(filteredEntries, args.tail);

	if (args.json) {
		console.log(
			JSON.stringify(
				{
					filePath: resolvedPath,
					sessionFilter: args.sessionId ?? null,
					summary,
					recentEntries,
				},
				null,
				2,
			),
		);
		return;
	}

	printHumanSummary(resolvedPath, summary, recentEntries);
}
