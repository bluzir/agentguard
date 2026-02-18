import { describe, expect, it } from "vitest";
import { parseAuditLines, summarizeAuditEntries } from "../src/cli/audit.js";

describe("audit CLI helpers", () => {
	it("parses jsonl and counts invalid lines", () => {
		const content = [
			'{"timestamp":"2026-02-18T00:00:00Z","phase":"pre_tool","framework":"generic","sessionId":"s1"}',
			"not-json",
			'{"timestamp":"2026-02-18T00:00:01Z","phase":"post_tool","framework":"generic","sessionId":"s2"}',
		].join("\n");

		const parsed = parseAuditLines(content);
		expect(parsed.entries).toHaveLength(2);
		expect(parsed.invalidLines).toBe(1);
	});

	it("builds summary from decision chains", () => {
		const entries = [
			{
				timestamp: "2026-02-18T00:00:00Z",
				phase: "pre_tool",
				framework: "generic",
				sessionId: "s1",
				toolName: "Bash",
				decisions: [
					{ action: "allow", module: "tool_policy", severity: "info" },
					{ action: "allow", module: "exec_sandbox", severity: "info" },
					{ action: "deny", module: "fs_guard", severity: "high" },
				],
			},
			{
				timestamp: "2026-02-18T00:00:03Z",
				phase: "pre_request",
				framework: "claude-telegram",
				sessionId: "s1",
				artifact: {
					signatureVerified: true,
					versionPinned: true,
					sbomUri: "file:///tmp/sbom.json",
				},
				decisions: [
					{
						action: "challenge",
						module: "approval_gate",
						severity: "critical",
					},
				],
			},
		];

		const summary = summarizeAuditEntries(entries, 2);
		expect(summary.totalEntries).toBe(2);
		expect(summary.invalidLines).toBe(2);
		expect(summary.uniqueSessions).toBe(1);
		expect(summary.phaseCounts.pre_tool).toBe(1);
		expect(summary.phaseCounts.pre_request).toBe(1);
		expect(summary.frameworkCounts.generic).toBe(1);
		expect(summary.frameworkCounts["claude-telegram"]).toBe(1);
		expect(summary.decisionActionCounts.allow).toBe(2);
		expect(summary.decisionActionCounts.deny).toBe(1);
		expect(summary.decisionActionCounts.challenge).toBe(1);
		expect(summary.moduleCounts.fs_guard).toBe(1);
		expect(summary.totalDecisions).toBe(4);
		expect(summary.denyCount).toBe(1);
		expect(summary.challengeCount).toBe(1);
		expect(summary.interventionRatePct).toBe(50);
		expect(summary.medianDetectionLatencySec).toBe(0);
		expect(summary.sandboxCoveragePct).toBe(100);
		expect(summary.signedArtifacts).toBe(1);
		expect(summary.pinnedArtifacts).toBe(1);
		expect(summary.sbomArtifacts).toBe(1);
	});
});
