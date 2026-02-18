import fs from "node:fs";
import path from "node:path";
import { type Decision, type GuardEvent, GuardPhase } from "../types.js";
import { BaseModule } from "./base.js";

interface FsGuardConfig {
	allowedPaths: string[];
	blockedPaths: string[];
	blockedBasenames?: string[];
}

const FILE_TOOLS = new Set([
	"Read",
	"Write",
	"Edit",
	"Glob",
	"Grep",
	"NotebookEdit",
]);

/**
 * §9.2 fs_guard — restrict file tools to allowlisted paths.
 * Phase: PRE_TOOL
 *
 * Key requirements:
 * - Canonicalization via absolute path.
 * - Deny if target is outside allowed prefixes.
 * - Blocked prefixes checked first.
 */
export class FsGuardModule extends BaseModule {
	name = "fs_guard";
	phases = new Set([GuardPhase.PRE_TOOL]);

	private allowedPaths: string[] = [];
	private blockedPaths: string[] = [];
	private blockedBasenames: Set<string> = new Set();

	override configure(config: Record<string, unknown>): void {
		super.configure(config);
		const c = config as unknown as Partial<FsGuardConfig>;
		this.allowedPaths = (c.allowedPaths ?? []).map((p) =>
			this.canonicalizePolicyPath(p),
		);
		this.blockedPaths = (c.blockedPaths ?? []).map((p) =>
			this.canonicalizePolicyPath(p),
		);
		this.blockedBasenames = new Set(
			(c.blockedBasenames ?? []).map((name) => name.toLowerCase()),
		);
	}

	async evaluate(event: GuardEvent): Promise<Decision> {
		const toolName = event.toolCall?.name;
		if (!toolName || !FILE_TOOLS.has(toolName)) {
			return this.allow("not a file tool");
		}

		const targetPath = this.extractPath(event);
		if (!targetPath) {
			return this.allow("no path in arguments");
		}

		const canonicalPath = this.canonicalizeTargetPath(targetPath);

		// Blocked prefixes checked first
		for (const blocked of this.blockedPaths) {
			if (this.isWithin(canonicalPath, blocked)) {
				return this.deny(
					`path "${canonicalPath}" is in blocked prefix "${blocked}"`,
					"critical",
				);
			}
		}

		const baseName = path.basename(canonicalPath).toLowerCase();
		if (this.blockedBasenames.has(baseName)) {
			return this.deny(
				`path "${canonicalPath}" is blocked by basename policy`,
				"critical",
			);
		}

		// Must be within at least one allowed prefix
		const isAllowed = this.allowedPaths.some((allowed) =>
			this.isWithin(canonicalPath, allowed),
		);

		if (!isAllowed) {
			return this.deny(
				`path "${canonicalPath}" is outside allowed prefixes`,
				"high",
			);
		}

		return this.allow("path within allowed prefix");
	}

	private extractPath(event: GuardEvent): string | undefined {
		const args = event.toolCall?.arguments;
		if (!args) return undefined;

		// Common path argument names across file tools
		return (args.file_path ?? args.path ?? args.notebook_path) as
			| string
			| undefined;
	}

	private expandPath(p: string): string {
		const home = process.env.HOME ?? process.env.USERPROFILE ?? "";
		return path.resolve(p.replace(/^~/, home));
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

	private isWithin(targetPath: string, basePath: string): boolean {
		const relative = path.relative(basePath, targetPath);
		return (
			relative === "" ||
			(!relative.startsWith("..") && !path.isAbsolute(relative))
		);
	}
}
