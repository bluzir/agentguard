import { spawnSync } from "node:child_process";
import path from "node:path";
import { type Decision, type GuardEvent, GuardPhase } from "../types.js";
import { BaseModule } from "./base.js";

interface ExecSandboxConfig {
	engine?: "bwrap" | "none";
	required?: boolean;
	shareNetwork?: boolean;
	childPolicy?: {
		network?: "inherit" | "deny";
	};
	readOnlyPaths?: string[];
	readWritePaths?: string[];
	tmpfsPaths?: string[];
	shellPath?: string;
	shellFlag?: "-c" | "-lc";
}

const SHELL_TOOLS = new Set(["Bash"]);
const DEFAULT_READ_ONLY_PATHS = ["/"];
const DEFAULT_TMPFS_PATHS = ["/tmp"];

function shellEscape(arg: string): string {
	return `'${arg.replace(/'/g, "'\\''")}'`;
}

/**
 * §9.4 exec_sandbox — hard boundary for command execution.
 * Phase: PRE_TOOL
 *
 * Wraps command execution in configured sandbox engine.
 * If required=true and engine unavailable -> DENY.
 */
export class ExecSandboxModule extends BaseModule {
	name = "exec_sandbox";
	phases = new Set([GuardPhase.PRE_TOOL]);

	private engine: "bwrap" | "none" = "none";
	private required = false;
	private shareNetwork = true;
	private childNetworkPolicy: "inherit" | "deny" = "inherit";
	private readOnlyPaths: string[] = DEFAULT_READ_ONLY_PATHS;
	private readWritePaths: string[] = [];
	private tmpfsPaths: string[] = DEFAULT_TMPFS_PATHS;
	private shellPath = "sh";
	private shellFlag: "-c" | "-lc" = "-c";
	private cachedBwrapAvailable: boolean | undefined;

	override configure(config: Record<string, unknown>): void {
		super.configure(config);
		const c = config as unknown as Partial<ExecSandboxConfig>;
		this.engine = c.engine ?? "none";
		this.required = c.required ?? false;
		this.shareNetwork = c.shareNetwork ?? true;
		this.childNetworkPolicy = c.childPolicy?.network ?? "inherit";
		this.readOnlyPaths = this.normalizePaths(
			c.readOnlyPaths,
			DEFAULT_READ_ONLY_PATHS,
		);
		this.readWritePaths = this.normalizePaths(c.readWritePaths, []);
		this.tmpfsPaths = this.normalizePaths(c.tmpfsPaths, DEFAULT_TMPFS_PATHS);
		this.shellPath = c.shellPath ?? "sh";
		this.shellFlag = c.shellFlag ?? "-c";
		this.cachedBwrapAvailable = undefined;
	}

	async evaluate(event: GuardEvent): Promise<Decision> {
		const toolName = event.toolCall?.name;
		if (!toolName || !SHELL_TOOLS.has(toolName)) {
			return this.allow("not a shell tool");
		}

		if (this.engine === "none") {
			if (this.required) {
				return this.deny(
					"sandbox required but no engine configured",
					"critical",
				);
			}
			return this.alert("sandbox disabled, command running without isolation");
		}

		if (this.engine === "bwrap") {
			const available = await this.checkBwrapAvailable();
			if (!available) {
				if (this.required) {
					return this.deny(
						"sandbox required but bwrap is not available",
						"critical",
					);
				}
				return this.alert("bwrap not available, running without sandbox");
			}

			// Wrap command in sandbox — modify the tool arguments
			const command = event.toolCall?.arguments?.command as string | undefined;
			if (command) {
				return this.modify(
					"command wrapped in bwrap sandbox",
					{
						toolArguments: {
							command: this.wrapWithBwrap(command),
						},
					},
					"info",
				);
			}
		}

		return this.allow("sandbox check passed");
	}

	private async checkBwrapAvailable(): Promise<boolean> {
		if (this.cachedBwrapAvailable !== undefined) {
			return this.cachedBwrapAvailable;
		}

		const result = spawnSync("bwrap", ["--version"], { stdio: "ignore" });
		const errorCode = (result.error as NodeJS.ErrnoException | undefined)?.code;
		this.cachedBwrapAvailable =
			errorCode !== "ENOENT" && result.status !== null;
		return this.cachedBwrapAvailable;
	}

	private wrapWithBwrap(command: string): string {
		const shareNetwork = this.shareNetwork && this.childNetworkPolicy !== "deny";
		const args: string[] = [
			"bwrap",
			"--die-with-parent",
			"--new-session",
			"--unshare-all",
			...(shareNetwork ? ["--share-net"] : []),
			"--proc",
			"/proc",
			"--dev",
			"/dev",
		];

		for (const mountPath of this.readOnlyPaths) {
			args.push("--ro-bind", mountPath, mountPath);
		}

		for (const mountPath of this.readWritePaths) {
			args.push("--bind", mountPath, mountPath);
		}

		for (const mountPath of this.tmpfsPaths) {
			args.push("--tmpfs", mountPath);
		}

		args.push(
			"--setenv",
			"HOME",
			"/tmp",
			"--setenv",
			"TMPDIR",
			"/tmp",
			"--",
			this.shellPath,
			this.shellFlag,
			command,
		);

		return args.map(shellEscape).join(" ");
	}

	private normalizePaths(
		configured: string[] | undefined,
		defaults: string[],
	): string[] {
		const raw = (configured?.length ? configured : defaults).filter(Boolean);
		const normalized = raw.map((p) =>
			path.isAbsolute(p) ? path.normalize(p) : path.resolve(p),
		);
		return [...new Set(normalized)];
	}
}
