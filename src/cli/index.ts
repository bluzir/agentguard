#!/usr/bin/env node

const commands: Record<string, () => Promise<void>> = {
	init: () => import("./init.js").then((m) => m.run()),
	link: () => import("./link.js").then((m) => m.run()),
	install: () => import("./install.js").then((m) => m.run()),
	scan: () => import("./scan.js").then((m) => m.run()),
	doctor: () => import("./doctor.js").then((m) => m.run()),
	pentest: () => import("./pentest.js").then((m) => m.run()),
	audit: () => import("./audit.js").then((m) => m.run()),
	hook: () => import("./hook.js").then((m) => m.run()),
	serve: () => import("./serve.js").then((m) => m.run()),
};

const USAGE = `agentguard - Security layer for AI agent orchestrators

Usage: agentguard <command> [options]

Commands:
  init       Scaffold config and framework wiring
  link       Link approval channel identity (telegram)
  install    Generate framework wiring snippets/scripts
  scan       Scan skills/prompts/tool metadata for suspicious patterns
  doctor     Environment and policy health checks
  pentest    Run baseline security test scenarios
  audit      Audit log inspection and summaries
  hook       stdin/stdout adapter entrypoint
  serve      HTTP/MCP runtime server

Options:
  --help     Show help
  --version  Show version
`;

async function main(): Promise<void> {
	const args = process.argv.slice(2);
	const command = args[0];

	if (!command || command === "--help" || command === "-h") {
		console.log(USAGE);
		process.exit(0);
	}

	if (command === "--version" || command === "-v") {
		console.log("0.2.0");
		process.exit(0);
	}

	const handler = commands[command];
	if (!handler) {
		console.error(`Unknown command: ${command}\n`);
		console.log(USAGE);
		process.exit(1);
	}

	try {
		await handler();
	} catch (err) {
		const message = err instanceof Error ? err.message : String(err);
		console.error(`Error: ${message}`);
		process.exit(1);
	}
}

main();
