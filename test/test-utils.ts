import { createRequire } from "node:module";

const require = createRequire(import.meta.url);

export function isNodeSqliteAvailable(): boolean {
	try {
		const sqliteModule = require("node:sqlite") as {
			DatabaseSync?: unknown;
		};
		return typeof sqliteModule.DatabaseSync === "function";
	} catch {
		return false;
	}
}
