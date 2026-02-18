export type { Adapter } from "./base.js";
export { OpenClawAdapter } from "./openclaw.js";
export { NanobotAdapter } from "./nanobot.js";
export { ClaudeTelegramAdapter } from "./claude-telegram.js";
export { GenericAdapter } from "./generic.js";

import type { Framework } from "../types.js";
import type { Adapter } from "./base.js";
import { ClaudeTelegramAdapter } from "./claude-telegram.js";
import { GenericAdapter } from "./generic.js";
import { NanobotAdapter } from "./nanobot.js";
import { OpenClawAdapter } from "./openclaw.js";

export function createAdapter(framework: Framework | "claudeTelegram" | string): Adapter {
  switch (framework) {
    case "openclaw":
      return new OpenClawAdapter();
    case "nanobot":
      return new NanobotAdapter();
    case "claudeTelegram":
    case "claude-telegram":
      return new ClaudeTelegramAdapter();
    case "generic":
      return new GenericAdapter();
    default:
      throw new Error(`unknown framework: "${framework}"`);
  }
}
