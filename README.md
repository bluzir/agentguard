<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="assets/banner-dark.png">
    <source media="(prefers-color-scheme: light)" srcset="assets/banner.png">
    <img alt="RADIUS" src="assets/banner.png" width="960">
  </picture>
</p>

<p align="center">
  <strong>Draw the boundary.</strong><br>
  No LLM in the decision loop.
</p>

<p align="center">
  <a href="https://www.npmjs.com/package/agentradius"><img src="https://img.shields.io/npm/v/agentradius?style=flat&color=2563EB&label=npm" alt="npm"></a>
  <a href="https://github.com/bluzir/radius/blob/main/LICENSE"><img src="https://img.shields.io/badge/license-MIT-111827?style=flat" alt="MIT"></a>
  <a href="https://www.agentradius.cc"><img src="https://img.shields.io/badge/docs-agentradius.cc-6B7280?style=flat" alt="docs"></a>
</p>

---

> "The more data & control you give to the AI agent: (A) the more it can help you AND (B) the more it can hurt you." — [Lex Fridman](https://x.com/lexfridman/status/2023573186496037044)

## The problem

Your agent has root access to your machine. Your security layer is a system prompt that says "please be careful." Think about that for a second.

Intelligence is scaling. Access is scaling. Security is not. One bad prompt and your agent reads `~/.ssh/id_rsa`, runs `rm -rf /`, loops 500 times through your API budget, or installs a skill with hidden exfiltration instructions.

You could review every action manually, but that defeats the point of having an agent. You need containment that doesn't kill capability.

## Why this matters

Numbers from 78 validated research sources (114 analyzed), Feb 2026:

| | |
|---|---|
| **13.4%** | Of 3,984 marketplace skills scanned, 534 had critical issues. 76 were confirmed malicious — running install-time scripts that stole credentials. |
| **6 / 6** | Researchers tested six coding agents for tool injection. All six gave up remote code execution through poisoned tool metadata. |
| **85%+** | A 78-study survey of prompt-based guardrails found most break under adaptive red-team attacks. The LLM can't reliably police itself. |

A regex match on `rm -rf` is true or false. The agent can't talk its way past it.

## What RADIUS does

RADIUS sits between the agent and every tool call. Before the agent reads a file, runs a command, or makes a network request, RADIUS intercepts the call, runs it through a pipeline of modules, and returns one of five verdicts:

- **allow** — proceed
- **deny** — block the call, return a reason
- **modify** — patch the arguments (e.g. strip dangerous flags)
- **challenge** — pause and ask a human for approval
- **alert** — log it, let it through

You choose which modules run and how strict each one is. Want to block `~/.ssh` reads but allow `/tmp`? That's one line in `fs_guard`. Want to require Telegram approval for `Bash` calls but not for `Read`? That's one rule in `approval_gate`. Every module is independent — turn them on, off, or configure each one separately.

The point is granularity without complexity. You start with a profile (`local`, `standard`, or `unbounded`) that gives you sensible defaults for every module. Then you adjust whatever you want in `radius.yaml`. Two commands to get running:

```bash
npm install agentradius
npx agentradius init --framework openclaw --profile standard
```

That's it. You have filesystem locks, shell blocking, secret redaction, rate limits, and an audit log. No boilerplate, no infrastructure, no external services.

## Modules

Eleven modules, none with an LLM. They block or allow based on rules you write.

| Module | What it does |
|--------|-------------|
| `kill_switch` | Emergency stop. Set an env var or drop a file, all risky actions halt. |
| `tool_policy` | Allow or deny by tool name. Optional argument schema validation. Default deny. |
| `fs_guard` | Blocks file access outside allowed paths. `~/.ssh`, `~/.aws`, `/etc` are unreachable. |
| `command_guard` | Matches shell patterns — `sudo`, `rm -rf`, pipe chains. Blocked before execution. |
| `exec_sandbox` | Wraps commands in bwrap. Restricted filesystem and network access. |
| `egress_guard` | Outbound network filter. Allowlist by domain, IP, port. Everything else is dropped. |
| `output_dlp` | Catches secrets in output — AWS keys, tokens, private certs. Redacts or blocks. |
| `rate_budget` | Caps tool calls per minute. Stops runaway loops. |
| `skill_scanner` | Inspects skills at load time for injection payloads: zero-width chars, base64 blobs, exfil URLs. |
| `approval_gate` | Routes risky operations to Telegram or an HTTP endpoint for human approval. |
| `audit` | Append-only log of every decision. Every action, every timestamp. |

## Three postures

One config change. Pick the containment level that matches your context.

**Local** — Zero trust.
Production, billing, credentials. Default deny. Sandbox required. 30 calls/min.

**Standard** — Trust but verify.
Development, staging, daily work. Default deny. Secrets redacted. 60 calls/min.

**Unbounded** — Observe only.
Research, brainstorming, migration. Logs everything, blocks nothing. 120 calls/min.

## Install

```bash
npm install agentradius
```

## Get running

```bash
npx agentradius init --framework openclaw --profile standard
npx agentradius doctor    # verify setup
npx agentradius pentest   # test your defenses
```

This creates `radius.yaml` and wires the adapter for your orchestrator.

Supported frameworks: `openclaw`, `nanobot`, `claude-telegram`, `generic`.

What gets generated:

- **openclaw**: `.radius/openclaw-hook.command.sh`, `.radius/openclaw-hooks.json`
- **claude-telegram**: `.radius/claude-telegram.module.yaml`, `.radius/claude-tool-hook.command.sh`, auto-patched `.claude/settings.local.json`

Hook scripts resolve config via `$SCRIPT_DIR` so they work regardless of shell working directory.

## Usage

### As a library

```typescript
import { RadiusRuntime, GuardPhase } from 'agentradius';

const guard = new RadiusRuntime({
  configPath: './radius.yaml',
  framework: 'openclaw'
});

const result = await guard.evaluateEvent({
  phase: GuardPhase.PRE_TOOL,
  framework: 'openclaw',
  sessionId: 'session-1',
  toolCall: {
    name: 'Bash',
    arguments: { command: 'cat ~/.ssh/id_rsa' },
  },
  metadata: {},
});

// result.finalAction === 'deny'
// result.reason === 'fs_guard: path ~/.ssh/id_rsa is outside allowed paths'
```

### As a hook (stdin/stdout)

```bash
echo '{"tool_name":"Bash","tool_input":{"command":"sudo rm -rf /"}}' | npx agentradius hook
```

### As a server

```bash
npx agentradius serve --port 3000
```

## Configuration

```yaml
global:
  profile: standard
  workspace: ${CWD}
  defaultAction: deny

modules:
  - kill_switch
  - tool_policy
  - fs_guard
  - command_guard
  - output_dlp
  - rate_budget
  - audit

moduleConfig:
  kill_switch:
    enabled: true
    envVar: RADIUS_KILL_SWITCH
    filePath: ./.radius/KILL_SWITCH

  fs_guard:
    allowedPaths:
      - ${workspace}
      - /tmp
    blockedPaths:
      - ~/.ssh
      - ~/.aws
    blockedBasenames:
      - .env
      - .env.local
      - .envrc

  command_guard:
    denyPatterns:
      - "^sudo\\s"
      - "rm\\s+-rf"

  rate_budget:
    windowSec: 60
    maxCallsPerWindow: 60
    store:
      engine: sqlite
      path: ./.radius/state.db
      required: true
```

Template variables: `${workspace}`, `${HOME}`, `${CWD}`, and any environment variable.

## Approvals

`approval_gate` routes risky tools to Telegram or HTTP for human confirmation. Both support `sync_wait` mode.

Telegram callbacks: **Approve** (one action) · **Allow 30m** (temporary lease) · **Deny**

HTTP expects a POST returning `{"status":"approved"}`, `{"status":"denied"}`, `{"status":"approved_temporary","ttlSec":1800}`, or `{"status":"error","reason":"..."}`.

```yaml
approval:
  channels:
    telegram:
      enabled: true
      transport: polling
      botToken: ${TELEGRAM_BOT_TOKEN}
      allowedChatIds: []
      approverUserIds: []
    http:
      enabled: false
      url: http://127.0.0.1:3101/approvals/resolve
      timeoutMs: 10000
  store:
    engine: sqlite
    path: ./.radius/state.db
    required: true

moduleConfig:
  approval_gate:
    autoRouting:
      defaultChannel: telegram
      frameworkDefaults:
        openclaw: telegram
        generic: http
    rules:
      - tool: "Bash"
        channel: auto
        prompt: 'Approve execution of "Bash"?'
        timeoutSec: 90
```

`Allow 30m` only bypasses repeated approval prompts. All other modules still enforce normally.

## OpenClaw subprocess compatibility

OpenClaw hooks run as subprocesses, so in-memory state resets on every tool call. Anything that needs to persist across calls requires SQLite:

```yaml
approval:
  store:
    engine: sqlite
    path: ./.radius/state.db
    required: true

moduleConfig:
  rate_budget:
    store:
      engine: sqlite
      path: ./.radius/state.db
      required: true
```

| Module | Subprocess mode | Note |
|--------|----------------|------|
| `kill_switch`, `tool_policy`, `fs_guard`, `command_guard`, `audit` | Works | Stateless or file/env based |
| `approval_gate` + `Allow 30m` | Works | SQLite lease store persists across processes |
| `rate_budget` | Works | SQLite store keeps counters across processes |
| `output_dlp` | Partial | Requires `PostToolUse` hook wiring |
| `egress_guard` | Works | Preflight policy; kernel egress needs OS firewall |
| `exec_sandbox` | Platform dependent | Linux `bwrap`; non-Linux needs equivalent |
| `skill_scanner` | Not triggered by `PreToolUse` | Run via `npx agentradius scan` or CI |

## Custom adapter

For Claude Code-based orchestrators with custom runtime/protocol, see `examples/claude-custom-adapter-runner.mjs`.

Maps Claude hook payload to canonical `GuardEvent`, runs the pipeline, maps back to Claude response JSON.

```bash
echo '{"hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"sudo id"}}' \
  | node ./examples/claude-custom-adapter-runner.mjs --config ./radius.yaml
# {"decision":"block","reason":"command_guard: denied by pattern ..."}
```

## Threat coverage

### Covered

| Attack | What stops it |
|--------|---------------|
| Credential theft (`cat ~/.ssh/id_rsa`) | `fs_guard` |
| System file access (`/etc/shadow`) | `fs_guard` |
| Privilege escalation (`sudo ...`) | `command_guard` |
| Destructive shell (`rm -rf /`) | `command_guard` |
| Secret leakage in output (`AKIA...`, `ghp_...`) | `output_dlp` |
| Runaway loops (500 calls/min) | `rate_budget` |
| Emergency freeze | `kill_switch` |
| Skill supply chain (hidden instructions) | `skill_scanner` |
| Unsigned skill installs | `skill_scanner` provenance policy |
| Dotenv harvest (`.env` reads) | `fs_guard` + `command_guard` |
| Network exfiltration | `egress_guard` |
| Sandbox escape | `exec_sandbox` (bwrap) |
| Unapproved tool use | `tool_policy` |

### Not covered (v0.4)

Being honest about gaps matters more than a longer table.

- **Prompt injection at model level.** Jailbreaks that produce harmful text without tool calls. RADIUS only sees tool calls and outputs, not the model's internal reasoning.
- **Semantic attacks via allowed tools.** Reading an allowed file, then sending its contents via an allowed API. Modules check independently; they don't reason about intent.
- **Token/cost budgets.** Rate limiting counts calls, not tokens or dollars.
- **Multi-tenant isolation.** One config per runtime. No user-level policy separation.
- **OS-level exploits.** `exec_sandbox` uses bwrap, not a VM. A kernel exploit bypasses it.

## Tests

92 tests across 10 suites. ~500ms.

```bash
npm test
```

### CI regression

`.github/workflows/security-regression.yml` runs build, tests, and pentest on every push:

```bash
npx agentradius init --framework generic --profile standard --output /tmp/radius-ci.yaml
npx agentradius pentest --config /tmp/radius-ci.yaml
```

### Built-in pentest

```
npx agentradius pentest

  [OK  ] fs_guard blocks /etc/passwd
  [OK  ] command_guard blocks sudo chain
  [OK  ] fs_guard blocks dotenv file reads
  [OK  ] output_dlp detects tool-output secret
  [OK  ] output_dlp detects response secret
  [OK  ] skill_scanner catches malicious skill
  [OK  ] skill_scanner catches tool metadata poisoning
  [OK  ] rate_budget blocks runaway loop
  [WARN] egress_guard blocks outbound exfiltration
  [OK  ] adapters handle malformed payloads
```

### Audit metrics

```bash
npx agentradius audit --json
```

Intervention rate, detection latency, kill-switch activations, sandbox coverage, provenance coverage, dotenv exposure posture.

## How it works

```
Orchestrator event
  -> Adapter (converts to canonical format)
    -> Pipeline (modules run in config order)
      -> first DENY or CHALLENGE wins, patches compose, alerts accumulate
    -> Adapter (converts back to orchestrator format)
  -> Response
```

Modules run in config order. If any module returns DENY or CHALLENGE, the pipeline stops. MODIFY patches are deep-merged. If an enforce-mode module throws, it fails closed (denies). Observe-mode errors log and continue.

## Requirements

- Node.js >= 20
- Node.js 22+ for persistent state (`node:sqlite` for approval leases, rate budgets)
- `bwrap` (optional, `exec_sandbox` on Linux)

## Credits

Security philosophy and threat model based on research by [Dima Matskevich](https://github.com/matskevich):

- [openclaw-infra/security](https://github.com/matskevich/openclaw-infra/tree/main/docs/security) — 5-layer security hardening for AI agents
- ["openclaw: why security from the docs is decoration"](https://dimamatskevich.substack.com/p/openclaw) — why prompt-level defenses fail under adaptive attacks

## License

MIT
