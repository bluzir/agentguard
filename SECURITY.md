# Security Policy

This document describes the security posture of the `radius` repository only.

Scope:
- Included: code and release artifacts from this repo (`radius`)
- Excluded: sibling repos in the same workspace (`openclaw-infra`, `nanobot`, `landing`, etc.)

## Security Principles

`radius` is designed around deterministic, human-first safety:
- deterministic enforcement before prompt-level guidance
- fail-closed behavior on high-risk paths
- blast-radius reduction over "perfect prevention" claims
- explicit tradeoffs and known gaps documented in public

Core model:
- LLM output is untrusted input
- policy modules decide `allow | deny | modify | challenge | alert`
- destructive or ambiguous actions should require explicit human intent

## Threat Model (Repo-Level)

Primary threats we design against:
- tool abuse (`sudo`, destructive shell, unsafe command chains)
- credential exposure (`.env`, API keys, token leaks in outputs)
- filesystem exfiltration (`~/.ssh`, `/etc`, out-of-workspace paths)
- prompt/skill/tool-metadata injection patterns
- runaway automation loops and budget burn
- unsafe third-party skill provenance (unsigned/unpinned/unscanned)

Out of scope for strict guarantees:
- kernel/VM escape class attacks
- compromised host OS or compromised CI runner
- semantic misuse of allowed tools in valid-but-malicious workflows

## Security Controls Implemented

Runtime controls:
- `kill_switch`: emergency stop via env/file toggle
- `tool_policy`: allow/deny and schema checks per tool
- `fs_guard`: path allowlist + blocked path/basename protection
- `command_guard`: shell deny patterns (including chained command segments)
- `exec_sandbox`: optional `bwrap` execution isolation
- `egress_guard`: outbound domain/IP/port controls when enabled
- `output_dlp`: secret detection and redaction/blocking
- `rate_budget`: call-rate limiting for loop containment
- `skill_scanner`: prompt-injection + provenance heuristics
- `approval_gate`: human approval for risky actions (Telegram and HTTP supported)
- `audit`: append-only security decision trail

Adapter-level protections:
- canonical event mapping with defensive parsing for malformed payloads
- challenge propagation preserved across adapters
- fail-safe defaults when fields are missing/invalid

CLI/operational controls:
- `radius doctor`: posture checks (config, provenance, approval readiness, dotenv policy)
- `radius pentest`: adversarial baseline scenarios
- `radius audit`: KPI-style security telemetry from logs

## SDLC and CI Controls

Current CI gate:
- workflow: `.github/workflows/security-regression.yml`
- steps:
  - build
  - full tests
  - baseline pentest regression

Current test posture:
- adapter robustness tests (malformed payloads, challenge path)
- module coverage across all core controls
- runtime approval flow checks
- install/init wiring checks for secure bootstrap paths

## Supply Chain and Release Controls

Current:
- npm package publishes from built artifacts only (`dist`)
- deterministic build step before publish (`prepublishOnly`)
- test suite and pentest available before release

Recommended operator hygiene:
- pin dependency versions where practical
- review dependency updates with `npm audit` and changelogs
- prefer minimal install permissions and sandboxed execution

## Secrets Handling Policy

Rules for this repository:
- never commit real credentials, tokens, private keys, or production identifiers
- examples must use placeholders or synthetic tokens
- tests may include fake secret-shaped strings only for detector validation

If a secret is committed:
1. Revoke/rotate immediately
2. Remove from source and history as needed
3. Document incident and mitigation in release notes/changelog

## Vulnerability Reporting

Please report vulnerabilities responsibly:
- Preferred: GitHub Security Advisory (private disclosure)
- Fallback: open a GitHub issue for non-sensitive security bugs

Include:
- affected version/commit
- reproduction steps
- expected vs actual behavior
- impact assessment and suggested remediation (if available)

Response goals (best effort):
- acknowledge report quickly
- validate and triage severity
- publish patch and upgrade guidance

## Known Security Limitations

- `exec_sandbox` is defense-in-depth, not VM-grade isolation
- no formal proof of safety for autonomous tool orchestration
- prompt-level attacks remain partially detectable, not fully preventable
- some controls are configuration-dependent (for example `egress_guard`, approvals, sandbox enablement)

## Security Roadmap (Polish)

P0 (next):
- make `egress_guard` enabled-by-default in local templates
- add CI `npm audit --omit=dev --audit-level=high` gate
- publish explicit secure-config examples per framework with one-command validation
- add deny-by-default template for high-risk tools with pre-wired `approval_gate`

P1:
- add CodeQL/SAST workflow for TypeScript
- generate SBOM (CycloneDX/SPDX) on release artifacts
- add dependency update policy + security changelog section per release
- add regression fixtures for tool poisoning and indirect prompt-injection payloads

P2:
- signed release provenance (npm provenance + attestations)
- optional policy signatures for config bundles
- richer risk scoring in `audit` output (blast-radius score, exposure score)

---

Security is a moving target. This policy favors practical risk reduction, clear defaults, and fast iteration with transparent limitations.
