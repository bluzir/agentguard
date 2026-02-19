# Changelog

All notable changes to this project will be documented in this file.

## [0.5.0] - 2026-02-19

### Added

- `self_defense` module for immutable control-plane protection (opt-in).
- `tripwire_guard` module for optional honeytoken tripwires (opt-in).
- `repetition_guard` module for repeated identical tool-call loop detection (opt-in).
- `tool_policy` support for `action: challenge` with configurable challenge payload.
- `egress_guard` tool-specific binding support via `tool_policy.rules[].egress`.
- HTTP approval resolver support for `pending` responses with `pollUrl` bridge flow.
- `exec_sandbox.childPolicy.network` for explicit child-process network handling.

### Fixed

- `egress_guard` wildcard domain matching now supports `*.example.com`.

### Changed

- Backward compatibility preserved: new hardening modules are not enabled by default.
- README and doctor guidance expanded for Telegram one-bot topology and approval bridge behavior.

## [0.4.0] - 2026-02-18

- Baseline deterministic module stack (`tool_policy`, `fs_guard`, `command_guard`, `output_dlp`, `rate_budget`, `audit`).
- OpenClaw/Nanobot/Claude-Telegram wiring and approval bootstrap commands.
