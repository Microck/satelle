---
name: satelle-recover
description: Recover Satelle failures. Use when setup, run, steer, status, logs, MCP, provider auth, readiness, transport, Host Daemon, or session operations fail or produce blockers.
---

# Satelle Recover

Recover from evidence. Satelle failures should end with a typed error, preserved state, and a narrow next command.

## Steps

1. Capture the typed failure.

Rerun the failing command with the command's `--json` mode. Use `--error-format json` only when the current binary exposes that global option. Preserve the command, host, profile, session id, exit code, and error code.

Completion criterion: the agent can name the stable error code and the affected target.

2. Check local configuration first.

Run `satelle config check --json` and `satelle config explain --json` for the selected context.

Completion criterion: local config is valid, or config errors are fixed before remote diagnosis continues.

3. Diagnose the host.

Run `satelle doctor --json`, narrowed with `--scope` when the failure already points to transport, config, codex, computer-use, or provider.

Completion criterion: every blocker has a scope, finding, evidence, and recovery command.

4. Read normalized logs.

Use `satelle logs --json`, scoped by `--session` when a session id is known. Do not request raw diagnostic exports unless the user explicitly accepts the sensitivity.

When available, prefer redacted task artifacts such as `plan.md`, `worklog.md`, and `goal.md` alongside normalized logs before asking for raw transcripts, screenshots, or recordings.

Completion criterion: claims about prior actions are backed by normalized log entries, current status, or redacted task artifacts.

5. Repair narrowly.

Use `satelle setup --dry-run`, `satelle repair --dry-run`, or `satelle host update --dry-run` before applying changes. Ask before using `--yes`.

Completion criterion: the recovery plan identifies what will mutate, what state is preserved, and how to verify afterward.

For MCP failures, first confirm whether the server was intentionally started with `satelle mcp serve --enable-mutations`. A missing mutation tool means mutation access was not enabled. It is not a reason to bypass the CLI consent or Trusted Profile rules.

6. Escalate with a support bundle only after normal diagnostics are insufficient.

Use `satelle support bundle --host <alias> --output <path> --json` with a user-selected local destination. The archive includes redacted configuration shape, versions, readiness, normalized logs, transport diagnostics, and the 200 most recent setup-ledger summaries. Its manifest lists unavailable categories under `not_collected`; a partial bundle is evidence of those collection failures, not proof that the Host has no history.

For an authorized noninteractive export, also pass `--no-input --yes`. Satelle does not upload the archive. Inspect its contents before sharing it, and request separate permission before any upload. Avoid raw exports, screenshots, recordings, full transcripts, and provider payloads unless the user explicitly requests them.

Completion criterion: the local output path, collected categories, missing categories, and remaining sensitivity are clear. Preserve the original failure and recovery evidence alongside the bundle report.
