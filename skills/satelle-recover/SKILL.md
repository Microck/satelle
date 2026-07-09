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

6. Escalate with a support bundle only after normal diagnostics are insufficient.

Prefer redacted diagnostic bundles when the current binary exposes them. Avoid raw exports, screenshots, recordings, full transcripts, and provider payloads unless the user explicitly requests them.

Completion criterion: the artifact scope and sensitivity are clear before capture.
