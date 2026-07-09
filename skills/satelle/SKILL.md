---
name: satelle
description: Route Satelle work to the narrow setup, use, or recover skill. Use when an agent is asked to configure, operate, troubleshoot, or explain Satelle but the correct Satelle workflow is not obvious.
---

# Satelle

Satelle is a remote computer-use bridge. Route to the smallest Satelle skill that can complete the job.

## Route

1. Use `satelle-setup` when the task is to install, configure, onboard, or verify a Satelle host before prompt execution.

Completion criterion: the agent has a setup plan, knows whether mutation consent is needed, and knows the next verification command.

2. Use `satelle-use` when the task is to run, steer, inspect, stop, or follow an existing Satelle session.

Completion criterion: the agent has used the session contract instead of treating a one-shot command as disposable state.

3. Use `satelle-recover` when setup, run, steer, status, logs, MCP, or host commands fail or produce readiness blockers.

Completion criterion: the agent has a typed failure, evidence from diagnostics or logs, and a recovery path that preserves state.

4. Stay in this router only for high-level explanation or when choosing among the other skills.

Completion criterion: the response names the specific skill to use next and why.

## Rules

- Prefer Satelle JSON output for agent decisions.
- Treat `session_id` as the public handle. Do not depend on underlying Codex thread IDs.
- Do not handle raw provider secrets in chat, logs, facts, config snippets, or skill output.
- Do not use `--yes`, YOLO mode, raw diagnostic exports, or recording modes unless the user explicitly asks for that risk-bearing behavior.
