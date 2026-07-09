---
name: satelle-setup
description: Setup Satelle hosts from an AI-agent workflow. Use when configuring a host, planning onboarding, installing or updating the Host Daemon, selecting provider auth, validating readiness, or preparing MCP/client integrations.
---

# Satelle Setup

Bootstrap Satelle without hiding consent or secrets. Prefer planning first, then apply only after the user has approved the exact mutation path.

## Steps

1. Inspect the target context.

Run `satelle config check --json`, then `satelle config explain --json` for the selected host and profile when available.

Completion criterion: local config is valid or the agent has a typed configuration error and suggested commands.

2. Build a setup plan.

Run `satelle setup --host <alias> --no-input --json` for agent-safe planning. Add `--component <name>` only when the user asked for a targeted setup flow.

Completion criterion: the agent has `planned_actions`, `required_input`, `readiness_summary`, and `recovery_commands`.

3. Handle provider auth as references, not secrets.

Use host-resolved Secret Source descriptors such as environment, file, credential-store, or host-store references. Do not ask the user to paste raw provider secrets into the agent conversation.

Completion criterion: any missing provider auth is represented as a descriptor or as a user action requirement, never as raw secret text.

4. Separate consent from configuration.

If the setup plan contains mutations, ask the user before using `--yes`. Never treat project config, profile selection, YOLO mode, or prior prompts as mutation consent.

Completion criterion: either no mutation is needed, or the user explicitly approved the exact setup command that mutates the host.

5. Verify readiness.

After setup, run `satelle doctor --scope computer-use --refresh --json` and provider refresh when the selected provider requires Computer Use validation.

For runtimes or providers that claim pointer control, treat drag gestures as a separate readiness signal from simple clicks when the current binary exposes that diagnostic detail.

Completion criterion: readiness is ready, or the agent reports typed blockers with the next recovery command.

## MCP And Client Setup

When the release exposes MCP client installation, prefer a dry run first:

```bash
satelle mcp install --target <client> --dry-run --json
```

If `satelle mcp install` is not available in the current binary, report that MCP installation is specified but not implemented in this release. Apply only after the user accepts the target, server name, and Satelle binary path.

Completion criterion: the AI client points to the intended Satelle MCP server command, or the dry run explains what would change.
