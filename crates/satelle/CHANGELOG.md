## satelle@0.1.33

### Host startup and recovery

Keep detached Windows desktop Hosts alive after the bootstrap SSH connection closes. Preserve hidden helpers and stop unconfirmed handoff tasks.

Open native Windows null handles correctly and report redirected PowerShell failures with their real exit codes.

Recover interrupted inactive Windows Host starts and POSIX service restarts after checking the daemon, service, listener and old launcher twice. Preserve the original claim, execution markers and diagnostic mailbox without treating an unknown restart as successful.

Detect the canonical Mac launchd service and full Host executable paths during recovery.

### Unix installation

Reap download and polling children before releasing an interrupted install lock, including termination during child PID capture.

## satelle@0.1.32

### Bootstrap recovery

Recover interrupted POSIX setup begins whose claim directory nonce differs from the private claim identity. Preserve ownership, stale-heartbeat, execution-marker and no-ledger-run checks, and archive the whole claim with a receipt.

## satelle@0.1.31

### Quiet background commands

Hide background SSH, update, telemetry and batch helper processes on Windows. Preserve interactive terminals and app-access or operating-system approval prompts.

## satelle@0.1.30

### Background Windows hosts

Keep background bootstrap helpers, Host Daemons and provider processes out of visible terminal windows. Keep app-access and operating-system approval prompts visible.

End the persistent Host Daemon and its children when its scheduled task stops.

Validate hidden scheduled-task actions during service discovery and maintenance. Use absolute-path checks supported by Windows PowerShell.

## satelle@0.1.29

### Host recovery

Run Windows interactive and persistent Host tasks at normal priority so managed SDK verification can finish promptly.

Run Doctor on authenticated direct and SSH Hosts. Keep diagnostics on the Host that owns readiness and require control permission.

Keep local daemon and SSH tunnel traffic away from unrelated HTTP proxy settings.

Create Windows bootstrap metadata and execution markers with explicit user ownership and protected permissions.

Recover an orphaned setup begin only after exclusive local store ownership proves it has no retained ledger run. Preserve the original claim and a durable recovery receipt.

Show safe startup stages when managed Codex admission stalls.

## satelle@0.1.28

### Native recovery

Reconnect to a stopped Mac Host Daemon after an SSH connection reset.

Refresh stale signed Windows Computer Use bundles during explicit setup and accept the current official backend inventory while keeping native runtime access restricted.

Recognize current native app-access questions by canonical app identity. Preserve the official Windows registered-core inheritance declarations during setup and native execution.

Keep the Mac control service reachable while a saved app-approval read waits on a macOS privacy decision. Report a bounded native-readiness error instead of hanging startup.

Verify control connections and service restarts through host status without waiting for native readiness.

Show the owning maintenance operation when setup or a task is blocked by host maintenance.

## satelle@0.1.27

### App access

Show supported native app requests in Satelle and accept an explicit allow once, Always allow, or deny decision. Resume the same task after the response. Saved approval uses the official native SDK; OS permissions remain manual.

Open named Mac apps directly instead of requiring Finder discovery first.

### Readiness recovery

Reconcile interrupted provider probes before checking native readiness, while preserving running and unknown-outcome guards.

## satelle@0.1.26

### Native task results

Report a task as blocked when native app approval was denied, even if an earlier tool call succeeded.

### Windows readiness

Keep the native click-and-drag readiness surface in physical pixels so display scaling and window borders do not move the targets away from the authenticated screenshot coordinates.

## satelle@0.1.25

### Recovery

Read completed native readiness and session turns from their private Codex home without creating incomplete MCP server entries from another home. This lets supported recovery reconcile a failed turn before retrying readiness.

## satelle@0.1.24

### Native readiness diagnostics

Report classified Codex turn failures from the native readiness probe instead of hiding them behind a generic session failure.

## satelle@0.1.23

### Native Computer Use setup

Launch the Mac native bridge with the same verified environment admitted by Satelle. This fixes a startup failure caused by requiring instruction fields that native isolation removes.

Accept Codex's filtered Windows marketplace catalog while verifying every retained entry and all Computer Use plugin files against the protected desktop bundle. This fixes setup failures when Codex omits unrelated plugins from its catalog.

## satelle@0.1.22

### Setup fixes

Report an invalid existing managed Codex installation before changing its files, so setup can fail without leaving an uncertain maintenance operation.

Prevent native app-server startup from creating incomplete entries for unrelated MCP servers in the private binding home. This fixes a Mac startup failure while preserving the verified Computer Use bridge.

Use the verified official bundled Computer Use marketplace snapshot on Windows. This fixes setup failures when current Codex rejects the protected desktop resource directory as a marketplace source.

## satelle@0.1.21

### Installation

Publish the current Satelle package set as version 0.1.21. Runtime behavior is unchanged from 0.1.20.

## satelle@0.1.20

### Setup

Keep the Host owner's local credential aligned with configured desktop bindings, so adding a desktop no longer blocks local setup with an idempotency conflict. Credential identity, scope, and revocation checks remain enforced.

Keep the on-demand daemon on port 3001 after setup, so the final readiness check and later commands reach the same daemon.

## satelle@0.1.19

### Installation

Publish the current Satelle package set as version 0.1.19. Runtime behavior is unchanged from 0.1.18.

## satelle@0.1.18

### Host startup

Keep setup reachable before a desktop is configured. Managed SSH and persistent daemons now use the Host user's desktop and provider bindings without changing service storage paths.

## satelle@0.1.17

### Installation

Publish the current Satelle release through npm and native archives.

## satelle@0.1.16

### Installation

Release the latest managed Codex setup and Host automation through npm and
native archives. This replaces the partially published npm version 0.1.15.

## satelle@0.1.15

### Installation

Publish the Cargo package correctly when no previous version exists on crates.io.
This release includes the managed Codex updates and Host automation prepared for
0.1.14, whose publication stopped before any registry package was published.

## satelle@0.1.14

### Managed Codex updates

Install or upgrade to the latest stable official Codex during managed setup.
Verify release digests and the installed binary before selecting the new runtime,
and preserve the working installation when an update fails.

Report unsuccessful native Computer Use readiness actions promptly instead of
waiting for the probe deadline. Improve daemon reconnect and log-follow recovery.

### Automation and Host management

Add batch, watch, notification and interactive REPL workflows, durable turn queues,
multi-user desktop selection, explicit image attachments and consented recordings.
Manage API tokens and Host credential sources, and support configuration includes
and expiring trusted profiles.

### Installation and diagnostics

Make the Satelle executable available as a single Cargo package. Add optional
mutual TLS, OpenTelemetry and native log sinks, desktop snapshot export, and
support bundles with explicit consent for raw diagnostics.

## satelle@0.1.13

### Native setup and recovery

Count only installed Computer Use plugins during readiness checks, including
plugins exposed by remote sources.

Preserve managed setup failures for recovery and install Satelle's Codex package
under private Host state while continuing to use the existing Codex home for
authentication.

Validate macOS bridge runtime values directly. Leave Host metadata absent after
an offline store reset so first SSH trust can enroll the stopped Host again.

## satelle@0.1.12

### Native readiness and durable recovery

Make Windows native readiness checks and managed Codex startup tolerate slow
version probes, transient failures, and stale Computer Use plugin sources.

Recover admitted operations after transport loss, preserve failure classes,
and allow offline reset of abandoned operation metadata.

## satelle@0.1.11

### Windows bootstrap maintenance and slow-daemon startup

Admit the managed-setup action shapes (`bootstrap-handoff`, `managed-codex`,
`native-computer-use`, and the persistent-service variant) in bootstrap
maintenance so full setup no longer fails at maintenance begin.

Report bootstrap-busy when the Windows lock holder exits with the busy code
instead of misclassifying the result, and wait out the daemon's own
readiness budgets before declaring a slow Windows daemon unreachable.

## satelle@0.1.10

### Windows native startup and doctor diagnostics

Fix Windows native Computer Use startup failing to read `kernel.js` by granting
the Codex sandbox read and execute access to each session's private bridge
files. Keep those files until process shutdown is confirmed.

Report doctor timeouts from the current probe execution instead of showing
stale timeout diagnostics.

## satelle@0.1.9

### Windows app-policy probe reliability

Allow up to three 30-second app-policy handshake attempts within the caller's
absolute deadline. Stop retries when process or reader cleanup is unconfirmed.
This reduces readiness failures caused by transient app-server handshake stalls.

## satelle@0.1.8

### Windows CI reliability

Eliminate stdin-EOF races in the MCP integration tests that flaked Windows CI
runs. No behavior change.

## satelle@0.1.7

### Diagnostic support bundles

Export a redacted diagnostic bundle with `satelle support bundle` when normal
diagnostics are not enough, and run Windows persistent Hosts on the documented
interactive-token logon task.

## satelle@0.1.6

### Native Computer Use execution

Run production local operations through one durable loopback Host Daemon, with native Computer Use execution on Windows and macOS.

## satelle@0.1.5

### Linux compatibility

Run GNU Linux packages on glibc 2.17 and newer systems, including older supported distributions.

## satelle@0.1.4

### Native Computer Use setup

Make authenticated setup and native Computer Use sessions work on current macOS and Windows
runtimes, including reconnect, detached steering, stop, and recovery.

## satelle@0.1.3

### Windows installation reliability

Ship self-contained Windows binaries that run on clean systems without a separately installed
Visual C++ runtime.

## satelle@0.1.2

### Native acceptance and release reliability

Complete authenticated Host setup and native Computer Use acceptance on macOS and Windows.
Harden installer locking, release publication recovery, npm validation, and process containment
for reliable upgrades and public artifacts.

## satelle@0.1.1

### Satelle public MVP

Ship the first public Satelle release with the Controller, Host Daemon, native desktop control,
multi-Host operations, diagnostics, repair, updates, MCP tools, and signed cross-platform packages.
