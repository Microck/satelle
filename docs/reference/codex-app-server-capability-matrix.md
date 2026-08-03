---
title: Codex app-server capability matrix
description: Pinned upstream capabilities, approval boundaries, and native Host readiness blockers.
---

# Codex app-server capability matrix

This reference fixes the upstream contract target for Satelle Phase 0. It is
for Satelle adapter implementers and reviewers. It does not define Satelle's
public CLI, HTTP, WebSocket, event, or MCP names.

The current verdict is **candidate support, not public-release support**. A real
Windows Host run proved the harmless native readiness path through Codex
Desktop's official bundled Computer Use plugin and private app-server session.
The complete Windows Session journey and the macOS acceptance run remain
release blockers. Satelle does not use VNC, browser automation, terminal UI
scraping, or undocumented GUI automation as a substitute.

## Contract sources

The product requirements are the following `.facts` entries:

- `d1k`: Phase 0 real-Host acceptance journey.
- `z4l`: version range and capability-matrix requirement.
- `dk4`: typed missing-capability blocker requirement.
- `8or`: no terminal UI scraping or undocumented GUI automation fallback.
- `agf` and `lfv`: macOS and Windows are native Computer Use Host Platforms;
  Linux is a Controller Platform, not a native Computer Use Host Platform.
- `r7b`, `9uvm`, and `k0f`: native prompts remain operator-visible unless a
  stable callback exists, and capability probes outrank remembered docs.
- `nhx`, `71g`, `80d`, and `zgl`: Windows app-policy discovery resolves the
  active Codex home, recognizes the current allow-list, treats the legacy file
  only as migration input, and does not turn sensitive-action prompts into a
  policy guarantee.
- `hbqw`, `b3i`, and `q0a`: YOLO applies the documented Codex approval and
  sandbox settings without extending into native or operating-system prompts.
- `pr0`, `h2e`, and `sj4`: Satelle steer starts a follow-up Turn on the same
  Session and may return after that new Turn starts.

Upstream evidence:

- [Codex 0.144.0 app-server README](https://raw.githubusercontent.com/openai/codex/rust-v0.144.0/codex-rs/app-server/README.md)
- [Codex 0.144.0 generated protocol schema](https://raw.githubusercontent.com/openai/codex/rust-v0.144.0/codex-rs/app-server-protocol/schema/json/codex_app_server_protocol.schemas.json)
- [Current official Codex manual](https://developers.openai.com/codex/codex-manual.md),
  retrieved 2026-07-09 for current Computer Use platform and approval policy
- [Current Computer Use guide](https://learn.chatgpt.com/docs/computer-use),
  retrieved 2026-07-18 for Windows app-policy storage and migration behavior

The version-tagged README and schema are authoritative for protocol shape. The
current manual is authoritative only for current product availability and
platform policy. A live capability probe on the target Host is the final
authority for readiness.

## Version and transport contract

| Property | Phase 0 contract |
| --- | --- |
| Codex contract target | Exactly `0.144.0` |
| Candidate version range | `>=0.144.0, <=0.144.0` |
| Windows Codex Desktop contract target | Exactly `26.727.6591.0` with bundled Computer Use plugin `26.727.51351` |
| macOS Codex Desktop contract target | Exactly `26.730.61639` with bundled Computer Use plugin inventory version `1.0.1000621` and signed helper version `26.803.1000621` |
| Production support verdict | Blocked until the complete Windows and macOS real-Host acceptance journeys pass |
| Schema surface | Stable schema generated without `--experimental` |
| App-server transport | `stdio://` |
| Framing | One JSON message per line on stdin/stdout |
| Process boundary | Satelle Host Daemon owns the app-server process and stream |
| Excluded upstream transport | `ws://` because Codex documents it as experimental and unsupported |
| Not selected for Phase 0 | Unix-socket control transport; it is unnecessary for the first adapter |

The exact version pin is intentional. A later Codex release is unsupported
until Satelle regenerates its stable schema evidence and reruns the real-Host
acceptance journey. A semver comparison by itself must never mark a release as
compatible.

The upstream stdio choice does not change Satelle's own remote transport. The
Host Daemon may expose Satelle HTTP and WebSocket contracts while keeping
app-server method names and framing private to the adapter.

### Project trust mutation boundary

Codex 0.144.0 documents a Host-side mutation on `thread/start`: when the
request includes `cwd` and the resolved sandbox is workspace-write or full
access, app-server marks that project trusted in the user's `config.toml`.
Creating a Satelle Session must not silently grant that trust.

The Phase 0 adapter therefore starts app-server in a daemon-owned non-project
working directory and omits `cwd` from ordinary Computer Use thread creation.
If a later workflow needs an operator project directory, Satelle must first
model the trust change as an explicit Host mutation with plan presentation,
authorization, consent, and postcondition verification. Merely selecting a
Host, model, provider, sandbox, or YOLO policy is not consent to modify Codex
project trust.

## Capability matrix

Status meanings:

- `available`: documented in the stable 0.144.0 protocol.
- `partial`: a stable primitive exists, but Satelle must add normalization or
  Host-owned state.
- `blocked`: no production support claim is allowed until the stated proof or
  capability exists.

| Satelle requirement | Internal upstream mapping at 0.144.0 | Status | Required interpretation or proof |
| --- | --- | --- | --- |
| Connection readiness | `initialize` request followed by `initialized` notification | available | Perform once per app-server connection before all other requests. |
| Create a Session | `thread/start` and the returned thread identifier | available | Persist the upstream identifier only in Host-owned adapter state. Omit `cwd` by default and start app-server from a daemon-owned non-project directory so Session creation cannot silently change project trust. |
| Start an attached Turn | `turn/start` with the stored thread identifier | available | The response creates the Turn; attached output follows the event stream. |
| Lifecycle events | `thread/started`, `turn/started`, `item/started`, item deltas, `item/completed`, and `turn/completed` | available | Treat `item/completed` as the authoritative item result. The README notes that turn notifications currently carry an empty `items` array. |
| Terminal outcome | `turn/completed` with `completed`, `interrupted`, or `failed` status | available | Normalize upstream status into Satelle's stable Turn state without exposing the upstream spelling. |
| Generic approval callbacks | Stable server requests for command execution, file change, and permission approval | partial | These callbacks cover their documented action classes only. They are not evidence of native Computer Use app approval coverage. |
| Windows persistent app policy | `initialize` supplies the active `codexHome`; `config/read` with layers includes the raw parsed user `config.toml` layer | partial | Match the base user layer to `codexHome/config.toml`, then report `stable` only for a string array at `[computer_use.windows].always_allowed_app_ids`. A legacy `[apps].allowed` list is `private` migration input. Missing policy is `absent`; malformed or unreadable evidence is `incomplete`. Never retain the path or app identifiers. The removed legacy `denied` list is not a fallback. |
| macOS persistent app policy | The signed Computer Use helper stores approved bundle identifiers in its app-group container | partial | Read only `~/Library/Group Containers/2DC432GLL2.com.openai.sky.CUAService/Library/Application Support/Software/ComputerUseAppApprovals.json`. Require a regular non-symlink file below the regular non-symlink group root, enforce the 1 MiB limit and exact JSON shape, and retain identifiers only in process memory. |
| Native Computer Use approval state | The official Computer Use bridge can issue `mcpServer/elicitation/request` for an app-selection decision | partial | Accept only the exact Computer Use connector, official platform bridge (`node_repl` on Windows or `computer-use` on macOS), current thread and Turn, form shape, and app identifier already present in the platform's canonical persistent policy. All other app and sensitive-action prompts remain operator decisions. |
| Native Computer Use readiness | The official bundled plugin loads its platform bridge through the isolated private app-server process | partial | Plugin presence, OS policy, and request acknowledgement are not readiness. The target Host must pass the live harmless click-and-drag probe through the same bridge used for prompt Turns. |
| Harmless native action | One Turn invokes the official Computer Use API through the isolated bridge and observes two private loopback callbacks | partial | The Windows candidate passed an independently observed click and drag. Every supported Host still must pass this live probe, and full Session acceptance remains separate. |
| Restore current Session state after Client reconnect | Satelle Host Daemon state plus stable `thread/read` with `includeTurns`, and `thread/resume` when the adapter must reopen the stored thread | partial | A fresh Satelle Client reads Host Daemon state. If the adapter connection is also fresh, initialize it before reading or resuming. Prove that identifiers, active/terminal Turn state, and approval state survive the Client reconnect. |
| Start a detached steer Turn | `thread/resume` when needed, then a new `turn/start` on the existing thread | partial | Satelle `steer` means a new follow-up Turn after the prior Turn. Detach is Satelle behavior: the Host Daemon keeps ownership and event processing after the requesting Client returns. |
| Inject input into an active Turn | Upstream `turn/steer` | available but excluded from public steer | This method only adds input to an already in-flight regular Turn and requires the expected active Turn identifier. It is not the mapping for Satelle's public `steer` command. |
| Stop an active Turn | `turn/interrupt` with the stored thread and Turn identifiers | available | An empty response only accepts the interruption request. It does not prove that execution stopped. |
| Confirm stopped state | Wait for `turn/completed` with upstream status `interrupted`, then persist Satelle's stopped state | partial | Do not release control ownership or report stopped from timeout, disconnect, request acceptance, or lease expiry alone. Confirm through the terminal event and fresh Client status read. |

## Approval boundary

The stable 0.144.0 server-request schema contains these relevant approval
requests:

- `item/commandExecution/requestApproval`
- `item/fileChange/requestApproval`
- `item/permissions/requestApproval`

Satelle uses this closed response mapping when the committed Turn Execution
Policy has approval `never` and sandbox `danger-full-access`:

| Server request | YOLO response | Scope |
| --- | --- | --- |
| `item/commandExecution/requestApproval` | `{"decision":"accept"}` | Current request only |
| `item/fileChange/requestApproval` | `{"decision":"accept"}` | Current request only |
| `item/permissions/requestApproval` | Echo the requested `fileSystem` and `network` profile with `"scope":"turn"` | Current Turn only |
| `applyPatchApproval` | `{"decision":"approved"}` | Current deprecated request only |
| `execCommandApproval` | `{"decision":"approved"}` | Current deprecated request only |

Satelle deliberately does not return `acceptForSession`,
`approved_for_session`, exec-policy amendments, or network-policy amendments.
Those responses persist authority beyond the callback currently being handled.
Permission responses reject top-level fields outside the pinned `fileSystem`
and `network` profile before anything is echoed to app-server.

The stable generated schema does not list a dedicated native Computer Use app
approval request. The official Desktop bridge can instead issue an
`mcpServer/elicitation/request` for app selection. Satelle accepts only the
closed request shape tied to the official Computer Use connector, the current
thread and Turn, and an app identifier already present in the Host platform's
canonical persistent policy. Windows uses the current allow-list. macOS uses
the signed helper's approval file. That response does not add or persist
authority.

Therefore Satelle Phase 0 must distinguish two outcomes:

1. A supported Host exposes an operator-visible prompt through a documented or
   otherwise supported observable signal. Satelle reports action required,
   waits for the operator to resolve it, and reruns the affected probe.
2. Satelle cannot observe a required approval state or cannot determine whether
   execution may proceed. The adapter returns a typed missing-capability blocker
   and the workflow remains unsupported.

Satelle must not auto-answer native app, operating-system, administrator,
security, or sensitive-action prompts unless a documented stable callback
explicitly permits it. Terminal UI scraping and undocumented GUI automation are
not fallback transports. MCP elicitation outside the exact Computer Use
app-selection shape, dynamic tool calls, user-input requests, unknown methods,
and future approval-like method names are not part of the YOLO allowlist.
Satelle must not auto-answer them. When a supported operator-visible prompt
exists, Satelle reports action required and waits. Otherwise, it returns a
typed missing-capability blocker.

## Typed blocker contract

Adapter discovery must produce a typed support verdict before Satelle claims a
workflow as supported. A missing-capability blocker must carry, at minimum:

- a closed capability key, such as connection handshake, Turn start, lifecycle
  events, native readiness, approval observation, stop confirmation, or thread
  recovery;
- the detected Codex version;
- the detected Host platform;
- whether the only observed surface is stable, private, experimental,
  undocumented, absent, or incomplete; and
- evidence suitable for diagnostics, without prompt content or secrets.

The blocker is an internal adapter type. Its translation into Satelle public
errors belongs to the public contract layer. A free-form log message alone does
not satisfy `dk4`, and a blocked verdict must prevent the affected workflow
from being advertised as ready.

## Platform constraints

The current official manual says native Computer Use in the ChatGPT desktop app
is available on macOS and Windows in supported regions. It also separates OS
permissions from app approvals:

- macOS requires Screen Recording and Accessibility permissions;
- Windows requires the target app to remain visible on the active desktop;
- Windows persistent app decisions use
  `[computer_use.windows].always_allowed_app_ids` in
  `$CODEX_HOME/config.toml`; and
- macOS persistent app decisions use the signed helper's exact app-group
  `ComputerUseAppApprovals.json`; and
- app approvals may still require direct user action.

The Windows Host probe obtains the active Codex home from the live app-server
`initialize` response, not from a remembered default path. It reads the raw
parsed base user layer through `config/read` and requires that layer to identify
the resolved home's `config.toml`. Only when the current key is absent does it
inspect `$CODEX_HOME/computer-use/config.toml`; `[apps].allowed` is private
migration evidence, while `[apps].denied` is ignored because the current policy
schema removed it. A stable app allow-list does not prove that Satelle can
observe or resolve a later sensitive-action prompt.

The macOS Host probe first admits the exact managed Codex runtime. It then
reads only the signed Computer Use helper's app-group approval file named
above. It rejects redirected group roots, redirected files, non-files, files
larger than 1 MiB, and any JSON shape other than the current
`approvedBundleIdentifiers` string array. The identifiers never enter
diagnostics, public events, or Satelle persistence.

For Satelle MVP, macOS and Windows are candidate native Computer Use Host
Platforms. Linux may run the Controller and test the generic app-server
substrate, but it must return an unsupported-platform capability verdict for
native Computer Use Host execution.

## Reproducible protocol proof

The following commands establish the installed version and stable protocol
surface. They do not establish native Computer Use readiness:

```sh
codex --version

stable_schema_dir="$(mktemp -d)"
codex app-server generate-json-schema --out "$stable_schema_dir"

jq -r '.oneOf[] | .properties.method.enum[]' \
  "$stable_schema_dir/ClientRequest.json" \
  | grep -E '^(initialize|thread/(start|resume|read)|turn/(start|steer|interrupt))$'

jq -r '.oneOf[] | .properties.method.enum[]' \
  "$stable_schema_dir/ServerRequest.json"
```

On 2026-07-09 the local proof returned `codex-cli 0.144.0`, and the stable
schema contained the lifecycle and approval methods recorded above.

This text-only smoke command also completed initialization, thread creation,
Turn creation, item streaming, and terminal completion through app-server:

```sh
codex debug app-server send-message-v2 \
  'Reply exactly SATELLE_APP_SERVER_OK. Do not call tools or access files.'
```

The observed final reply was `SATELLE_APP_SERVER_OK`. This proves only the
generic control substrate. It is not a native Computer Use acceptance result.

## Real-Host Phase 0 acceptance record

The release evidence for one supported Host must record all of the following in
one run:

1. Host platform and version, Codex version, app-server schema hash, native
   Computer Use runtime or plugin version, and desktop-session identity.
2. Structured readiness and approval-state results.
3. One live harmless action whose expected result is independently observable.
4. One attached native Computer Use Turn reaching a terminal state.
5. A fresh Satelle Client reconnecting and reading the same Session state.
6. One detached Satelle steer operation starting a new follow-up Turn on the
   same Session.
7. A stop request followed by confirmed terminal interruption.
8. A fresh status read showing the normalized stopped state.

The run fails if it substitutes a text-only Turn, terminal UI scraping,
undocumented GUI automation, plugin presence, a feature flag, or a request
acknowledgement for the required action-path and terminal-state evidence.

### Windows native readiness record: 2026-08-04

The real Host candidate used Windows 11 ARM64 build 26200 in the active console
session, Codex CLI 0.144.0, Codex Desktop 26.727.6591.0, and the official
bundled Computer Use plugin 26.727.51351.

The final probe started `satelle setup --verify --no-input --json` inside the
active desktop session. Satelle launched a private stdio app-server, enabled
only the validated official Computer Use plugin and its Desktop-owned native
bridge, and disabled unrelated configured MCP servers and plugins. A topmost
private loopback page required an independent click and drag. The official
Computer Use API produced both callbacks, and the probe read both event labels
back from the accessibility tree.

The command exited with status 0 after 38.617 seconds. Its versioned JSON report
recorded `verification.status = "passed"`, `result.status = "ready"`,
`ready = true`, no blocking findings, and a passed
`computer-use.native.refresh` probe. The run used the public 120-second timeout
and did not use a Host-specific timeout override.

This proves only the Windows native readiness portion of facts `d1k` and `z4l`.
It does not prove the negative-path or no-fallback guarantees in `dk4` and `8or`.
It is not the complete Phase 0 acceptance record: the attached Session,
fresh Controller reconnect, detached follow-up Turn, confirmed stop, and fresh
terminal status still need one continuous Windows proof. macOS acceptance also
remains required before public release.

## Current blockers

| Blocker | Consequence |
| --- | --- |
| The complete Windows Session acceptance journey has not passed | Native readiness alone does not prove reconnect, follow-up Turn, detached ownership, or confirmed stop. |
| No passing macOS Host acceptance record exists | Public MVP support requires a complete real-Host acceptance run on macOS. |
| Native app and sensitive-action prompts outside the exact allowed-app elicitation shape remain operator-only | Satelle must report action required or a typed blocker and must not broaden YOLO authority. |
| Only 0.144.0 has been inspected | All other Codex versions remain unsupported until schema and real-Host validation pass. |
| Linux lacks official native Computer Use Host support | Linux validation may cover Controller and generic protocol behavior only. |
