---
title: Codex app-server capability matrix
description: Pinned upstream capabilities, approval boundaries, and native Host readiness blockers.
---

# Codex app-server capability matrix

This reference fixes the upstream contract target for Satelle Phase 0. It is
for Satelle adapter implementers and reviewers. It does not define Satelle's
public CLI, HTTP, WebSocket, event, or MCP names.

The current verdict is **not production-supported yet**. Codex 0.144.0 has the
stable thread, turn, event, interrupt, and recovery primitives that Satelle
needs, but the native Computer Use action path and approval-state handling have
not yet passed the required proof on a real supported Host.

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
| Production support verdict | Blocked until the real-Host acceptance journey passes |
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
| Native Computer Use approval state | No documented native app or sensitive-action approval callback appears in the stable `ServerRequest` union | blocked | The current manual says Computer Use app approvals surface directly to the user. Satelle must surface an observable prompt as `action_required` or a manual-action-required blocker. If the prompt cannot be observed through a supported signal, return a typed missing-capability blocker. |
| Native Computer Use readiness | `configRequirements/read` exposes only the managed `computerUse.allowLockedComputerUse` constraint | blocked | This field is policy, not proof of plugin installation, enablement, OS permissions, app approval, desktop availability, or action-path readiness. A live harmless action is mandatory. |
| Harmless native action | A normal Codex Turn may invoke native Computer Use; app-server has no separate readiness-success request | blocked | Prove on a supported Host by observing the expected nonce and harmless visible action through the same path used for prompt Turns. Plugin presence alone is insufficient. |
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

It does not contain a documented native Computer Use app-approval or
sensitive-action callback. The current official manual also says Computer Use
app approvals surface directly to the user and are separate from shell, file,
and sandbox approvals.

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
not fallback transports. MCP elicitation, dynamic tool calls, user-input
requests, unknown methods, and future approval-like method names are not part of
the YOLO allowlist and remain declined, failed, or unsupported.

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
- app approvals may still require direct user action.

The Windows Host probe obtains the active Codex home from the live app-server
`initialize` response, not from a remembered default path. It reads the raw
parsed base user layer through `config/read` and requires that layer to identify
the resolved home's `config.toml`. Only when the current key is absent does it
inspect `$CODEX_HOME/computer-use/config.toml`; `[apps].allowed` is private
migration evidence, while `[apps].denied` is ignored because the current policy
schema removed it. A stable app allow-list does not prove that Satelle can
observe or resolve a later sensitive-action prompt.

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

## Current blockers

| Blocker | Consequence |
| --- | --- |
| No real macOS or Windows Host acceptance record exists yet | Fact `d1k` remains unproven and Phase 0 cannot complete. |
| Stable app-server has no documented native app-approval callback | Satelle must prove supported prompt observation and manual recovery, or report a typed capability blocker. |
| Native readiness has no single stable success request | Satelle must implement and pass the live harmless readiness probe before prompt execution. |
| Only 0.144.0 has been inspected | All other Codex versions remain unsupported until schema and real-Host validation pass. |
| Linux lacks official native Computer Use Host support | Linux validation may cover Controller and generic protocol behavior only. |
