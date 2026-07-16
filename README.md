# Satelle

Satelle is a remote computer-use bridge. A controller sends durable work to an
operator-controlled native Host, while the Host owns execution, session state,
logs, and provider credentials.

> [!IMPORTANT]
> Satelle is pre-release software. Build it from source. The npm package names
> reserved by this repository are not published installation paths yet.

## Platform support

| Role | macOS | Windows | Linux |
| --- | --- | --- | --- |
| Controller CLI | Implemented | Implemented | Implemented |
| Native Computer Use Host | Candidate | Candidate | Not supported |

macOS and Windows Host support still requires a successful native readiness
probe on the target machine. Linux can run the controller and generic Codex
substrate, but cannot claim native Computer Use Host readiness.

## Build and try it

Prerequisites are Rust 1.97.0, Node.js 20.9 or newer for the docs, and Codex
0.144.0 on a native Host.

```sh
cargo build --release --locked -p satelle-cli
./target/release/satelle setup --host local-demo --dry-run
./target/release/satelle doctor --host local-demo --scope computer-use --refresh
./target/release/satelle run --host local-demo "Open the browser"
```

The setup command is a plan until mutation consent is explicit. If the native
readiness probe reports a blocker, follow its recovery command before running
work.

## Release surface

The single `satelle` executable includes controller commands and foreground
Host Daemon mode. Implemented paths include local setup planning, configuration
and path inspection, Host start/status/session inspection, run, steer, status,
stop, logs, doctor, shell completions, direct HTTPS/WSS operation, and MCP stdio
serving. Repair, persistent Host lifecycle management, support bundle export,
self-update, SSH execution, and remote setup are unavailable. Source builds are
the only documented installation path until release publication is complete.

## Security model

- The Host Daemon is the authority for execution, durable state, logs, and
  provider Secret Source resolution.
- Project configuration can express shared intent, but cannot define secrets,
  trust material, daemon paths, desktop identity, mutation consent, or YOLO
  enablement.
- Remote direct transport requires HTTPS, a pinned Host identity, a bearer
  token loaded from an owner-only file, and an explicit CA bundle.
- YOLO affects documented Codex approval callbacks only. It does not answer
  native app, operating-system, administrator, security, or sensitive-action
  prompts.
- Prompts and secret material are excluded from normal operational logs.

## Development

```sh
cargo test --workspace --locked
cargo clippy --workspace --all-targets --locked -- -D warnings
npm test
npm run docs:build
```

The documentation source is in [`docs/`](docs/) and the Fumadocs application
is in [`website/`](website/). See the documentation site for installation,
onboarding, command, configuration, transport, diagnostics, and security
guides.

## License

Satelle is licensed under the terms in [`LICENSE`](LICENSE).
