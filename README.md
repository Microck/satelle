# Satelle

Satelle is a self-hosted control plane for durable native Computer Use. A
Controller sends work to an operator-controlled Host, while the Host owns
execution, Session state, logs, desktop access, and provider credentials.

> [!IMPORTANT]
> Satelle is pre-release software. Build it from source. This tree is version
> 0.1.0. The npm package names reserved by this repository are not published
> installation paths yet.

The [installation guide](docs/how-to/install-satelle.mdx) lists the reserved
package identities, the post-publication commands, and the currently available
source-build path without presenting unpublished packages as usable.

## Run the shortest successful flow

Install Rust 1.97.0 and Codex 0.144.0 on a candidate macOS or Windows Host,
then build Satelle from the repository root:

```sh
cargo build --release --locked -p satelle-cli
```

Review the local setup plan, then prove that the visible desktop is ready:

```sh
./target/release/satelle setup --host local-demo --dry-run
./target/release/satelle doctor --host local-demo --scope computer-use --refresh
```

Start one attached Turn and save the returned `session_id`:

```sh
./target/release/satelle run --host local-demo "Open the browser"
```

The Session is durable. A fresh Controller process can inspect it, start a
detached follow-up Turn, stop that Turn, and confirm the terminal state:

```sh
./target/release/satelle status <session_id> --host local-demo
./target/release/satelle steer <session_id> --host local-demo --detach "Open settings"
./target/release/satelle stop <session_id> --host local-demo
./target/release/satelle status <session_id> --host local-demo
```

`ready` from the live Computer Use probe is required. A binary, plugin, or
feature flag alone is not proof that native desktop control works.

## Platform support

Controller support and native Computer Use Host support are different:

| Role | macOS | Windows | Linux |
| --- | --- | --- | --- |
| Controller CLI | Implemented | Implemented | Implemented |
| Native Computer Use Host | Candidate | Candidate | Not supported |

Candidate Host support means that the target machine must pass the live native
readiness probe. Linux can run Controller commands and generic Codex substrate,
but it cannot claim native Computer Use Host readiness in this release.

## Implemented surface

The single `satelle` executable currently provides:

- Local, direct HTTPS/WSS, and authenticated SSH-tunneled Controller paths.
- Local setup planning and SSH on-demand transport token handoff with explicit
  consent.
- Direct Host identity trust for an operator-provisioned token and CA bundle.
- Durable `run`, `steer`, `status`, `stop`, and normalized `logs` operations.
- Host start, status, desktop-session inspection, and live `doctor` probes.
- Configuration check/explain, resolved paths, shell completions, and MCP stdio
  serving and client configuration installation.
- Human output, stable JSON results, and command-specific lifecycle events.

The following surfaces are not implemented and must not be treated as
available:

- Public npm packages or release archives.
- Local setup mutation after planning.
- Direct transport setup or automatic direct-token provisioning.
- Persistent Host service installation and Host stop/restart lifecycle control.
- Repair, Host update, self-update, storage migration, or support bundle export.
- The Satelle Agent Skill Bundle and `satelle skills` commands.
- Native Linux Computer Use Host execution.

Source builds are the only documented installation path until release
publication is complete.

Use `satelle <command> --help` as the exact option reference for the binary you
are running.

## Security model

- The Operator controls each Host, Desktop Binding, provider credential, unsafe
  execution policy, and state-changing maintenance action.
- The Host Daemon is authoritative for execution, durable state, logs, API
  authentication, and provider Secret Source resolution.
- Project configuration can express shared intent, but cannot define secrets,
  trust material, daemon paths, desktop identity, mutation consent, or YOLO
  enablement.
- Direct transport requires HTTPS or WSS over TLS, a pinned Host identity, a
  bearer token loaded from an owner-only file, and an explicit CA bundle.
- SSH authenticates the tunnel but does not replace Satelle API authentication
  or Host identity verification.
- YOLO affects documented Codex approval callbacks only. It does not answer
  native app, operating-system, administrator, security, or sensitive-action
  prompts.
- Raw provider secrets, prompts, transcripts, and desktop content are excluded
  from normal operational logs. Other diagnostic metadata can still be
  sensitive and must be reviewed before sharing.

Report vulnerabilities privately according to [SECURITY.md](SECURITY.md). Do
not attach secrets, prompts, transcripts, screenshots, or unredacted diagnostic
output to a public issue.

## Documentation

The public documentation follows the Diataxis structure:

- [Tutorial](docs/tutorial/first-session.mdx): complete a first durable Session.
- [How-to guides](docs/how-to/): set up Hosts, connect remotely, operate
  Sessions, review installation methods, and diagnose failures.
- [Reference](docs/reference/): inspect command, configuration, and provider
  authentication machinery.
- [Explanation](docs/explanation/): understand security boundaries, Trusted
  Profiles, and YOLO.

The [documentation index](docs/index.mdx) is the best starting point. The
`.facts` sheet remains the product specification source of truth; public docs
are derived from frozen facts, current CLI help, and implemented behavior.

## Development

The Rust CLI and Host do not depend on the documentation application. Node.js
20.9 or newer is needed only for repository checks and the Fumadocs site.

```sh
cargo test --workspace --locked
cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
npm test
npm run docs:build
```

## License

Satelle is licensed under the [MIT License](LICENSE).
