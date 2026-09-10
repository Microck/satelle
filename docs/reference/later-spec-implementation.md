---
title: Later spec implementation
description: Delivery and verification of the phase 4 requirements.
---

The `.facts` sheet is the contract. This page tracks delivery blocks for the
318 requirements marked `@later` at the start of phase 4, based on `08aba611`.
Requirements stay marked `@later` until their implementation and verification
are complete. Completed requirements retain `@phase4` and gain `@implemented`.

Each block is reviewed in a pull request targeting `feat/later-specs`. After
those pull requests merge, the integration branch gets a final pull request to
`main`. Compilation and test builds run in Box; local work keeps source only.

| Block | Scope | Status |
| --- | --- | --- |
| Configuration composition and consent | Explicit includes, source attribution, Trusted Profile expiration | Merged in PR #218 |
| Host credential sources | Executable helpers with bounded JSON protocol, Host home expansion | Merged in PR #219 |
| Config repair | Deterministic local repair with backups and explicit consent | Box verified; pull request pending |
| Host operations | Storage migration, CLI/Host compatibility, explicit versions, plain update output | Pending |
| Transport and inputs | Mutual TLS, token lifecycle, remote image attachments | Pending |
| Output and package repair | Lossless output formats, launcher native repair | Pending |
| Sensitive diagnostics | Shared export consent, redaction, manifest, staging, audit, diagnostic bundles | Pending |
| Capture and observability | Raw protocol/subprocess exports, desktop snapshot, recording, native log sinks, telemetry | Pending |
| Durable admission | Queue storage, cancellation, expiry, reauthorization, restart recovery | Pending |
| Multiple desktop bindings | Broker authorization, isolation, per-binding leases and readiness | Pending |
| Automation | Batch, watch, webhook notifications, REPL, command history | Pending |
| Distribution and native action relay | Cargo package, conditional ecosystem publishing, capability-gated action confirmation | Pending |

Package repository submissions, staged npm publishing, and native action relay
retain the prerequisites declared in `.facts`. A missing external capability
or approval is a blocker, never proof of implementation.

## Configuration contract decisions

The first 24 requirements passed the complete Rust suites and Clippy on Linux,
macOS, and Windows, plus npm checks and the documentation build. Box verified
220 core tests and 36 targeted configuration integration tests.

- `include` is an array of explicit TOML file paths. Each file uses the schema
  and authority of its containing source, user or project.
- Includes run in list order before the including file. Host Bindings and
  Trusted Profiles retain the existing complete replacement semantics.
- Includes remain inside the top-level config file's directory tree. Project
  includes stay inside the discovered `.satelle` directory.
- Every included file is validated, even when a later file replaces its values.
- `expires_at` is an optional RFC 3339 UTC string on a user-owned Trusted
  Profile. Omission does not create an expiry. An expired profile supplies no
  mutation consent; explicit command consent or an interactive confirmation is
  still available.

## Credential helper contract decisions

The next 36 requirements passed the complete Rust test suites and Clippy on
Linux, macOS, and Windows. npm and documentation checks passed. Box also
verified helper success and failure responses, deadlines, descendant cleanup,
authorized runtime resolution, configuration inspection, and home-path handling.

- `kind = "executable-helper"` uses `argv`, optional `timeout` (default `10s`),
  and optional `environment` entries. The executable must be an absolute path
  on the Host. Arguments are literal; shell launchers and inline commands are
  invalid. The Host validates its platform grammar before execution.
- Stdin contains one object with `schema_version = 1`, `operation = "resolve"`,
  `provider_alias`, `resolved_provider`, and `host_alias`. Stdin closes after
  this request. Neither prompts nor existing credentials enter the request.
- Stdout contains exactly one object with `schema_version = 1`. A successful
  response has `status = "success"` and a nonempty `secret` string. A failure
  has `status = "error"` or `"interaction_required"` and a nonempty `code`.
  Unknown fields, NULs, non-UTF-8 output, and output over 64 KiB are rejected.
- The helper receives no terminal. Satelle discards stderr and does not answer
  prompts. The timeout covers the process and its pipes; Satelle terminates
  the helper process group when it finishes or reaches the deadline.
- The inherited environment consists of `HOME`, `USERPROFILE`, `SystemRoot`,
  `WINDIR`, `TMPDIR`, `TMP`, `TEMP`, `LANG`, and `LC_ALL` when present. Explicit
  entries contain literal non-secret settings. No full environment inheritance,
  PATH lookup, interpolation, or project-provided entries are supported.
- Config inspection never executes helpers. Explain output always redacts
  executable identity, every argument, environment key names, and environment
  values, including with `--show-secret-references`; it reports the effective
  timeout. Helper output and response error codes are never copied to logs.

## Host home path contract decisions

- Provider File descriptors accept absolute paths, bare `~`, and `~/...`.
  Windows Hosts also accept `~\...`. Other relative paths, named-user forms,
  misplaced home-expansion components, environment substitutions, and command
  substitutions fail. Embedded tildes in filenames, including Windows short
  names, remain literal characters.
- Expansion uses the resolving process account's OS home, before the Host
  validates its native absolute-path grammar or opens the file. The expanded
  absolute path is the effective file reference in the Host binding, including
  stored authorizations and provisioning destinations. The configured shorthand
  remains input and does not change the account that resolves it.
- POSIX resolution reads the effective user's account record. Windows uses
  the process account's known Profile folder. `HOME`, `USERPROFILE`, Satelle
  path overrides, SSH login settings, and `desktop_user` do not select this home.
- Config check validates syntax only. Config explain reveals an expanded
  reference only with `--show-secret-references` for a local on-demand Host.
  Other Hosts report `normalization_status = "remote_home_not_checked"`.
- Typed failures include `config_file`, `toml_path`, `host`,
  `secret_source_kind`, `resolver_os`, and `supported_forms` under `details`.
  A field is null when its source location or resolver is not known at that
  boundary. Failure messages never contain the secret-file path or contents.

## Config repair contract decisions

Box verified 229 core tests, 45 configuration integration tests, the interactive
repair test, workspace Clippy, and the generated documentation contract.

- `satelle config repair` selects the local user configuration file by default.
  `--file <path>` explicitly selects a loaded user or project configuration file,
  including an explicit include. No other file is edited.
- Repairs convert schema key spelling to its exact accepted lowercase,
  underscore form, for example `default-host` to `default_host`. A repair must
  have exactly one accepted spelling and no existing destination key. Repairs
  preserve values and comments. They never guess values, remove fields, or fix
  arbitrary misspellings through a fuzzy match.
- Each invocation validates the entire prospective configuration through the
  normal loader before offering a mutation. Other diagnostics require manual
  action. A dry-run is a redacted report, never a reusable apply plan.
- `--dry-run` reports the selected file, diagnostics, planned write, private
  backup path, original and repaired digests, restore command, and redacted
  unified diff of canonical JSON with the config-explain redaction policy. It
  creates no files or command-history entries. Comments remain in the edited
  TOML file but do not enter the preview.
- A mutation needs `--yes`, one final interactive confirmation, or a matching
  user-owned Trusted Profile with `config_repair` consent. Trusted Profiles
  apply only when every edit lies inside the explicitly selected Host Binding;
  they cannot authorize root, profile, or trust-policy edits.
- The command creates and verifies a byte-for-byte backup under the Controller
  state directory before replacing the selected file. It checks that the source
  still matches the preview, then uses the existing atomic config writer while
  preserving permissions. Any failure retains the backup and restore command.
