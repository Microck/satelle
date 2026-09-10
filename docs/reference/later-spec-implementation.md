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
| Configuration composition and consent | Explicit includes, source attribution, Trusted Profile expiration | Verified in PR #218 |
| Credential sources and config repair | Executable helpers, Host home expansion, deterministic local repair | Pending |
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
