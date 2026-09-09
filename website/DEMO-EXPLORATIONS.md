# Four animated landing workflows

This revision replaces the six exploratory concepts with the four requested
workflows, in order, on both `/` and `/demo-explorations`. The comparison route
remains `noindex`, but no longer offers a selection UI. Old `demos` and `view`
query parameters are ignored. The homepage hero, documentation routes, theme
tokens, dependencies, and original demo modules are unchanged.

## Scenes

| Order | Surface | Script |
| --- | --- | --- |
| 01 | Website QA | Type a checkout test request; add an item; open checkout; type an invalid email; observe the validation failure; show example QA notes. No purchase is made. |
| 02 | Claude Desktop-style chat | Ask which Hosts are available; read configured contexts with `config_check`; show `studio-mac` and `ops-pc`; ask for a browser task on `studio-mac`; show detached `run` admission. |
| 03 | Claude Code terminal and Host browser | Type a request targeting `ops-pc`; show a Satelle `run` call; browse a reports dashboard; download `September.csv`; open the Finance destination; select the downloaded file in a native picker; upload and show an illustrative confirmation. |
| 04 | macOS desktop | Type a wallpaper request; move to System Settings; choose Wallpaper; select Mountains; crossfade the desktop background; close Settings and reveal the changed desktop. |

Application furniture is illustrative, not clickable product chrome. The actual
controls are outside each application: Play/Pause, Replay, and individually
labelled step buttons. Source inspectors are native disclosures on the review
route. No control executes a command, calls MCP, contacts a Host, or transfers a
file. The examples use synthetic domains, data, findings, aliases, and outcomes.

## Motion contract

`workflow-motion.tsx` owns a finite requestAnimationFrame clock shared by all
four scenes. Beat definitions and the pure `sample` projection are in
`exploration-data.ts`.

- Autoplay starts once when at least 15% of a player enters the viewport. It
  reaches the final frame and stops; there is no automatic loop.
- Leaving the viewport or hiding the document suspends the clock. Returning
  resumes from the same position. An explicit Pause is not undone by scrolling.
- Human prompts are typed. Tool results arrive as blocks rather than being
  typed character by character.
- Pointers are measured against actual DOM targets, not desktop-only hardcoded
  coordinates. They arrive in 620ms; the corresponding app state commits at
  720ms. Pointer interpolation, the upload bar, and the wallpaper crossfade use
  the same clock, so Pause also freezes those changes.
- Replay restarts that scene only. Step buttons pause at the end of the chosen
  beat, showing its complete contents. Keyboard Enter/Space operate the native
  controls. Step changes have a polite, atomic status announcement; screen
  readers receive complete prompt text, not a stream of individual characters.
- SSR renders complete, readable scenes. In `prefers-reduced-motion: reduce`,
  autoplay is skipped, all scenes show their finished state, CSS motion is
  disabled, and manual step exploration remains available. A preference change
  while running takes effect immediately.
- Observers, listeners, and animation frames are cleaned up on unmount.

Styles are scoped to the landing tree and reuse its existing light/dark tokens.
The desktop wallpaper is a lightweight CSS illustration, not a downloaded asset.
No font or animation dependency was added.

## Fidelity and assumptions

Baseline: `c2c4c9d5bddaaad1a151436cd7bf41b59c948748`, Satelle 0.1.10 on the
PR branch. These are designed scenes, not recorded or verified task executions.

| Claim / field | Source in this repository | Boundary |
| --- | --- | --- |
| `config_check({ all: true })` | `crates/satelle-cli/src/mcp/schema.rs` | This is a read-only configuration check, not Host discovery. |
| `checked_contexts[].host`, `status`, and `not_checked` | `crates/satelle-cli/src/read.rs`, `config_check_report` | The list is derived from configured contexts. Remote Host availability, provider authentication, and native Computer Use are explicitly not checked. The visible rows say Configured, never Online or Ready. |
| Config result version | `crates/satelle-cli/src/mcp/output-schema.rs` | `satelle.config.check.v1`. Inspectors contain selected fields, not a fabricated full result. |
| `run` arguments `host`, `prompt`, `detach` | `crates/satelle-cli/src/mcp/schema.rs` | Mutation tools must already have been enabled on the MCP server. The example does not enable them or grant OS permissions. |
| Detached `run` reports `starting` | `crates/satelle-cli/src/main.rs`, `print_detached_session` | Admission is not task completion. The CLI transcript labels this as admission; later browser results are separate illustrative application state. |
| Claude Desktop and Claude Code client targets | `crates/satelle-cli/src/mcp/install.rs` | Client layouts are illustrations, not exact vendor screenshots or new Satelle-specific plugins. |
| Native desktop operations | `README.md`, `docs/tutorial/first-session.mdx` | macOS and Windows Hosts remain candidates and require a live readiness pass. Native Linux Host execution is unsupported. |
| Dashboard download/upload | Generic native browser task, carried by `run` | Assumes authorized, signed-in sites on `ops-pc`. The file stays on that Host between the browser download and browser upload; no Satelle file-transfer API or cross-Host copy is implied. |
| QA notes and wallpaper result | Synthetic illustration | Not a built-in QA dashboard, recorded test, guaranteed application outcome, or app-specific integration. No operating-system, administrator, or security prompt is approved. |

## Validation

Run the repository's existing hook:

```sh
npm run test:demos --workspace website
npm run docs:build
```

The fixture/timeline suite contains 23 tests: exact workflow order, interface
variety, finite clocks, boundaries, pointer-before-commit ordering, manual
stepping, typed prompts, marker presence, Host configuration semantics, MCP
admission, the file handoff, the wallpaper scene, and component syntax.

Local browser validation used the actual transpiled modules in an isolated
Chromium harness with an available React 16.0.0 runtime, a Fragment compatibility
shim, and system fonts. It checked 28 viewport/theme/motion combinations from
320px to 1920px and all 27 beat endpoints (756 state checks), without horizontal
page/card overflow or scene content overlapping playback controls. It also
exercised on-view playback, offscreen suspension, Pause/Play, keyboard controls,
Replay, completion without looping, source disclosures, and reduced-motion
changes. Document visibility was tested by dispatching a visibility event in the
harness, not by a full browser multi-tab integration test.

These checks are not a substitute for the pinned Next.js/React 19 build,
SSR/hydration, real site navigation, or actual Satelle execution. Dependency
network access was unavailable locally. The documentation workflow performs
the pinned integration build; its current status belongs in the PR, not in this
versioned document.
