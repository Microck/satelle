# Landing demo explorations

This implements the six review concepts as real website components, not images.
The homepage uses 01–04. `/demo-explorations` presents all six and lets a reviewer
select four, preview them together, and copy a URL that restores that selection.
The picker never changes the published homepage or any Satelle configuration.

## Review

From the repository root:

```sh
npm ci
npm run docs:dev
```

Open `/` for the updated homepage, then `/demo-explorations` for the comparison
page. Example selection:

```text
/demo-explorations?demos=durability,readiness,agent,boundaries&view=selection
```

The review route is marked `noindex`. It inherits the existing landing layout,
fonts, and system/light/dark theme. The hero and the documentation tree are not
changed. No dependency, font, screenshot, vendor logo, or external service is
added.

## Design

The new `sx-` styles are scoped beneath `.sa`, alongside the existing demo
styles. They use the existing theme tokens rather than adding a palette. Each
card has one short heading, one supporting line, a documentation link, and one
flat instrument-like surface. Window furniture is deliberately inert.

This is an alternate demo treatment under the principles in `DESIGN.md`, not a
redesign of its token system: no glow, gradient chrome, colored traffic lights,
or looping animation. These demos start complete and react immediately to the
reader instead of typing automatically. There is no timing claim to infer.

Cards share a two-column grid that becomes one column below 55rem. Their bodies
use container queries, wrap long identifiers, and expand for native `details`
disclosures rather than hiding information behind an internal scroller. On very
small cards, the support matrix uses visible symbols with a legend; its full
cell text remains available to assistive technology.

## Fidelity

The examples are tied to release 0.1.10 and the source on `feat/landing-page`
(base revision `e390e26f5f18eb287f1434e2ea3489057d356f07`). Every interaction is
local browser state. No button runs a command, grants permission, contacts a
Host, starts an MCP server, or writes a configuration file.

| Concept | Implemented interaction | Grounding |
| --- | --- | --- |
| 01 / Session | Switch between detached admission and inspection from a fresh Controller | `crates/satelle-cli/src/main.rs`: `print_detached_session` and `print_session_human`; existing `demos/durability.tsx` |
| 02 / Readiness | Compare blocked and post-manual-approval example reports | CLI doctor output; `crates/satelle-host/src/lib.rs`: `project_native_refresh`; existing `demos/readiness.tsx` |
| 03 / Transports | Switch local, direct TLS, and SSH binding requirements | `docs/how-to/connect-remote.mdx`, `docs/reference/configuration.mdx` |
| 04 / MCP | Compare the 8-tool default with 15 advertised tools; expand input/result projections | `crates/satelle-cli/src/mcp/schema.rs`, `crates/satelle-cli/src/output.rs` |
| 05 / Boundaries | Highlight Session, credential, and desktop ownership | `README.md` security model and `docs/explanation/security-boundaries.mdx` |
| 06 / Platforms | Inspect each platform and expand unavailable capabilities | `README.md` platform and implemented-surface sections |

Important corrections relative to the image mockups:

- Detached admission prints `starting`, not `running`. A later status query can
  report the same Session as running. Session and Turn IDs are well-formed
  `rs_`/`rt_` UUIDv7 examples, not abbreviated IDs accepted by the CLI.
- Doctor uses `Host`, `Status`, `Ready`, `Scopes`, and finding/evidence lines.
  There is no invented checks-passed counter or automatic permission grant.
- MCP is read-only by default. `steer` requires `session_id` and `prompt`.
  Its example explicitly includes `detach: true` because the schema defaults
  that argument to false. Displayed JSON is labeled as selected result fields;
  a Turn count summarizes the returned array instead of inventing a JSON field.
- The transport card shows requirements, not a configuration editor. Direct
  transport still needs a provisioned token and CA bundle. SSH replaces neither
  Satelle API authentication nor Host identity verification.
- The Host resolves provider secrets; the Controller still needs transport
  authentication material. This is not a claim that no data reaches a provider.
- macOS and Windows native Hosts remain candidates gated by the live probe.
  Native Linux Host execution is not supported. A candidate is not marked with
  an implemented checkmark.

## Checks

```sh
npm run test:demos --workspace website
npm run docs:build
```

The 14 fixture and selection tests run automatically via the website `prebuild`
hook, including in the existing documentation build workflow. They cover URL
normalization, immutable selection, the four-card limit, identifiers, probe
labels/timestamps, platform claims, and explicit MCP detached admission.

Browser review checklist:

1. Test both themes at 320, 390, 768, 880, 1024, 1440, and 1920px. No page or
   panel should overflow horizontally, including with disclosures open.
2. Navigate every tab strip with arrows, Home, and End. Check visible focus,
   selected-state labels, and the associated tabpanel.
3. Change every example. Expand the MCP calls and platform limits. All data is
   illustrative; no network request should be made by a demo control.
4. Deselect one of 01–04, choose 05 or 06, preview four, reload, and confirm the
   selection survives. Check clipboard success and denial feedback.
5. Repeat with reduced motion. Disable JavaScript and verify useful initial
   markup remains visible.

Local implementation validation used an isolated browser harness for these
components with system-font fallbacks. It is not a substitute for the full
Next.js build, hydration, existing hero, or documentation-route checks. The full
build belongs to the normal CI workflow and the repository's pinned runtime.
