# Workflow demo explorations

Review at `/demo-explorations`. The homepage imports the same `DemoGallery`
component with its default selection. This is a website illustration, not a
Satelle frontend, a live Host connection, or evidence of task completion.

## Revision: different workflows, not six terminals

V12's useful reference is its variety of contexts: a PR thread, a Slack
conversation, an agent session, and a CLI. The first Satelle implementation
copied the terminal treatment across too many cards. This revision replaces
that approach with six different application surfaces:

| ID | Surface | Interaction |
| --- | --- | --- |
| `spreadsheet` | Desktop workbook with cells, formula bar and chart | Before/result toggles the illustrative chart, not the source values |
| `chat` | Claude Desktop-style conversation | Ask about the Session or why a follow-up is unavailable; inspect the example status tool call |
| `editor` | Cursor-style file pane and agent sidebar | Switch the example MCP mode, then preview detached follow-up admission |
| `browser` | Native browser tab, address bar and start/settings pages | Compare the first Turn with an illustrative follow-up in the same Session |
| `document` | Word processor with outline, toolbar and document page | Compare a synthetic draft with formatted headings and spacing |
| `terminal` | One CLI transcript | Compare detached admission with status from a fresh Controller |

The homepage defaults are `spreadsheet,chat,editor,browser`: **zero terminal
cards**. The comparison page includes one optional CLI card. There is no new
Satelle dashboard, Slack bot, GitHub integration, office add-in, browser
extension, or hosted service in these designs.

Flat surfaces use the existing landing tokens. There are no vendor logos,
external assets, font changes, new dependencies, gradients, autoplay loops or
new network requests. Client and application chrome is an illustration, not a
pixel-exact claim about another vendor's current UI. Only labeled example
controls are interactive; inert chrome is not rendered as fake buttons.

## Product fidelity

The source baseline is `ef70a83340845ec012e39d4f080d28425096dd35`, based on
`feat/landing-page` at `e390e26f5f18eb287f1434e2ea3489057d356f07`, release 0.1.10.

| Claim or fixture | Repository source |
| --- | --- |
| Cursor and Claude Desktop are MCP installer targets | `crates/satelle-cli/src/mcp/install.rs`: `ALL_TARGETS`, `InstallTarget` |
| Eight read-only tools and fifteen with mutations advertised | `crates/satelle-cli/src/mcp/schema.rs`: `tools(enable_mutations)` |
| `status` input uses `session_id` and `host` | Same file, `status` tool schema |
| `steer` requires `session_id` and `prompt`; detach defaults to false | Same file, `mutation_tools` |
| Selected status and steer JSON fields | `crates/satelle-cli/src/output.rs`; MCP schema and existing `demos/agent.tsx` |
| Detached admission prints two lines, `starting` | `crates/satelle-cli/src/main.rs`: `print_detached_session`; existing `demos/durability.tsx` |
| A later status prints Session, Host, Status, Turns, Latest turn and Latest status | Same file, `print_session_human` |
| Browser followed by `Open settings` in the same Session | `README.md`, shortest successful flow; `docs/how-to/operate-session.mdx` |
| Spreadsheet example numbers | Existing `demos/stages/excel.tsx`: `MONTHS` (Q3 synthetic showcase data) |
| Desktop word-processing scenario, not an office API | Existing `demos/stages/filing.tsx` and `website/DESIGN.md` section 7; the new brief is synthetic copy |
| Host ownership and native support boundaries | `README.md`, platform support and security model |

The editor's starting state is `stopped`, so the example does not claim that
`steer` admits a concurrent Turn over an already-running one. Enabling mutation
tools is a separate example step from admitting the follow-up. The request
explicitly includes `detach: true`; its returned status is `starting`, not a
claim that settings already opened. Turning the example flag back off resets
the local follow-up state. The switch neither changes real configuration nor
grants Host, OS, or app permissions.

The chat is a separate read-only example. It displays selected status fields,
not fabricated CLI output. Its follow-up explains that `steer` is absent from
the tool list. It does not silently enable or invoke mutations.

Browser, spreadsheet and document scenes are illustrative candidate tasks,
not recordings, benchmarks, promises of reliable completion or named app
integrations. They assume a configured Host that passes live readiness.
macOS and Windows remain candidate native Hosts. Linux Controller support is
not native Linux Host support. These caveats stay visible in the gallery and
app captions. No remote live-doctor call, permission bypass, automatic token
provisioning, persistent Host service installation, or storage migration is
added or implied.

## Preview selection

Select at most four. Deselect one before adding another. `Preview selected 4`
filters the comparison page only; it does not change the published homepage.
A shared example URL is:

```text
/demo-explorations?demos=spreadsheet,chat,editor,browser&view=selection
```

Missing/invalid selections use fresh defaults. An explicitly empty selection
stays empty. Unknown IDs are removed, duplicates deduplicated, and results
capped at four. Old all-terminal selection IDs now normalize to the new
defaults. `popstate` is observed and its listener cleaned up on unmount.
Clipboard denial has a visible fallback message. History updates preserve
Next's existing history state. The review route remains `noindex`.

## Validation

```sh
npm run test:demos --workspace website
npm run docs:build
```

The existing website `prebuild` hook runs the fixture tests. Eighteen tests
cover scenario diversity, non-terminal defaults, the single terminal body,
selection normalization and limits, IDs, CLI print shapes, MCP admission and
schemas, synthetic chart totals, CTAs and visible capability boundaries.
They also syntax-transpile the actual TSX, not a duplicate component.

An isolated Chromium harness renders the actual transpiled components using
an available React 16 runtime, a Fragment compatibility shim, and system-font
fallbacks. Local checks passed for all six controls, keyboard Enter/Space,
MCP read-only gating and reset, tool disclosures, four-card selection,
clipboard-denial feedback, and 28 viewport/theme/motion combinations
(56 initial/alternate layouts). Widths: 320, 390, 768, 880, 1024, 1440 and 1920.
No page/card horizontal overflow, visible text below 12px, page JavaScript
errors, or reduced-motion animations were found in that harness.

This environment cannot download the pinned npm dependencies. These local
checks do **not** replace the Next.js/React 19 build, SSR/hydration, actual
route navigation or integration tests. The previous revision's Documentation
CI build passed; that is not a result for this revision. Check CI on the new
commit separately. No deployment or merge is performed by this change.
