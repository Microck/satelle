# Monochrome application workflows

Replaces the pending terminal-heavy/placeholder revision with the four requested
scenarios. The homepage and `/demo-explorations` use the same React components.
The review route remains `noindex` and exposes illustrative MCP argument/result
excerpts. The old six-option selector and all segmented step bars are gone.

## Visual contract

The V12 reference is a vocabulary of recognizable applications drawn within one
website design system, not four unrelated embedded product themes. Satelle's
existing `--sa-*` ramp owns every application background, foreground, border,
chart, icon, avatar, selection, and simulated button. Both existing themes work.

There are no Slack-purple panels, Google brand colors, orange Claude mascot,
red/yellow/green window lights, white application islands, remote images, or
CSS grayscale filters. Identity comes from layout and familiar controls. The
website accent is reserved for keyboard focus. No font or dependency is added.

The UI geometry is a responsive recreation, not a claimed pixel-for-pixel capture
of a specific vendor version. App-specific typography is replaced by the site's
existing sans and mono stacks. All app chrome is illustrative and hidden from
assistive technology; the actual playback controls are real labelled buttons and
the current action is a live status. The reduced-motion Next frame button keeps
all stills available without restoring the removed step rail.

## The four scenes

1. **GitHub QA.** Read-only navigation through `github.com/Microck/satelle`, the
   README and Issues search, ending at an empty search state. Notes are scripted
   examples, not measured QA results or a built-in Satelle QA dashboard. No defect
   or vulnerability is attributed to GitHub. Nothing is submitted.
2. **ChatGPT desktop concept.** Ask which Hosts are configured, display the
   configured aliases, request the Slack task, and preview a proposed approval
   and detached admission. A persistent `Integration concept` badge, a visible
   caption, and the review-page requirements section prevent this from implying
   a shipped integration.
3. **Claude Code to Google Drive.** A recognizable Clawd/terminal prompt and MCP
   transcript precede a finite window handoff. The terminal minimizes; the Host
   browser expands. Google Analytics Share -> Download File -> CSV is followed
   by Google Drive Reports -> New -> File upload -> native picker -> Open.
   `Traffic acquisition.csv` stays on `ops-pc` throughout. This is not a Satelle
   file-transfer API or a cross-Host copy. Sample accounts are assumed signed in
   and authorized. The chart and file data are synthetic.
4. **Slack profile photo.** Account menu -> Profile -> Edit -> Upload Photo ->
   Pictures -> `profile.png` -> Open -> crop -> Save -> Save Changes. The new
   avatar is an original abstract illustration, not a supposed photo of the user.
   No account is changed and no Slack API integration is claimed.

## Product fidelity

Product baseline: `3601b323d5d487597666066f97eb0197205ae41a` on
`feat/landing-demo-explorations`, derived from the requested `feat/landing-page`.

- `crates/satelle-cli/src/read.rs`: `config_check(all=true)` reports checked
  configuration contexts. `remote_host`, `provider_auth`, and
  `native_computer_use` remain in `not_checked`. Configured is not online/ready.
- `crates/satelle-cli/src/mcp/schema.rs`: `run` takes `prompt`, `host`, and
  `detach`. Mutation tools require explicit enablement. The demo's complete
  illustrative input is available on the review route; terminal fields are
  excerpts. Detached `starting` means admission, not completed work.
- `crates/satelle-cli/src/mcp/install.rs`: Claude Code is an installer target;
  ChatGPT is not. This revision does not add a transport bridge, installer,
  plugin, desktop compatibility, or backend for the ChatGPT concept.
- `README.md`: native macOS/Windows Hosts are candidates, gated by a live
  readiness probe. Native Linux Host execution is unsupported. No demo grants
  operating-system, administrator, or application permission.

OpenAI documents remote MCP connectivity and currently describes custom-app
availability on ChatGPT web. A desktop-compatible connection would need separate
implementation and verification. This website scene cannot establish that.

## Reference sources

Visual structure: https://v12.sh/ and the screenshots provided for this change.
Vendor workflow references, checked 2026-09-09:

- https://code.claude.com/docs/en/interactive-mode
- https://help.openai.com/en/articles/12584461-developer-mode-and-mcp-apps-in-chatgpt
- https://support.google.com/analytics/answer/9317657
- https://support.google.com/drive/answer/2424368
- https://slack.com/help/articles/115005506003-Upload-a-profile-photo

These references support UI conventions/workflow order, not an endorsement,
partnership, measured outcome, or claim of an available Satelle integration.

## Motion and implementation

`workflow-motion.tsx` owns a single finite clock per scene. Autoplay starts when
15% of the card enters view. Offscreen cards and hidden documents suspend work;
manual Pause persists. Replay resets only that scene. Prompts type in; tool
results appear as blocks. Cursor travel finishes before the application commits
its next state. Window handoff, conversation scrolling, crop adjustment, and upload
progress follow that same clock. All observers/listeners/frames are cleaned up.

Server rendering and reduced motion show complete content. Reduced motion has no
autoplay and no CSS motion. Replay starts its still sequence; Next frame advances
it. There are no segmented bars and no stale “Use the steps” instructions.

`workflow-ui.tsx` holds the reusable monochrome chrome, icons, abstract avatar,
and source disclosures. `workflow-scenes.tsx` holds app layouts.
`exploration-data.ts` contains the immutable fixtures and pure clock functions.
`explorations.css` is scoped under `.sa` and uses the existing landing tokens.
No product state, Host, service, shell, or account is contacted by these modules.

## Validation

Run the existing prebuild fixture tests:

```sh
npm run test:demos --workspace website
```

The prepared revision passed 25 fixture/source tests, including the four-scene
order, real domains, monochrome paint, removal of step bars, Host semantics,
ChatGPT concept labelling, pointer-before-commit timing, and the file/profile
workflows. TS/TSX files transpile without syntax diagnostics.

An isolated Chromium harness rendered 546 scene endpoints across seven widths
(320, 390, 768, 880, 1024, 1440, 1920) and both themes, and checked 350 pre-action
cursor targets. No page/card overflow, clipped dialog, terminal-footer overlap,
missing/out-of-bounds target, or JavaScript error remained. Actual playback checks
covered autoplay, pause, replay, offscreen suspension, dynamic reduced motion,
and still navigation.

The harness uses an available React 16 runtime and system fonts. This is **not**
a pinned React 19 / Next.js build, a full type-check, SSR/hydration validation, or
vendor-application testing. Run the full existing website build in CI. No new CI
result is claimed for an unpushed revision.
