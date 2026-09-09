# Four focused, animated landing demos

The homepage `/` and `/demo-explorations` share `DemoGallery`. This revision
builds on `c9990430c5fb83b616f0a7fbdce2b79b7073f806`; it keeps the working
view-triggered, looping player and changes the four mounted scenes. The hero,
application dependencies, theme tokens, and documentation routes are untouched.

## Scene behavior

**Responsive QA.** The instruction asks for a responsive-layout walkthrough.
The computer grabs a browser's visible lower-right resize handle, drags it
narrower, and exposes a fixed-width product row whose Add to bag button is
partially clipped. It widens the same window and narrows it again to reproduce
the problem. A short finding states the visible issue. Only the illustrated
browser resizes: the real landing page must never overflow. This is a seeded
local storefront at `localhost:3000/storefront`, not a claim that a third-party
website has a defect. The container-query row intentionally retains the wide
window's width, so the clipping is real DOM layout rather than a swapped image.

**ChatGPT concept.** There is only a title, a conversation, and a composer. All
messages appear in full: no typing animation and no opacity fade. Assistant
messages use a short, clock-driven scale/translation popup. The different task
is turning `Documents/launch-notes.odt` into a one-page PDF on `studio-mac`.
The conversation shows configured Hosts, task admission, a user asking for
progress, illustrative `status`/`logs` summaries while running, a question about
the destination, and a final completed status with the Host-local PDF path.
Conversation scrolling follows the same clock and responds to viewport changes.
The final file is not a downloadable ChatGPT attachment.

**Claude Code to browser.** The pointer clicks the actual minus control in the
illustrated terminal titlebar. Only after that click does the opaque terminal
shrink into its taskbar item, revealing the Host browser underneath. There is
no fading terminal or fading browser. The compact Clawd glyphs are drawn as
exact Unicode block quadrants in a crisp SVG grid, avoiding the fallback-font
and letter-spacing artifacts of the former text rendering. The dashboard is
reduced to its title, two values, a chart, and export control. Drive retains
only the Reports folder, New/File upload, a native picker, and upload result.
The CSV still downloads and uploads on the same Host.

**Slack profile.** A small navigation rail, one profile and one photo replace
the dense workspace clone. The sequence still opens the account menu, Profile,
Edit, Upload Photo, Pictures, the selected image, and Open. The pointer drags
the crop slider, saves the crop, and then uses Save Changes. Both the profile
and account thumbnail receive the new image. There is no Slack API call.

## Motion and interaction contract

`workflow-motion.tsx` is unchanged from the previously verified player. Normal
playback starts in view, holds its result for 1.8 seconds, and repeats while
visible. Pause persists; hidden/offscreen time is not accumulated. Reduced
motion disables autoplay, while explicit Play/Replay opts into one real run.
No segmented step bars or next-frame controls are introduced.

`workflow-gesture.tsx` measures visible targets before the click changes the
application. It freezes that geometry for the current beat, rather than chasing
a target that moves or unmounts after the click. The pointer arrives at 620ms;
application state commits at 760ms. Resize/crop drags begin at 760ms, remain
pressed for 1.2 seconds, and use the exact same easing and endpoints as the
window or slider. Pause freezes all of these projections. Observers disconnect
on unmount. Drag endpoints are inert layout markers, not fake buttons.

`CHAT_MESSAGES`, `CLAWD`, `qaWidth`, and `messagePop` live with the typed timeline
fixtures in `exploration-data.ts`. The scene clock drives all motion; CSS does
not introduce independent timers or fades. Complete SSR/reduced-motion frames
remain useful. The application illustrations are hidden from assistive tech;
real Play/Pause/Replay controls and their status labels remain accessible.

## Product truth and visual sources

All scenes are scripted UI illustrations, not recordings, measurements, or
live commands. They never contact a Host, submit a purchase, change a real
profile, or transfer a file. Sample log/status summaries are not literal tool
transcripts or a guarantee that any application task will succeed.

`config_check({ all: true })` reports configured contexts, not discovery or a
readiness verdict. Detached `run` reports `starting`. Later status/log examples
are clearly separated from admission, ending in an illustrative `completed`
result. Repository grounding remains `crates/satelle-cli/src/mcp/schema.rs`,
`mcp/output-schema.rs`, `mcp/install.rs`, `read.rs`, and the release README.
Native macOS/Windows Hosts remain candidates gated by live readiness. Native
Linux Host execution is unsupported.

The ChatGPT card remains visibly labelled **Concept**. This Satelle release
serves local stdio MCP and has no ChatGPT installer/compatible remote bridge.
A bridge and client compatibility need separate implementation and verification.
The review page exposes the proposed tool arguments/results and the limitation.
See OpenAI's requirements:
https://help.openai.com/en/articles/12584461-developer-mode-and-mcp-apps-in-chatgpt

The sparse framing follows the supplied V12 references and https://v12.sh/.
Existing OpenAI, Slack, Drive, and Analytics paths are untouched, still sourced
from Simple Icons 15.0.0 with exact-path SHA-256 tests. Geometry uses
`currentColor`; new scenes and their CSS contain only `--sa-*` paint tokens.
The Clawd source preserves the compact three-line block art already in the
repository's terminal scene. Its new quadrant rendering is a faithful compact
silhouette, not a claim of pixel identity with every Claude Code release.
Terminal interaction reference: https://code.claude.com/docs/en/interactive-mode
The photo is original abstract artwork, not a portrait of the visitor.

## Validation

```sh
npm ci --ignore-scripts
npm run postinstall --workspace website
npm run test:demos --workspace website
npm run docs:build
```

The 25 fixture/source tests cover the four mounted components, complete chat
messages, the new task and completion, popup geometry, wide/narrow QA states,
press/drag ordering, terminal minimization without opacity, crop/save ordering,
compact application content, product boundaries, and unchanged logo paths.

Local isolated Chromium checks exercise 560 beat endpoints across seven widths
and both themes. They additionally measure every click and the moving resize/
crop handles against the rendered cursor; unintended overflow and missing
action targets fail the checks. The local runtime uses available React 16 and
system fonts; that is not a claim to have run the pinned Next.js build locally.

The existing **Landing demo browser checks** workflow builds the pinned site
and tests the actual `/` route. The updated script observes a complete real-time
cycle of each scene, checking rendered pixels, whole-message insertion, click
and drag alignment within four pixels, terminal minimization, loop/replay,
reduced-motion opt-in, offscreen suspension, and responsive final states. It
also checks that the seeded narrow-screen button is visibly partially clipped,
while the real page is not. Browser video, screenshots, and `gesture-proof.json`
are uploaded with the workflow artifacts. CI on the new commit, not a previous
successful run, is the source of truth for production-build validation.
