# Four animated landing demos

Both `/` and `/demo-explorations` mount the same four components. This revision
corrects playback and restores the requested checkout and simple conversation.
The existing Claude Code-to-browser and Slack profile-photo scenes are retained,
not redesigned. No step bars, six-option picker, vendor color palettes, backend
integrations, or live account actions have been added.

## What changed

1. **Checkout QA.** The browser now depicts the Swag Labs checkout at
   `saucedemo.com`, a real test-practice website, instead of a GitHub repository.
   The example types a first name, checks the required-last-name error, completes
   the form, and reaches order review. It stops before purchase. These are
   scripted validation observations, not a measured run or an invented defect.
2. **Simple ChatGPT conversation.** The earlier sparse chat treatment is back:
   window title, messages, two configured-Host rows, one task, and a composer.
   There is no sidebar, chat history, model menu, approval panel, or custom app
   dashboard. A small Concept label and the visible connection caveat remain.
3. **Claude Code to the Host browser.** The existing recognizable terminal,
   minimizing transition, Google Analytics CSV export, Google Drive upload and
   native file picker remain. Sample account data and file outcomes are not
   guaranteed task results.
4. **Slack profile photo.** The existing Profile / Edit / Upload Photo / native
   picker / crop / Save / Save Changes flow remains. No Slack API or account
   mutation is performed by this webpage.

All app surfaces still use the landing page's `--sa-*` tokens. `landing-scenes.css`
supplements the existing stylesheet; it does not recolor native-app surfaces with
vendor palettes. The original hero, documentation pages, and product commands
are untouched. The homepage's instructional note now describes the real controls.

## Why playback could look static

The prior player stopped permanently after a single pass. More importantly, its
reduced-motion branch removed Play: Replay only advanced to another still frame.
A user whose OS/browser requested reduced motion had no way to intentionally
watch the animation. The old SSR markup also opened on the final frame.

The replacement keeps complete SSR markup but changes the mounted player:

- Normal playback starts on entering view, holds the final scene for 1.8 seconds,
  then repeats while visible. Typing, cursor motion, app changes, terminal
  minimization, crop adjustment, and upload progress use the same clock.
- Pause actually freezes scene time. It persists when scrolling away and back.
  Offscreen cards and hidden tabs stop scheduling animation frames, then resume
  without catching up elapsed background time. Observers/listeners are cleaned up.
- Reduced motion still prevents autoplay. **Play animation** and **Replay** now
  explicitly opt into one real animation, not another still. It stops at the end
  rather than looping. Native browser controls support Enter/Space.
- There are no step bars or next-frame instructions. Repeated animation does not
  repeatedly announce every beat to a screen reader; the status is live only
  while stopped. The illustrated application's furniture is not focusable.

The `data-playing`, `data-elapsed`, and `data-cycle` attributes are observability
hooks used to test actual playback, not a replacement for rendering movement.

## Scope and product truth

These are UI reenactments, not recordings or connections to real Hosts. QA uses
sample checkout data; uploads use sample accounts. The website never fetches an
application API, executes a shell command, or submits a form to a real service.

`config_check({ all: true })` reports configured contexts, not discovered,
reachable, or ready computers. Native macOS/Windows Host support remains
candidate-only and must pass the live readiness probe. Native Linux Host
execution is unsupported. Detached `run` admission reports `starting`, not
completion. The file remains on the same Host between browser download/upload.

The ChatGPT window is a **design concept**, not an available Satelle integration.
This release serves MCP over stdio and has no ChatGPT installer target. A
compatible remote bridge and desktop-client support need separate implementation
and verification. The proposed MCP calls are disclosed on the review route,
not presented as a shipped connector. No configuration switch grants Host or OS
permissions. The selected Host aliases and Session ID are illustrative.

Repository grounding is unchanged: `crates/satelle-cli/src/mcp/schema.rs`,
`mcp/install.rs`, `mcp/output-schema.rs`, `read.rs`, and the release README.

## Brand geometry and provenance

The former improvised OpenAI knot and Slack shapes are replaced with the actual
monochrome path geometry from **Simple Icons 15.0.0**. Drive and Analytics use the
same sourced approach. Paths are unchanged, with a `0 0 24 24` viewBox and
`currentColor`; no remote image or asset/font dependency is introduced.

- `https://github.com/simple-icons/simple-icons/blob/15.0.0/icons/openai.svg`
- `https://github.com/simple-icons/simple-icons/blob/15.0.0/icons/slack.svg`
- `https://github.com/simple-icons/simple-icons/blob/15.0.0/icons/googledrive.svg`
- `https://github.com/simple-icons/simple-icons/blob/15.0.0/icons/googleanalytics.svg`

Simple Icons distributes these data under CC0. The underlying brands/trademarks
remain their owners' property. They identify the illustrated applications, not a
partnership. `workflow-logos.tsx` documents the source; fixture tests verify each
path's SHA-256 so it cannot silently regress to an approximate homemade symbol.
The abstract profile avatar is original, not a photograph of the visitor.

Visual references checked: `https://v12.sh/`, `https://openai.com/brand/`, Slack's
media kit, and Claude Code's interactive-mode documentation. The useful V12
reference is the sparse app framing and visible workflow progression, not an
attempt to reproduce every control from a full desktop application.

## Validation and reproduction

```sh
npm ci --ignore-scripts
npm run postinstall --workspace website
npm run test:demos --workspace website
npm run docs:build
```

Twenty local fixture/source tests cover checkout semantics, sparse chat structure,
all four workflow IDs, clock boundaries, explicit reduced-motion play, looping,
monochrome paint, Host/MCP limitations and exact logo geometry. Targeted local
Chromium checks exercise the two changed scenes with system-font fallbacks,
including actual typing/DOM changes, pause, reduced-motion opt-in, normal loops,
and responsive final-state containment. These isolated checks use an available
React 16 runtime; they are not the pinned website build.

**The new Landing demo browser checks workflow tests the actual exported `/`
page built with the repository's pinned Next.js and React versions.** It renders
all four scenes, compares scene DOM and pixels over real elapsed time, checks
pause/replay and a full loop, scroll suspension, explicit reduced-motion Play,
responsive final states and the review route. It uploads screenshots, a browser
video and the check report even when a test fails. No still-frame-only harness
is accepted as proof that the landing page animates.

The browser runner is installed in a temporary CI directory; the application
lockfile and dependencies are unchanged. Run it locally against `website/out`
with `DEMO_BASE_URL` and `PLAYWRIGHT_MODULE` pointing to an installed Playwright
module. The workflow result on the new PR commit is the source of truth for the
full build/browser result; the old commit's successful build does not count.
