# Satelle site design system

The design language for `satelle.micr.dev`. The landing page at `/` and the
Fumadocs documentation at `/docs` are separate visual systems: this document
governs the landing page only, and nothing here is imported by the docs tree.

Structure, rhythm, and the interactive-demo approach are modelled on
[v12.sh](https://v12.sh). Color, voice, and every demo are Satelle's own.

## 1. What the page has to say

Satelle is a control plane, not an agent. An operator sits at a terminal on one
machine; a Host somewhere else owns execution and drives a visible desktop. The
page has to make three things obvious, in this order:

1. Work runs on a machine you control, on a real desktop, in real applications.
2. The Session outlives the terminal that started it.
3. The Operator holds every boundary that matters, and the product says out
   loud what it cannot do yet.

Everything on the page serves one of those three. A section that serves none of
them does not belong.

### Voice

Short declaratives. Present tense. No em dashes. No adjective stacking, no
"seamlessly", no "effortlessly". Name the thing: Session, Turn, Host, Operator,
Controller, Desktop Binding. These are the product's own words and the docs use
them, so the landing page uses them too.

Satelle is pre-release. The page says so in the first viewport and repeats the
implemented/not-implemented split in full. That honesty is the differentiator,
not a disclaimer to bury.

### What the page must never contain

- Testimonials, logos, or quotes. There are no customers to quote.
- Pricing, trials, credits, or an "Open app" button. Satelle is self-hosted.
- Any capability listed as unimplemented in `README.md`.
- CLI output that the binary does not actually print. Every terminal frame in
  every demo is traceable to a `println!` in `crates/satelle-cli` or to
  documented help text. See §7.

## 2. Color

The entire palette derives from the two logo files in `output/satelle-logo-edit/`.
Those three values are the only fixed inputs:

| Role | Hex | OKLCH | Source |
| --- | --- | --- | --- |
| Accent | `#E5184D` | `oklch(59.2% .228 16.0)` | both logo variants |
| Ground | `#0F0D17` | `oklch(16.7% .021 293.2)` | `satelle-logo-dark.svg` ink |
| Text | `#D6D8E0` | `oklch(88.3% .011 274.9)` | `satelle-logo-light.svg` tail |

The page is **light by default**, as the reference is, with a system/light/dark
toggle in the footer, as the reference also has. Three states, not two: an
explicit choice stamps `data-theme` on the root element, and the default
"system" setting stamps nothing, where only `prefers-color-scheme` separates the
two. A small inline script applies a stored choice before first paint.

`satelle-logo-dark.svg`, the dark-ink variant, exists precisely for a light
surface. Its ink is the light theme's primary text; the pale tail from
`satelle-logo-light.svg` is the dark theme's.

### The ramps

Twelve steps each, interpolated in OKLCH between the ground and the ink, with the
hue drifting `274.9 <-> 293.2` so light steps stay cool and dark steps stay
violet. Every step is inside sRGB.

Both ramps are tuned against the **darkest surface the step actually lands on**,
not against the page ground. Tuning against the ground alone is what produced 108
contrast failures on the first light build: `--sa-9` measured 3.97:1 on `--sa-1`
but 3.54:1 on `--sa-3`, where most muted text sits.

| Token | Light | Dark | Use |
| --- | --- | --- | --- |
| `--sa-0` | `#FFFFFF` | `#08060F` | recessed wells: terminal bodies, code surfaces |
| `--sa-1` | `#F9FAFF` | `#0F0D17` | page ground |
| `--sa-2` | `#F4F5F9` | `#171620` | raised surface: cards, window bodies |
| `--sa-3` | `#ECEDF2` | `#1F1E28` | window chrome, table headers, tab strips |
| `--sa-4` | `#E4E5EA` | `#272631` | hovered surface |
| `--sa-5` | `#DBDCE2` | `#32313C` | pressed surface, selected row |
| `--sa-6` | `#D1D2D8` | `#3F3E49` | hairline border |
| `--sa-7` | `#C2C4CA` | `#575761` | border on interactive elements |
| `--sa-8` | `#8B8B94` | `#676872` | strong border. **Never text**: it measures ~3:1 |
| `--sa-9` | `#696973` | `#90919B` | faint text |
| `--sa-10` | `#5A5A63` | `#A9AAB3` | muted text |
| `--sa-11` | `#52515B` | `#C3C5CE` | secondary text |
| `--sa-12` | `#0F0D17` | `#D6D8E0` | primary text |

Shadow colour is theme state too, through `--sa-shadow` and
`--sa-shadow-strength`. The dark theme's 60% black reads as soot on a near-white
ground, so the light theme uses the logo ink at 16% and keeps the hue family.

### The QA battery

Run against a real Chrome, not a headless stand-in, because several defects only
appear in one: a snap Chromium masked child overflow behind `overflow-x: clip`,
and its shared profile leaked a stored theme between runs. The checks:

- contrast of every text node against its real painted background, both themes;
- every button, tab and radio clicked from a fresh page, asserting the DOM
  actually changed, with already-active controls excluded;
- hover response on every rail mark, not on its button, because the mark is what
  carries the colour;
- `prefers-reduced-motion` leaves no element with a live transition or animation;
- nothing clipped horizontally, at 1440 and at 390, excluding elements that
  declare their own `text-overflow: ellipsis` or the footer's watermark;
- no text under 12px, measuring SVG glyphs through their screen CTM because a
  `viewBox` scales them;
- every demo's control bar inside its card at both widths;
- no horizontal page overflow from 320 to 1920.

All of it runs clean. Treat a regression as a build failure.

Four defects came only from that battery and would not have shown in a
screenshot: no rail step responded to a pointer, because `[data-done]` outranked
`:hover` and every demo opens finished; the tabpanel was focusable with no ring;
a window bar's third grid track was `auto`, so a long right-hand label pushed the
window past a phone viewport and squeezed the middle track to zero; and a
`@container` override sat above the rule it was meant to override, where source
order silently beat it.

### Accent rules

`#E5184D` measures 4.41:1 on the light ground and 4.19:1 on the dark one. Both are
under 4.5:1, so it is a **surface and mark colour, never body text** in either
theme:

- `--sa-accent: #E5184D` fills the primary button, the live-state dot, the active
  tab rule, the 1px marker on a current row. White on it is 4.60:1, which passes.
- `--sa-accent-text` is the only accent value allowed to carry text: `#C4003D` on
  light (5.90:1), `#EF5469` on dark (5.63:1).

The accent is scarce. Per viewport: one primary action, plus live state. If a
screenshot of a section shows crimson in three unrelated places, the section is
wrong. Emphasis is carried by the ramp and by size, not by colour.

### State colors

Demos surface real Turn states and doctor severities, which need non-accent
semantics. Derived on the same hue-drift discipline, all in gamut:

| Token | Hex | Meaning |
| --- | --- | --- |
| `--sa-ok` | `#3FCF8E` | `completed`, probe ready, DRC clean |
| `--sa-live` | `#E5184D` | `running`, `starting` (the accent, deliberately) |
| `--sa-warn` | `#E8B339` | `blocked`, `recovery_pending`, fixable finding |
| `--sa-stop` | `#80818B` | `stopped`, cancelled, inert |
| `--sa-fail` | `#F2555A` | `failed`, error severity |

`--sa-fail` and `--sa-accent` are close by design: failure and liveness both
mean "look here". They never appear in the same component.

## 3. Type

**Geist Sans** and **Geist Mono**, self-hosted from `public/fonts/`, latin
subset, weights 400/500/600, `font-display: swap`.

Söhne, which v12.sh uses, is a commercial Klim license. The only copies
available to download are unlicensed scrapes, so the site does not ship it.
Geist is the same neo-grotesque lineage under OFL-1.1, and v12 already pairs its
own display face with Geist Mono.

```
--font-sans: "Geist", ui-sans-serif, system-ui, -apple-system, sans-serif
--font-mono: "Geist Mono", ui-monospace, "SF Mono", Menlo, monospace
```

### Register

The page runs two registers and never blends them inside one block.

**Editorial** (sans): headlines, section statements, prose. Tight tracking on
large sizes (`-0.022em` at step 5 and up), `text-wrap: balance` on headlines,
`text-wrap: pretty` on paragraphs, measure capped at `--measure: 34rem`.

**Operator** (mono): everything that represents machine state. Command lines,
Session identifiers, Turn states, event names, file paths, host aliases, log
levels, byte counts, durations. Mono also carries small structural labels inside
demo chrome, uppercase with `0.08em` tracking at `--step--2`.

The rule: if a real terminal would print it, it is mono. Prose about it is sans.
This is what makes the demos read as instruments rather than illustrations.

### Fluid scale

Utopia, `320px -> 1215px` (`20rem -> 75.94rem`, matching `--grid-max-width`),
16px base at ratio 1.125 growing to 18px at ratio 1.2.

```
--step--2: clamp(.75rem,   .7277rem  + .1117vw, .8125rem)   /* 12 -> 13  labels */
--step--1: clamp(.8889rem, .8715rem  + .0869vw, .9375rem)   /* 14 -> 15  mono body, captions */
--step-0:  clamp(1rem,     .9553rem  + .2235vw, 1.125rem)   /* 16 -> 18  body */
--step-1:  clamp(1.125rem, 1.0446rem + .4022vw, 1.35rem)    /* 18 -> 22  lead */
--step-2:  clamp(1.2656rem,1.1389rem + .6335vw, 1.62rem)    /* 20 -> 26  card headings */
--step-3:  clamp(1.4238rem,1.2379rem + .9299vw, 1.944rem)   /* 23 -> 31  subsection */
--step-4:  clamp(1.6018rem,1.3405rem + 1.3067vw,2.3328rem)  /* 26 -> 37  section */
--step-5:  clamp(1.802rem, 1.4455rem + 1.7829vw,2.7994rem)  /* 29 -> 45  section lead */
--step-6:  clamp(2.0273rem,1.5511rem + 2.381vw, 3.3592rem)  /* 32 -> 54  hero */
```

Line height: `1.08` at step 6, `1.14` at step 5-4, `1.28` at step 3-2, `1.55`
for body, `1.5` for mono blocks. Mono blocks use `font-variant-numeric:
tabular-nums` so columns of numbers hold still while a demo updates them.

## 4. Space, grid, radius

Utopia space on the same viewport range, `max = min * 1.125`:

```
--space-3xs .25 -> .2812      --space-l   2 -> 2.25
--space-2xs .5  -> .5625      --space-xl  3 -> 3.375
--space-xs  .75 -> .8438      --space-2xl 4 -> 4.5
--space-s   1   -> 1.125      --space-3xl 6 -> 6.75
--space-m   1.5 -> 1.6875     --space-4xl 8 -> 9
```

Plus one-up pairs for anything that should grow faster than the scale:
`--space-s-m`, `--space-m-l`, `--space-l-xl`, `--space-xl-2xl`,
`--space-2xl-3xl`, `--space-3xl-4xl`. Section vertical rhythm is
`--space-3xl-4xl`; the gap between a section headline and its demo is
`--space-l-xl`.

Three tracks, gutter / content / gutter, at `--grid-max-width: 86rem` (1376px)
with `--grid-gutter: --space-m`. A child sits full-bleed by asking for
`grid-column: 1 / -1`; everything else lands on column 2.

```
--grid-edge: max(var(--grid-gutter), (100% - var(--grid-max-width)) / 2)
```

An earlier version declared twelve columns and a column-gap. Nothing on the page
addressed an individual column, and the gap either side of the content span was
charged against the content, so the column came out 108px narrower than the token
asked for. That is what squeezed the two-up demo cards to 545px and made every
demo grow vertically to compensate.

Demos inside the two-up grid size themselves with `@container` queries against
`.card-body`, not with viewport media queries: a card is roughly half the width
the viewport reports, and breakpoints written for a full-width demo never fire
inside one.

Radius: `--radius-sm .25rem`, `md .375rem`, `lg .5rem`, `xl .75rem`,
`2xl 1rem`, `full 9999px`. Window frames use `xl`. Nested surfaces step down one
level so corners stay concentric. Terminal bodies use `md`.

Borders are 1px, `--sa-6`, and structural. There are no decorative cards: a
border exists to mark where one machine's surface ends and another's begins. No
pills, no gradient chrome, no glow. Elevation is the ramp, not shadow; the only
shadow on the page is under a window while it is being dragged.

## 5. Motion

Motion clarifies a change and nothing else.

```
--mo-instant: 0ms      /* selection, tab switch, value commit */
--mo-state:   150ms    /* hover, press, row highlight */
--mo-popover: 200ms    /* tooltips, disclosure */
--mo-overlay: 300ms    /* window open, section reveal */
--mo-ease:    cubic-bezier(0.175, 0.885, 0.32, 1.1)
--mo-ease-flat: cubic-bezier(0.25, 1, 0.5, 1)
--mo-stagger: 24ms
```

`--mo-ease` carries a small overshoot and belongs on anything that appears or
moves. `--mo-ease-flat` is for anything that must not overshoot: progress fills,
terminal scroll, a value counting up, a window following the pointer.

**The reference's motion vocabulary, measured, not invented.** Read off the live
page with a browser: four keyframes and nothing else.

| Keyframe | Duration | Runs | Where |
| --- | --- | --- | --- |
| enter | 0.24s | once | every section and card, opacity plus a 0.25rem rise |
| fade in | 0.12s | once | every row or printed line as it lands (39 of them) |
| caret blink | 0.8s | **infinite** | six carets, hard on/off, no easing |
| pulse | 1.4s | infinite | one live marker |

This page mirrors that: `.sa-enter`, `.sa-in`, and `.sa-caret[data-blink]`.

An earlier version of this document banned infinite animation outright, and that
was wrong for this page. A terminal caret that does not blink reads as a
screenshot, which is the one thing these demos must not look like. The two
infinite animations here animate opacity only, on elements a few pixels wide,
and the caret's `data-blink` is false once its script settles, so a page at rest
carries no live animation at all. What stays banned is the thing the rule was
actually aimed at: shimmer, skeleton sweeps, spinners, animated blur, and
anything large or continuous.

**Demos play themselves once, then stop.** The reference's card demos are nearly
empty windows that type their content in when they scroll into view: sampling one
showed its text grow 156, 159, 170, 180, 191, 200, 204 characters, then jump 115
at once, hold, then jump again. So a person's input is typed at about 22ms per
character and the machine's reply arrives whole. Typing out machine output would
misrepresent what happened.

`demos/typewriter.tsx` implements exactly that, and the hero advances its Turn on
the same trigger. Three rules keep it honest: the run starts only when the demo
is actually on screen, it ends of its own accord at the last beat, and any reader
interaction cancels it, because nothing should keep moving under a hand that is
already driving.

Under `prefers-reduced-motion` every demo presents its finished script on the
first paint. A reader who does not want motion loses the reveal and nothing else.

Drag follows the pointer with no transition at all. Transitions on a dragged
element make it feel like it is lagging behind the hand.

`prefers-reduced-motion: reduce` drops every enter, exit, and transform
transition to `0ms`, stops the caret, and makes demos step instantly between
states. Demos stay fully usable: reduced motion removes animation, never
function.

## 6. Demo craft

The interactive demos are the argument. They are not decoration and they are not
video. Rules that apply to all of them:

1. **Real output only.** See §7.
2. **The demo is the claim.** Each demo proves exactly one of the three points
   in §1. If you cannot say which, cut it.
3. **Interactive, not autoplaying.** A demo may render a settled first frame and
   wait. It advances when the reader does something. Nothing loops.
4. **Keyboard equal to pointer.** Every draggable window moves with arrow keys
   when its title bar has focus, `Shift` for a coarser step, `Home` to reset.
   Every clickable row is a real `<button>` in tab order. Focus is visible:
   2px `--sa-accent` outline at 2px offset.
5. **Labelled honestly.** Each demo names what is interactive and what is
   illustrative, in a caption the screen reader reads first. Chrome that does
   nothing says so.
6. **Degrades to a still.** With JavaScript off the demo renders its first frame
   as static markup and stays legible.
7. **Contained.** Wide frames scroll inside their own `overflow-x: auto`. The
   page body never scrolls sideways at any width.
8. **Narrow screens.** Windows stop being draggable below `48rem` and stack
   vertically, keeping their fixed rails anchored. Do not hide a demo on mobile.

### The two machines

Satelle's whole shape is two machines, so the demos are built from two window
types and they must stay visually distinct:

- **Controller window.** The operator's terminal, on Linux. Ground `--sa-0`,
  mono throughout, a title bar reading the shell and host. This is where the
  reader's agency lives.
- **Host window.** The controlled desktop, on Windows or macOS. Ground
  `--sa-2`, chrome `--sa-3`, sans UI inside because it is imitating desktop
  applications. A Host window carries a state dot in its title bar and the Host
  alias. It is never presented as something the reader controls directly.

Both are drawn, never screenshotted. Application interiors (a spreadsheet grid,
a PCB canvas, a document page) are built from the same tokens as the rest of the
page, at low chroma, so they read as diagrams of the work rather than fake
screenshots. Do not imitate a real vendor's UI closely enough to be mistaken for
it, and do not use any vendor's logo or wordmark.

## 7. Fidelity contract

Every string a demo prints as machine output must exist in the product. The
sources, all in this repository:

| What | Where |
| --- | --- |
| `run`/`steer`/`status` human output | `crates/satelle-cli/src/main.rs` `print_session_human` |
| `stop` human output | same file, the stop branch: `Outcome`, `Previous state`, `Current state`, `Changed`, `Stopped at` |
| `doctor` human output | same file: `Host`, `Status`, `Ready`, `Scopes`, then `[severity] summary (fixability)` and `  evidence:` |
| `host sessions` output | same file: `Session`/`User`/`State`/`Kind`/`Display`/`Selected`/`Portable selectors`/`Native selectors` |
| Turn states | `status_label`: `starting`, `running`, `recovery_pending`, `completed`, `blocked`, `failed`, `stopped` |
| Event types | `crates/satelle-core/src/events.rs`: `preflight`, `readiness`, `provider_smoke`, `turn_started`, `turn_progress`, `action_required`, `command_failed`, `turn_completed`, `turn_blocked`, `turn_failed`, `turn_stopped` |
| Event sources | `cli`, `host_daemon`, `codex_adapter` |
| Human event line | `eprintln!("{}: {}", event_type, message)` |
| Log sources / levels | `host_daemon`, `storage`, `codex_adapter` / `info`, `warn`, `error` |
| Log cursor shape | `slc1_%016x` |
| Session id shape | `rs_` + UUIDv7, lowercase (`crates/satelle-core/src/ids.rs`) |
| MCP tool names | `crates/satelle-cli/src/mcp/schema.rs`: `config_check`, `config_explain`, `paths`, `status`, `logs`, `doctor`, `host_status`, `host_sessions`, and mutations `run`, `steer`, `stop`, `setup`, `repair`, `host_update`, `host_lifecycle` |
| Flags | `docs/reference/generated-cli.mdx`, which CI checks against `satelle --help` |
| Schema versions | `satelle.run.v2`, `satelle.status.v2`, `satelle.steer.v2`, `satelle.stop.v1`, `satelle.doctor.v1`, `satelle.events.v2`, `satelle.logs.entry.v1` |

Demo task content comes from an independent computer-use showcase pack (MIT):
four synthetic desktop workflows in LibreOffice Calc, KiCad, Godot, and
LibreOffice Writer. The prompts shown on the page are those tasks' real prompts.
They are synthetic demo tasks and the page does not imply they are benchmark
results or customer work.

Prompt text, host aliases, and Session identifiers are invented but
well-formed. Timings and step counts shown are illustrative and labelled as
illustrative. Nothing on the page presents a measured number as if it were
measured.

## 8. Page structure

Measured off v12.sh at a 1440 viewport and matched beat for beat. The reference
has five `<main>` children; so does this page. Its content column spans
x=27..1398, 1371px against 27px gutters, 95.7% of the page; this page spans
x=32..1408, 1376px. Its h1 is 31.104px at weight 400 in an 832px column, and
carries its supporting sentence inside the same h1 at a muted color; so does
this one. Every heading on both pages is weight 400.

| # | Beat | v12.sh | Satelle |
| --- | --- | --- | --- |
| nav | wordmark plus two pills | Book a call, Start a run | GitHub, Read the docs |
| 1 | hero, holding its own demo | 1146px | 991px |
| 2 | proof band | 281px, 12 customer logos | 325px, the six-cell support matrix |
| 3 | demo grid, two by two | 1356px, four channel demos | 2215px, four Session demos |
| 4 | three-up supporting cards | 738px | 417px |
| 5 | fifth beat | 612px, six testimonials | 817px, implemented, not implemented, verify |
| cta | centered line, one button, tinted band above the footer | | |
| foot | five columns plus an oversized mark bleeding off the bottom | | |

Document height 5043px against 5596px. Content column x=27..1398 against
x=32..1408. Cards 679px wide on both, and all four of this page's demo cards are
850px tall against the reference's uniform 624px.

Satelle has no customers, so beats 2 and 5 carry the honest equivalents rather
than being dropped: exactly where the product runs, and exactly what it does not
do yet. Dropping them would have cost the page two structural beats and left the
demos to carry the whole middle.

Section 3 runs taller than the reference's because these demos carry more than
v12's do: a probe table, a tool inventory, a three-path diagram. The cards are
identical to each other by construction, through `grid-auto-rows: 1fr` on the
two-up grid, so the row takes the tallest demo and every card stretches to it.

**Nothing scrolls inside a card.** A fixed 43rem viewport was tried first and put
a quarter to a half of every demo behind an inner scrollbar, including states the
rail could select and controls the reader had to reach; a nested scroller also
steals the wheel from the page. Keeping the tallest demo short is therefore a
content job, done in the demos. The four bodies currently measure 691, 799, 778
and 833px. When one of them grows, cut it rather than adding a scroller.

**One window, one artifact.** The reference's card body holds a single window and
nothing else. Each of these was two or three stacked blocks and had to be cut
back: durability lost a readout strip that repeated what both terminals print,
readiness lost an announce line and a note that now live in the card head,
transports lost an authority band that repeated the "Boundaries you hold" claim
card and a third fact per column, and the agent's fifteen-name tool inventory
became two wrapping lines of names. That took the cards from 1432px to 1041px.

The equalisation applies only once the cards are gridded. Stacked, it padded
every card out to the tallest and added about 4000px to a phone.

Cards carry a fill step and a 4px radius, no border. A border marks where one
machine's surface ends, and a layout container is not a machine, which is also
what the standing "no decorative card chrome" rule is asking for. The hairline
stays on `.sa-win`, where it is a real boundary.

### Accent discipline

The reference carries saturated colour on 0.037% of its pixels. An early build
of this page carried it on 1.52%: a 30% accent wash on the stage, a crimson
shell prompt in every terminal, the Session identifier printed eight times in
crimson, and seven crimson buttons. It now sits at 0.46%, from:

- the two calls to action, which is the accent's whole job;
- semantic state, where the colour is the information (`passed`, `blocked`);
- the current step on a rail, and the active tab.

Everything else takes the ramp. A demo's advance control uses `.sa-btn-step`,
which is the primary button's shape in ramp colours: it drives the demo rather
than asking the reader for anything. The card-head link is primary ink and
turns accent only on hover, as the reference's does.

### The hero stage

The reference floats its app window on a tinted slab: no border, a ~3px radius,
and a fill sitting 33 to 84 of 255 off the page ground. The window is inset 125px
from the stage edge, and the small terminal window breaks 94px past the app
window's left edge while still landing inside the slab. This page reproduces all
four numbers: crimson and violet radials over `--sa-3`, `--radius-sm`, an inset
that scales with the viewport, and a terminal that breaks 95px past a 1160px Host
window.

The stage is clean at its top edge and about 35 of 255 below the page ground at
the bottom, warm on the left and cool on the right, as two directional washes
with their own alpha. Radials anchored past the box were tried first and put
colour in the wrong corners while leaving the middle at a delta of 6.

The stage holds the windows and nothing else. Captions and the task picker do not
belong on it: the picker lives inside the Controller window, because choosing the
task is the operator's move, and the per-demo captions are screen-reader only
because the card head already carries their content visibly.

### Computer Use presentation

The hero is not a log with pictures beside it. It is a Turn playing back at
speed. Three things make it read that way, in `demos/control.tsx`: the screen
aura, the driven pointer, and the rule that the Host does not change until the
pointer gets there.

The shapes and numbers are taken from the shipping implementations rather than
invented, so an operator who has seen one recognises this. What was recoverable,
and from where:

| Source | What it gave |
| ------ | ------------ |
| Claude in Chrome extension, `assets/agent-visual-indicator.js` | the screen-edge glow, complete and verbatim |
| Codex Desktop Computer Use extension, `content-scripts/codex.js` | the cursor's geometry, glow filter, and motion model |
| `~/.codex/computer-use/config.json` | the local overlay's accent `#339cff` and its label, "Codex is using your computer" |

Codex's own screen overlay is a native Metal effect whose radii and easing are
compiled in and could not be read. So the aura's structure is the one that
could be, in crimson instead of a blue accent.

**The aura** is not a border. Three stacked inset shadows, no line and no
radius, at 15/25/35px and 0.7/0.5/0.2 alpha. A hard 2px ring was the first
attempt and read as window chrome rather than as a screen under someone else's
control. It is held for exactly as long as the Turn is non-terminal, so it
clears on `turn_completed` and the reader sees the desktop handed back. Its
label is a pill, which is what both vendors ship, at top centre because the
Controller window covers the bottom left where they put theirs.

**The pointer** is a crimson arrow with a white outline, carrying the same glow
filter the shipped cursors use: `drop-shadow(0 0 6px …90%) drop-shadow(0 0 15px
…48%)`. That pair of stops is the signature both vendors converged on.

This is a deliberate departure. Codex's arrow is black and puts the accent only
in the glow, and this page followed that first. But Satelle's pointer is meant
to be read as Satelle's, so the accent is on the arrow itself. The white outline
is what makes that work: crimson alone disappeared into the lighter application
interiors, which is why the faithful version was tried first.

Every `StageStep` may name `at: { x, y }` as fractions of the stage box and an
`act`:

| `act`   | What it draws                    | When |
| ------- | -------------------------------- | ---- |
| `type`  | a caret at the point, three keystrokes then solid | the step enters text |
| `drag`  | a trail behind the pointer, aimed back along the travel and as long as it was | the step draws, routes, or selects across |
| `click` | nothing of its own               | the step activates something |
| `move`  | nothing                          | default: the Host responding, or a check with no input |

On travel the pointer squashes along its axis, dipping to 0.85 at the midpoint,
as `rotate(axis) scale(1, s) rotate(-axis)`. On arrival it gives a short damped
shake, theirs being 12.5 degrees on a 660ms period over 1410ms, compressed here
to finish inside the demo's dwell so a settled demo has nothing running.

A click is also drawn, as two rings contracting onto the point over 480ms with a
held peak. Neither shipped implementation draws one: 21.5MB of extension
contains no `ripple`, no `keyframes`, and no per-click marker, and they carry the
press in their motion springs alone. That works at 60fps in a live session and
does not work in a stepped demo, where a click step landed with nothing at all
to see. The first attempt at this was 300ms with no hold and was still easy to
miss, which is the whole complaint it exists to answer.

**Text the Turn rewrites is typed, not swapped.** `Retype` in
`demos/typewriter.tsx` deletes the divergent tail one character at a time and
writes the new one, leaving the common prefix alone, which is what an editor
actually does: watching `=F5*G5` become `=F5*G5*(1-I5)` is the clearest thing on
the stage. Deleting runs faster than typing, because holding backspace is faster
than choosing characters. A `typeIn` mode covers text that appears rather than
changes, which is how a line the Turn has just written to a script gets written
rather than pasted.

The caret belongs in the field being edited, at the insertion point, not
floating beside the mouse pointer, which is not a thing any editor does. An
earlier version hung one off the cursor, where it was also invisible in
practice: it ran for 1020ms inside a 420ms window and blinked off for half of
each cycle. A typing step therefore gets a longer dwell than the others, since
cutting away mid-edit would show the pointer setting off again while the last
edit was still being written.

Movement is a `transition` on `left` and `top`, not a keyframe, because a move
has to start wherever the last action left the pointer, which a keyframe cannot
know, and not `translate`, because the target is a percentage of the stage box
and a percentage in `translate` resolves against the element's own size. The
duration is paced by distance, 170ms to 700ms: a pointer that takes as long to
cross the screen as to nudge 20px reads as teleporting. The curve is local to
the cursor, since the page's own easing is an ease-out that made it leave the
mark at full speed rather than accelerate out of rest.

**The Host changes on arrival, not on selection.** This is the part that does
the most work and the part that was wrong longest. `step` is the action the
pointer is working on; `phase` says whether it is still travelling or has
landed; and the drawn application, the event line, and the rail's done state all
follow the *committed* step, which lags by the travel time. Committing on
selection meant the pointer spent every step narrating a change that had already
happened, which is exactly why the hero read as an overview rather than a
session.

For the same reason the stage wrapper is keyed on the stage alone. It was keyed
on the step too, which unmounted and remounted the whole drawn application on
every action and faded it back in: the application appeared to blink rather than
to change. Letting React diff the interior means only the cells that changed
change, and those ease over 150ms.

A step with no `at` leaves the pointer put, so a run of Host-side steps does not
make the cursor wander. Targets are measured against the built page rather than
guessed, and they account for the Controller window covering the Host's bottom
left corner: a target under it would put the pointer somewhere the reader cannot
see it.

Both the aura and the pointer live inside `.desk-stage`, which carries an
explicit `z-index: 0` to make itself a stacking context. Without it they were
only positioned, not layered, and painted over the operator's own terminal: the
pointer appeared to be clicking around inside the Linux window it drives *from*.

Under `prefers-reduced-motion` the demo settles straight to the completed Turn,
so the aura is already released and the pointer is already at its last target.
Nothing needs a special case: the global 1ms clamp in `landing.css` covers the
enter, the squash, the landing shake, and the caret.

### Dragging the demo windows

A window may be dragged only within the box the page marks `data-demo-area`,
which is the tinted stage, and it is held fully inside it on every edge. Not the
window stack: the Controller rests outside the stack by design, breaking past
the Host window's left edge, so bounding a drag by the stack would snap it
inward the moment it was touched.

## 9. Implementation

React components under `website/app/(landing)/`, composed by
`website/app/page.tsx`. Tokens and primitives in
`website/app/(landing)/landing.css`, imported only by the landing layout.

The Fumadocs stylesheet and `RootProvider` live in `website/app/docs/layout.tsx`,
not the root layout, so the docs preset never reaches the landing page and the
landing tokens never reach the docs.

No client dependencies beyond React. Every demo is a self-contained client
component holding its own reducer. No animation library, no drag library, no
icon package: icons are inline SVG at 1.5px stroke on a 24px grid, sized in `em`
so they track the type they sit beside.

Demo state is a plain reducer over a frozen script of frames, so a demo can be
driven forward by a click, a key, or a test. State never lives in an effect that
mirrors a prop.
