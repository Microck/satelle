# Controller-to-Host illustration

The three supporting cards in `#claims` are replaced by one full-width device
animation. The hero, four workflow demos, support matrix and evidence section
are unchanged. The same landing theme tokens supply the illustration's paint.

Six upright desktop-class silhouettes drift around a central laptop. They take
turns sending a red pulse. The center remains neutral until the pulse arrives,
then lights in Satelle red. Its little application window fills work rows and a
progress bar, shows completion, and dims back to idle before the next task.
Returning to idle does not represent powering off the machine or deleting its
Session. One deterministic clock owns the orbits, signals and screen activity;
there are no CSS animation loops, external assets or added dependencies.

The block pauses offscreen, when the tab is hidden, or by click/Space. R replays.
Reduced motion starts with a static idle diagram and only animates one cycle on
explicit activation. Listeners and observers are disposed on unmount. Compact
screens use a taller orbit, keeping the Host and all six devices visible.

## Capability boundary

The copy says "Start on one machine. Work on another," not unrestricted support
for every device. `README.md` at `49daecc3` verifies macOS, Windows and Linux
Controllers and candidate macOS/Windows native Hosts gated by live readiness.
The illustration uses laptops, a desktop, a workstation, a mini PC and a rack
as **Controller** form factors, not six kinds of guaranteed native Hosts. It
intentionally does not add a phone/tablet client or imply native Linux Host
support. The center is an already configured, authorized, ready Host. This is a
scripted explanation, not auto-discovery, provisioning, telemetry or real work.

## Checks

`device-network.test.mjs` exercises the phase ordering, source round-robin,
geometry bounds/collisions, pulse endpoints, idle/cooldown and syntax. It runs
alongside the existing demo tests in `prebuild`.

`device-network-browser-check.mjs` runs after the existing landing browser suite
on the production-exported `/`. It observes all six signals and actual rendered
screen progress, verifies pause/resume and reduced motion, and checks desktop
and compact layouts. Its screenshots, video, sequence proof and checks.json are
stored under `device-network/` in the existing browser-evidence artifact. Local
component previews are supplementary; the current build result belongs in the
PR and is not inferred from a previous commit's CI.
