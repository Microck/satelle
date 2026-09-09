'use client';

import type { CSSProperties } from 'react';

import type { StageStep } from './stage';
import './control.css';

/**
 * The two things that make a drawn desktop read as one under agent control,
 * borrowed from how a native Computer Use session presents itself: a ring drawn
 * around the edge of the controlled screen for as long as control is held, and
 * a pointer that visibly goes to the thing being acted on.
 *
 * Both are Satelle's crimson rather than the blue a Codex session uses, because
 * this is Satelle's Host, but the idea is the one an operator already knows.
 */

/** Drawn over the whole screen area, so it frames the desktop, not the window. */
export function ControlRing({ held }: { held: boolean }) {
  return (
    <span className="ctl-ring" data-held={held} aria-hidden="true">
      <span className="ctl-ring-label sa-mono">Computer Use</span>
    </span>
  );
}

/**
 * Where the pointer stands once `step` has committed. Carries the last stated
 * position forward, so a step that names none leaves the pointer where the
 * previous action put it.
 */
function positionAt(steps: StageStep[], step: number) {
  let at = { x: 0.5, y: 0.5 };
  for (let i = 0; i <= step && i < steps.length; i += 1) {
    const named = steps[i]?.at;
    if (named) at = named;
  }
  return at;
}

/**
 * The move this step makes. It has to compare consecutive steps, not
 * consecutive *stated* positions: a step that names no target has not moved the
 * pointer at all, and treating the last named position as its origin reported
 * travel that never happened, which drew a drag trail out of nowhere.
 */
function travel(steps: StageStep[], step: number) {
  return { from: positionAt(steps, step - 1), to: positionAt(steps, step) };
}

/**
 * How long the pointer takes to reach `step`'s target.
 *
 * A pointer that takes as long to cross the whole screen as it does to nudge
 * 20px reads as teleporting, so the move is paced by how far it goes. Distance
 * is measured in stage fractions: the box is not square, so this is slightly
 * anisotropic, which is invisible in a duration.
 *
 * Exported because the demo has to hold the Host's change back until the
 * pointer arrives. If these two numbers disagree, the application changes
 * before the pointer that supposedly caused it gets there.
 */
export function moveDurationMs(steps: StageStep[], step: number): number {
  // Nothing animates into the first step: the pointer is simply already on
  // screen when the session opens, so there is nothing to wait for.
  if (step <= 0) return 170;
  const { from, to } = travel(steps, step);
  const distance = Math.hypot(to.x - from.x, to.y - from.y);
  return Math.round(Math.min(700, 170 + distance * 520));
}

/**
 * The pointer. Position and action come from the step, so the cursor is driven
 * by the same script as the event log and cannot drift out of agreement with it.
 *
 * `left` and `top` are transitioned rather than animated, because a move has to
 * start from wherever the last step left the pointer, which a keyframe cannot
 * know. They are also transitioned rather than composited through `transform`,
 * because the target is a percentage of the stage box and a percentage in
 * `translate` resolves against the element's own size instead. One small
 * absolutely positioned element for 400ms once per step is not worth a wrapper.
 */
export function ControlCursor({
  step,
  steps,
  /** True once the pointer has arrived and the action is landing. */
  acting,
}: {
  step: number;
  steps: StageStep[];
  acting: boolean;
}) {
  const { from, to } = travel(steps, step);
  const act = steps[step]?.act ?? 'move';

  const dx = to.x - from.x;
  const dy = to.y - from.y;
  const distance = Math.hypot(dx, dy);

  // The trail sits behind the pointer, so it points back along the travel, not
  // at a fixed angle. Same fraction-space caveat as the duration: good enough
  // for a direction, and a roughly right direction beats a constant wrong one.
  const backAngle = Math.round((Math.atan2(-dy, -dx) * 180) / Math.PI);
  // No travel, no trail: a drag that starts where the pointer already stands
  // would otherwise draw a streak out of nowhere.
  const trailRem = Math.min(2.5, distance * 6).toFixed(2);

  return (
    <span
      className="ctl-cursor"
      data-act={act}
      data-acting={acting}
      style={{
        left: `${to.x * 100}%`,
        top: `${to.y * 100}%`,
        '--ctl-move': `${moveDurationMs(steps, step)}ms`,
        '--ctl-back': `${backAngle}deg`,
        '--ctl-trail': `${trailRem}rem`,
      } as CSSProperties}
      aria-hidden="true"
    >
      {/* A click lands as one expanding ring, keyed on the step so it replays
          on every action rather than once per mount. It fires on arrival: a
          ring that expands while the pointer is still travelling would be a
          click on whatever it happened to be passing over. */}
      {acting && act === 'click' ? <i key={step} className="ctl-hit" /> : null}
      <svg width="18" height="20" viewBox="0 0 18 20" focusable="false">
        <path
          d="M2 1.5 15.5 11 9.5 11.6 12.3 17.8 9.6 19 6.8 12.8 2 16.4Z"
          fill="var(--sa-accent)"
          stroke="#fff"
          strokeWidth="1.2"
          strokeLinejoin="round"
        />
      </svg>
      {/* Keyed on the step so each typing action replays the burst. The
          reader complained the hero was "animated by blinking", so this ends:
          a few keystrokes landing, then a settled caret. */}
      {acting && act === 'type' ? <i key={`t${step}`} className="ctl-type" /> : null}
    </span>
  );
}
