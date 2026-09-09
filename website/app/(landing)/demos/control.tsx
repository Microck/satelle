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

/**
 * The screen aura, drawn over the whole controlled screen.
 *
 * Held for exactly as long as control is held, so it clears the moment the Turn
 * completes and the reader sees the desktop handed back.
 */
export function ControlRing({ held }: { held: boolean }) {
  return (
    <span className="ctl-ring" data-held={held} aria-hidden="true">
      <span className="ctl-ring-label">Satelle is using this computer</span>
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
        // The axis the squash happens along: the direction of this move.
        '--ctl-axis': `${Math.round((Math.atan2(dy, dx) * 180) / Math.PI)}deg`,
        '--ctl-trail': `${trailRem}rem`,
      } as CSSProperties}
      aria-hidden="true"
    >
      {/* Black body, white outline. The accent is carried by the glow, not the
          arrow: that is how the shipped cursor is built, and a crimson arrow
          also disappeared into the lighter application interiors. `paint-order`
          puts the stroke behind the fill so the outline reads as an outline
          rather than eating the shape. */}
      <svg
        className="ctl-cursor-glyph"
        width="24"
        height="24"
        viewBox="0 0 17 23"
        focusable="false"
      >
        <path
          d="M1.5 1.5 14.6 12.4 8.2 12.8 11.4 20.1 8.6 21.3 5.4 14 1.5 17.4Z"
          fill="#0a0a0a"
          stroke="#fff"
          strokeWidth="2.1"
          strokeLinejoin="round"
          paintOrder="stroke fill"
        />
      </svg>
      {/* Keyed on the step so each typing action replays the burst. The
          reader complained the hero was "animated by blinking", so this ends:
          a few keystrokes landing, then a settled caret. */}
      {acting && act === 'type' ? <i key={`t${step}`} className="ctl-type" /> : null}
    </span>
  );
}
