import type { ReactNode } from 'react';

/**
 * A Host stage is the drawn interior of one desktop application on the
 * controlled Host, plus the Turn script that drives it.
 *
 * Stages are drawn from the page's own tokens at low chroma. They are diagrams
 * of the work, not imitations of a vendor's interface: no vendor logo, no
 * wordmark, and never close enough to be mistaken for a screenshot.
 */
export type StageId = 'excel' | 'kicad' | 'godot' | 'filing';

/**
 * One committed step of the Turn. `event` is a real Satelle event type from
 * crates/satelle-core/src/events.rs and `message` is what the Controller prints
 * after it, matching the human event line `eprintln!("{}: {}", type, message)`.
 */
export type StageStep = {
  event: 'turn_started' | 'turn_progress' | 'turn_completed';
  message: string;
  /** Short label for the step rail. Four words at most. */
  label: string;
  /**
   * Fallback pointer position, as fractions of the stage box: { x: 0, y: 0 } is
   * its top left, { x: 1, y: 1 } its bottom right.
   *
   * Used only when the stage does not mark a target element for this step, and
   * on the server, where nothing can be measured. Prefer marking the element:
   * a fixed coordinate cannot follow anything that moves, and most steps of
   * most stages reflow the interior they act on. Coordinates measured against
   * the layout *after* a step commits had the pointer travelling to whatever
   * happened to sit there beforehand, which read as clicking at random.
   *
   * Coordinates are still right for a target that is a genuine point rather
   * than an element: somewhere on a board canvas, a spot in a game viewport.
   */
  at?: { x: number; y: number };
  /**
   * What the pointer does on arrival. `move` is the default and draws nothing.
   * `click` flashes a ring, `type` shows a caret at the point, and `drag` draws
   * a short trail behind the pointer.
   */
  act?: 'move' | 'click' | 'type' | 'drag';
};

export type StageProps = {
  /** Index into `steps`. The interior renders the state *after* this step. */
  step: number;
  /**
   * The step the pointer is on its way to, which is `step + 1` while it
   * travels and `step` once it has landed.
   *
   * A stage uses this to put `data-cu-target` on the one element that step is
   * about to act on, and the pointer measures that element live. The stage is
   * the only thing that knows which element a given action belongs to, and it
   * already has the step logic to decide.
   *
   * Mark an element that exists in the *current* render, since that is the
   * layout the pointer is travelling through. For an action that creates
   * something, mark whatever will hold it. Mark nothing when the action has no
   * element, and the step's `at` is used instead.
   */
  next: number;
  /** True when the reader prefers reduced motion: settle instantly. */
  reduced: boolean;
};

export type Stage = {
  id: StageId;
  /** Chip label in the task picker. Two or three words. */
  pick: string;
  /** Application name shown in the Host window title bar. */
  app: string;
  /** Document or project name shown in the Host window title bar. */
  file: string;
  /** The task prompt, verbatim from the showcase pack. */
  prompt: string;
  /** Illustrative wall-clock and action count, labelled as illustrative. */
  budget: { minutes: number; steps: number };
  steps: StageStep[];
  Render: (props: StageProps) => ReactNode;
};
