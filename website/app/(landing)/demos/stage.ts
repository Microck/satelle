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
   * Where the pointer is when this action commits, as fractions of the stage
   * box: { x: 0, y: 0 } is its top left, { x: 1, y: 1 } its bottom right.
   *
   * This is what makes the hero read as Computer Use rather than as a log with
   * pictures: the reader watches a cursor go to the thing the message names.
   * Point it at the element this step actually changes. A step with no `at`
   * leaves the pointer where the previous step put it.
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
