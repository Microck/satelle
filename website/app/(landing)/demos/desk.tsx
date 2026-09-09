'use client';

import { useCallback, useEffect, useMemo, useReducer, useRef, useState } from 'react';
import { useReducedMotion } from './motion';
import { ControlCursor, ControlRing } from './control';
import { useMovable, useViewportAtLeast } from './movable';
import type { Stage, StageId } from './stage';
import { excelStage } from './stages/excel';
import { filingStage } from './stages/filing';
import { godotStage } from './stages/godot';
import { kicadStage } from './stages/kicad';
import './desk.css';

const HOST_ALIAS = 'win-11-lab';
const SESSION_ID = 'rs_0193f2c1-8a4e-7c33-b0d1-5e9a4c17be02';
const TURN_ID = 'rt_0193f2c1-8a52-7f10-9c44-2b7e8d31af65';

const STAGES: Stage[] = [excelStage, kicadStage, godotStage, filingStage];

/**
 * How long a committed action is left on screen before the pointer sets off for
 * the next one. The travel time is on top of this and is set by the distance.
 *
 * A typing action gets longer, because the field it lands in deletes the old
 * text and types the new: cutting away mid-edit would show the pointer starting
 * its next move while the last one was still being written. Sized to the
 * longest retype on the page.
 */
const DWELL_MS = 360;
const TYPE_DWELL_MS = 1100;

/**
 * True once the element has been on screen, and true forever after. A hero that
 * plays itself out while the reader is further down the page has already
 * finished by the time they arrive.
 */
function useRunOnceInView(ref: React.RefObject<Element | null>, skip: boolean) {
  const [seen, setSeen] = useState(skip);
  useEffect(() => {
    if (seen || skip) return;
    const el = ref.current;
    if (!el || typeof IntersectionObserver === 'undefined') {
      setSeen(true);
      return;
    }
    const observer = new IntersectionObserver(
      (entries) => {
        if (entries.some((e) => e.isIntersecting)) {
          setSeen(true);
          observer.disconnect();
        }
      },
      { rootMargin: '-15% 0px -15% 0px' },
    );
    observer.observe(el);
    return () => observer.disconnect();
  }, [ref, seen, skip]);
  return seen;
}

/**
 * Demo state. A plain reducer keeps every transition drivable by a click, a
 * key, or a test, with no effect mirroring anything.
 *
 * `step` is the action the pointer is working on. `phase` says whether it is
 * still on its way there or has landed, and that distinction is the whole
 * illusion: the Host's change and the event line are held back until the
 * pointer arrives. Committing them on arrival is what makes the reader see a
 * pointer *causing* the change instead of narrating one that already happened.
 */
type Phase = 'travel' | 'acted';
type State = { stage: StageId; step: number; phase: Phase; auto: boolean };
type Action =
  | { type: 'pick'; stage: StageId }
  | { type: 'arrive' }
  | { type: 'next' }
  | { type: 'tick' }
  | { type: 'goto'; step: number }
  | { type: 'settle'; step: number }
  | { type: 'replay' };

const lastStepOf = (id: StageId) =>
  (STAGES.find((candidate) => candidate.id === id) ?? STAGES[0]).steps.length - 1;

function reduce(state: State, action: Action): State {
  const last = lastStepOf(state.stage);
  switch (action.type) {
    // Switching tasks plays that task from the start, the way the first view
    // does. A Session runs one Turn at a time, so nothing carries over.
    case 'pick':
      return { stage: action.stage, step: 0, phase: 'travel', auto: true };
    // The pointer reached the target. Now the action lands and the Host changes.
    case 'arrive':
      return { ...state, phase: 'acted' };
    // A reader taking over ends the automatic run: nothing should keep moving
    // under a pointer that is already driving. They still get the travel, so a
    // step they drive looks like a step that drove itself.
    case 'next':
      return { ...state, step: Math.min(state.step + 1, last), phase: 'travel', auto: false };
    case 'goto':
      return {
        ...state,
        step: Math.max(0, Math.min(action.step, last)),
        phase: 'travel',
        auto: false,
      };
    // Straight to a committed step with no travel, for reduced motion.
    case 'settle':
      return {
        ...state,
        step: Math.max(0, Math.min(action.step, last)),
        phase: 'acted',
        auto: false,
      };
    case 'replay':
      return { ...state, step: 0, phase: 'travel', auto: true };
    // The automatic run, which stops of its own accord at the last action.
    case 'tick':
      if (!state.auto || state.step >= last) return { ...state, auto: false };
      return { ...state, step: state.step + 1, phase: 'travel' };
  }
}

export default function DeskDemo() {
  const [state, dispatch] = useReducer(reduce, {
    stage: 'excel',
    // Starts at the first action and plays itself once, so the hero is visibly
    // a session running rather than a screenshot of one. Reduced motion gets
    // the finished Turn on the first paint instead.
    step: 0,
    // Committed, not travelling. The server renders this, so starting mid-travel
    // would hand a reader without JavaScript an untouched application and an
    // empty event log. Every step after the first still travels before it lands.
    phase: 'acted',
    auto: true,
  });
  const reduced = useReducedMotion();
  // Dragging is pointer work that does not survive a stacked narrow layout, so
  // it is disabled below 60rem where the windows sit one above the other.
  const movableEnabled = useViewportAtLeast('60rem');
  // Both windows are clamped to the stack, so neither can be pushed somewhere
  // a pointer cannot reach it.
  const stackRef = useRef<HTMLDivElement>(null);
  const started = useRunOnceInView(stackRef, reduced);
  const host = useMovable(movableEnabled, stackRef);
  const controller = useMovable(movableEnabled, stackRef);
  const captionId = 'desk-caption';
  const regionId = 'desk-region';

  // The terminal is capped so the floating Controller cannot grow over the whole
  // Host window, which means the newest event can fall below the fold. Keeping it
  // pinned to the bottom is real synchronisation with the DOM's scroll position,
  // which is what an effect is for.
  const termRef = useRef<HTMLDivElement>(null);

  const stage = useMemo(
    () => STAGES.find((candidate) => candidate.id === state.stage) ?? STAGES[0],
    [state.stage],
  );

  // The action whose effects are on screen. While the pointer is still on its
  // way to `state.step`, the Host still shows the previous one, so at the very
  // first step this is -1 and the application sits untouched with an empty log.
  const committed = state.phase === 'acted' ? state.step : state.step - 1;
  const last = stage.steps.length - 1;
  const finished = committed === last;
  const turnState = finished ? 'completed' : 'running';
  const visible = stage.steps.slice(0, committed + 1);

  // Pin the newest event to the bottom of the capped terminal. Keyed on the
  // committed action, since that is when a line is actually added.
  useEffect(() => {
    const el = termRef.current;
    if (el) el.scrollTop = el.scrollHeight;
  }, [committed, state.stage]);

  // The action lands when the pointer gets there, and the pointer is the only
  // thing that knows how far it had to go: it measures its own target, so
  // asking the demo to compute the same duration independently only gave the
  // two a chance to disagree. `ControlCursor` calls this when it arrives.
  const handleArrive = useCallback(() => dispatch({ type: 'arrive' }), []);

  // Leave the committed action on screen, then set off for the next one.
  useEffect(() => {
    if (reduced || !started || !state.auto || state.phase !== 'acted') return;
    const dwell = stage.steps[state.step]?.act === 'type' ? TYPE_DWELL_MS : DWELL_MS;
    const id = window.setTimeout(() => dispatch({ type: 'tick' }), dwell);
    return () => window.clearTimeout(id);
  }, [reduced, started, state.auto, state.phase, state.step, state.stage, stage.steps]);

  // Reduced motion never animates, so it opens on the finished Turn.
  useEffect(() => {
    if (reduced) dispatch({ type: 'settle', step: lastStepOf('excel') });
  }, [reduced]);

  return (
    <div className="desk">
      <div className="desk-stack" id={regionId} aria-describedby={captionId} ref={stackRef}>
        {/* The controlled machine. Never presented as directly clickable. */}
        <section
          className="sa-win desk-host"
          data-kind="host"
          data-focused={host.dragging}
          ref={host.windowRef as React.RefObject<HTMLElement>}
          style={host.windowStyle}
          {...host.windowData}
          aria-label={`Host ${HOST_ALIAS}, Windows 11`}
        >
          <div className="sa-win-bar">
            <Lights />
            <span
              className="sa-win-bar-grip"
              aria-label={`Move the ${HOST_ALIAS} Host window`}
              {...host.gripProps}
            >
              <span className="desk-bar-alias">{HOST_ALIAS}</span>
              <span className="sa-faint">Windows 11</span>
              <span className="sa-faint desk-bar-file">
                {stage.file} &middot; {stage.app}
              </span>
            </span>
            <span className="sa-state" data-state={turnState}>
              <span className="sa-dot" data-state={turnState} />
              {turnState}
            </span>
          </div>
          <div className="sa-win-body desk-stage">
            {/* Keyed on the stage only. It used to be keyed on the step too,
                which unmounted and remounted the whole drawn application on
                every action and faded it back in: the application appeared to
                blink rather than to change. Letting React diff the interior
                means only the cells that changed change. */}
            <div key={state.stage} className="desk-stage-in">
              <stage.Render step={committed} next={state.step} reduced={reduced} />
            </div>
            {/* Control is held for as long as the Turn is not terminal, which is
                exactly when the Host is driving the desktop. */}
            <ControlRing held={!finished} />
            <ControlCursor
              step={state.step}
              steps={stage.steps}
              acting={state.phase === 'acted'}
              onArrive={started && !reduced ? handleArrive : undefined}
            />
          </div>
        </section>

        {/* The operator's machine. The reader's agency lives here. */}
        <section
          className="sa-win desk-controller"
          data-kind="controller"
          data-focused={controller.dragging}
          ref={controller.windowRef as React.RefObject<HTMLElement>}
          style={controller.windowStyle}
          {...controller.windowData}
          aria-label="Controller terminal on Linux"
        >
          <div className="sa-win-bar">
            <Lights />
            <span
              className="sa-win-bar-grip"
              aria-label="Move the Controller window"
              {...controller.gripProps}
            >
              <span className="desk-bar-alias">operator@thinkpad</span>
              <span className="sa-faint">Linux</span>
            </span>
            <span className="sa-faint sa-mono">satelle</span>
          </div>

          <fieldset className="desk-picker">
            <legend className="sa-sr">Task to run on the Host</legend>
            {STAGES.map((candidate) => (
              <label
                key={candidate.id}
                className="desk-chip"
                data-active={candidate.id === state.stage}
              >
                <input
                  type="radio"
                  name="desk-task"
                  className="sa-sr"
                  checked={candidate.id === state.stage}
                  onChange={() => dispatch({ type: 'pick', stage: candidate.id })}
                />
                {candidate.app}
              </label>
            ))}
          </fieldset>

          <div className="sa-win-body desk-term sa-term" ref={termRef}>
            <div className="desk-term-cmd">
              <span className="sa-term-prompt">$ </span>
              <b>satelle run</b> --host {HOST_ALIAS} \{'\n'}
              {'  '}
              <span className="desk-term-prompt-text" aria-hidden="true">
                &quot;{stage.prompt}&quot;
              </span>
              <span className="sa-sr">&quot;{stage.prompt}&quot;</span>
            </div>

            <ol className="desk-events">
                  {visible.map((step, index) => (
                    <li key={step.label} className={index === committed ? 'sa-in' : undefined}>
                      <button
                        type="button"
                        className="desk-event"
                        data-current={index === committed}
                        aria-current={index === committed ? 'step' : undefined}
                        onClick={() => dispatch({ type: 'goto', step: index })}
                      >
                        <span className="desk-event-type">{step.event}</span>
                        <span className="desk-event-msg">{step.message}</span>
                      </button>
                    </li>
              ))}
            </ol>

            {finished ? (
                  <div className="desk-result">
                    <span>
                      <b>Session:</b> {SESSION_ID}
                    </span>
                    <span>
                      <b>Host:</b> {HOST_ALIAS}
                    </span>
                    <span>
                      <b>Status:</b> <span className="sa-term-ok">completed</span>
                    </span>
                    <span>
                      <b>Turns:</b> 1
                    </span>
                    <span>
                      <b>Latest turn:</b> {TURN_ID}
                    </span>
                    <span className="sa-term-dim">
                      {stage.budget.steps} actions, {stage.budget.minutes}m budget.
                      Illustrative, not a measured run.
                    </span>
                  </div>
            ) : (
              <div className="desk-term-cmd">
                <span className="sa-term-prompt">$ </span>
                <span className="sa-caret" data-blink="true" />
              </div>
            )}
          </div>

          <div className="desk-actions">
            {finished ? (
              <button
                type="button"
                className="sa-btn sa-btn-step"
                onClick={() => dispatch({ type: 'replay' })}
              >
                Replay this Turn
              </button>
            ) : (
              <button
                type="button"
                className="sa-btn sa-btn-step"
                onClick={() => dispatch({ type: 'next' })}
              >
                {state.auto ? 'Take over' : 'Next action'}
              </button>
            )}
            {host.moved || controller.moved ? (
              <button
                type="button"
                className="sa-btn sa-btn-ghost"
                onClick={() => {
                  host.reset();
                  controller.reset();
                }}
              >
                Reset layout
              </button>
            ) : null}
            <StepRail
              total={stage.steps.length}
              current={state.step}
              done={committed}
              labels={stage.steps.map((step) => step.label)}
              onSelect={(step) => dispatch({ type: 'goto', step })}
            />
          </div>
        </section>
      </div>
    </div>
  );
}

/** Direct access to any step of the Turn, and a compact progress read. */
function StepRail({
  total,
  current,
  done,
  labels,
  onSelect,
}: {
  total: number;
  /** The action being performed, which the pointer may still be travelling to. */
  current: number;
  /** The last action whose effects are on screen. */
  done: number;
  labels: string[];
  onSelect: (step: number) => void;
}) {
  return (
    <div className="desk-rail" role="group" aria-label="Turn actions">
      {Array.from({ length: total }, (_, index) => (
        <button
          key={labels[index]}
          type="button"
          className="desk-rail-step"
          data-done={index <= done}
          data-current={index === current}
          aria-current={index === current ? 'step' : undefined}
          onClick={() => onSelect(index)}
        >
          <span className="desk-rail-mark" />
          <span className="sa-sr">{`Action ${index + 1}: ${labels[index]}`}</span>
        </button>
      ))}
      <span className="desk-rail-count sa-mono">
        {Math.max(0, current + 1)}/{total}
      </span>
    </div>
  );
}

/** Window furniture, not controls: inert, hidden from assistive technology. */
function Lights() {
  return (
    <span className="sa-win-lights" aria-hidden="true">
      <i />
      <i />
      <i />
    </span>
  );
}
