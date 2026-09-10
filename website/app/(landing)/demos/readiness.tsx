'use client';

import { useCallback, useState, type ReactNode } from 'react';
import { useReducedMotion } from './motion';
import { useCaptionIds } from './movable';
import { useTypewriter, type Beat } from './typewriter';
import './readiness.css';

/**
 * Readiness: one terminal that runs the probe and prints the report.
 *
 * The command is the one README.md prints, with this page's Host alias in
 * place of its own. Everything the terminal prints comes from two places in
 * the product:
 *
 *   - the doctor branch of crates/satelle-cli/src/main.rs prints `Host:`,
 *     `Status:`, `Ready:`, `Scopes:`, then print_doctor_findings prints
 *     `[<severity>] <summary> (<fixability>)` and one indented
 *     `  evidence: <text>` line per evidence entry.
 *   - project_native_refresh in crates/satelle-host/src/lib.rs builds the one
 *     finding the `computer-use` scope can carry, and its evidence. It retains
 *     no other finding in that scope, which is why one run prints one finding.
 *
 * `Status:` is `ready` or `blocked`, never `not_ready`: recompute_doctor_summary
 * sets `if ready { "ready" } else { "blocked" }`.
 *
 * The blocked summary is the message on native_readiness_manual_action_failure,
 * which is raised exactly when the os_permissions or app_approval observation
 * comes back denied. Those are the os-permission-required and
 * app-approval-required blockers in crates/satelle-core/src/doctor.rs.
 */

const HOST_ALIAS = 'win-11-lab';
const COMMAND = `satelle doctor --host ${HOST_ALIAS} --scope computer-use --refresh`;

/** RFC 3339, five minutes apart because DEFAULT_NATIVE_READINESS_TTL is 5m. */
const OBSERVED_AT = '2026-09-08T18:29:44Z';
const EXPIRES_AT = '2026-09-08T18:34:44Z';

type Ending = 'blocked' | 'ready';

/**
 * A run has two endings and one shape: the person types the command, then the
 * binary answers. The report and the finding are `instant` because that is how
 * they arrive; typing machine output out would misrepresent what happened.
 *
 * Both scripts are module constants. `useTypewriter` watches the array
 * identity, so a fresh array on every render would restart the timer forever.
 */
const BLOCKED_SCRIPT: Beat[] = [
  { text: COMMAND, kind: 'cmd', hold: 380 },
  {
    text: `Host: ${HOST_ALIAS}\nStatus: blocked\nReady: false\nScopes: computer-use`,
    kind: 'report',
    instant: true,
    hold: 600,
  },
  {
    text: [
      '[error] native Computer Use requires a manual permission or app approval change (manual_action_required)',
      '  evidence: code=computer-use-not-ready',
      '  evidence: reason=native_readiness_manual_action_required',
      '  evidence: status=manual_action_required',
    ].join('\n'),
    kind: 'finding',
    instant: true,
    hold: 420,
  },
  {
    text: `A person clears this on ${HOST_ALIAS}. Satelle observes the permission; it never grants it.`,
    kind: 'note',
    instant: true,
  },
];

const READY_SCRIPT: Beat[] = [
  { text: COMMAND, kind: 'cmd', hold: 380 },
  {
    text: `Host: ${HOST_ALIAS}\nStatus: ready\nReady: true\nScopes: computer-use`,
    kind: 'report',
    instant: true,
    hold: 600,
  },
  {
    text: [
      '[info] native Computer Use readiness passed (informational)',
      '  evidence: source=live',
      `  evidence: observed_at=${OBSERVED_AT}`,
      `  evidence: expires_at=${EXPIRES_AT}`,
    ].join('\n'),
    kind: 'finding',
    instant: true,
    hold: 420,
  },
  {
    text: 'source=live: this run observed the verdict rather than reading one back from the cache.',
    kind: 'note',
    instant: true,
  },
];

const SCRIPTS: Record<Ending, Beat[]> = { blocked: BLOCKED_SCRIPT, ready: READY_SCRIPT };

/**
 * The two verdict values worth colouring. `--sa-warn` carries the whole
 * not-ready state, `[error]` tag included: `blocked` is a warn state in this
 * design system, and keeping `--sa-fail` out of a component that carries the
 * accent in its focus rings is a rule of that system.
 */
const TONE: Record<string, string> = {
  blocked: 'sa-term-warn',
  false: 'sa-term-warn',
  ready: 'sa-term-ok',
  true: 'sa-term-ok',
};

export default function ReadinessDemo() {
  const reduced = useReducedMotion();
  // useTypewriter decides on the first render whether to animate at all, and
  // useReducedMotion cannot know the answer until after mount: it starts false
  // so the server render and the first client render agree. Keying the run on
  // it remounts once with the right answer, which is what gets a reduced
  // motion reader the finished script instead of an empty window.
  return <Run key={String(reduced)} reduced={reduced} />;
}

function Run({ reduced }: { reduced: boolean }) {
  const { captionId, regionId } = useCaptionIds();
  const [ending, setEnding] = useState<Ending>('blocked');
  const { hostRef, typed, running, done, replay, finish } = useTypewriter(
    SCRIPTS[ending],
    reduced,
  );

  // Switching endings reruns the script, so the reader watches the same command
  // answer differently rather than seeing a verdict swap in place. Under
  // reduced motion there is no reveal to watch, so the new script is presented
  // finished instead.
  const run = useCallback(
    (next: Ending) => {
      setEnding(next);
      if (reduced) finish();
      else replay();
    },
    [reduced, replay, finish],
  );

  const cmd = typed[0]?.text ?? '';
  const output = typed.slice(1).filter((beat) => beat.kind !== 'note');
  const note = typed.find((beat) => beat.kind === 'note');
  // One caret, at the end of whatever has printed so far. It blinks only while
  // the script runs, so a settled page carries no live animation.
  const caret = <span className="sa-caret" data-blink={running} />;
  // A printed block fades in as it lands, which is the reference's own 0.12s
  // line reveal. It runs on mount, once, and never again.
  const landed = reduced ? 'rd-line' : 'rd-line sa-in';

  return (
    <div className="rd" ref={hostRef}>
      <p className="sa-caption sa-sr" id={captionId}>
        Two buttons drive this demo: one reruns the probe after the Operator grants access
        on {HOST_ALIAS}, the other replays the current run. The terminal prints what{' '}
        <code>satelle doctor</code> prints. The line below it is this page speaking, not
        program output. The alias and the timestamps are examples, not a measured run.
      </p>

      <p className="sa-sr" role="status" aria-live="polite">
        {done
          ? ending === 'blocked'
            ? `Probe finished. ${HOST_ALIAS} is blocked: a manual permission or app approval change is required.`
            : `Probe finished. ${HOST_ALIAS} is ready, observed by this run.`
          : 'Probe running.'}
      </p>

      <section
        className="sa-win"
        data-kind="controller"
        id={regionId}
        aria-label="Controller terminal on Linux"
        aria-describedby={captionId}
      >
        <div className="sa-win-bar">
          {/* Window furniture, not controls: inert and hidden from assistive
              technology. */}
          <span className="sa-win-lights" aria-hidden="true">
            <i />
            <i />
            <i />
          </span>
          <span className="sa-win-bar-grip">
            <span className="rd-bar-user">operator@thinkpad</span>
          </span>
          <span className="sa-faint sa-mono rd-bar-ver">satelle 0.1.10</span>
        </div>

        <div className="sa-win-body sa-term rd-term">
          <p className="rd-line rd-cmd">
            <span className="sa-term-prompt">$ </span>
            {cmd}
            {output.length === 0 ? caret : null}
          </p>

          {output.map((beat, index) => {
            const last = index === output.length - 1;
            return (
              <p key={beat.kind} className={landed}>
                {beat.kind === 'finding' ? (
                  <Finding text={beat.text} tail={last ? caret : null} />
                ) : (
                  <Report text={beat.text} tail={last ? caret : null} />
                )}
              </p>
            );
          })}
        </div>

        {/* Always in the layout, empty until the run ends, so the card does not
            step down the page when the note lands. */}
        <p className={reduced || !note ? 'rd-note' : 'rd-note sa-enter'}>{note?.text ?? ''}</p>

        <div className="rd-actions">
          {ending === 'blocked' ? (
            <button type="button" className="sa-btn sa-btn-step" onClick={() => run('ready')}>
              Operator grants access, re-probe
            </button>
          ) : (
            <button type="button" className="sa-btn sa-btn-step" onClick={() => run('blocked')}>
              Re-probe the blocked Host
            </button>
          )}
          <button
            type="button"
            className="sa-btn sa-btn-ghost"
            onClick={() => (reduced ? finish() : replay())}
          >
            Replay this run
          </button>
        </div>
      </section>
    </div>
  );
}

/**
 * `Host:` / `Status:` / `Ready:` / `Scopes:`, with the verdict value coloured.
 * `tail` is the caret, which belongs at the end of the last printed line the
 * way a terminal cursor does, not on a line of its own below the block.
 */
function Report({ text, tail }: { text: string; tail: ReactNode }) {
  const rows = text.split('\n');
  return (
    <>
      {rows.map((row, index) => {
        const split = row.indexOf(': ');
        const value = row.slice(split + 2);
        return (
          <span key={row} className="rd-row">
            <b>{row.slice(0, split + 1)}</b> <span className={TONE[value]}>{value}</span>
            {index === rows.length - 1 ? tail : null}
          </span>
        );
      })}
    </>
  );
}

/**
 * `[<severity>] <summary> (<fixability>)` and its evidence lines. The head is
 * split on its own brackets so the severity tag and the fixability carry their
 * own colour and the summary stays plain.
 */
function Finding({ text, tail }: { text: string; tail: ReactNode }) {
  const [head, ...evidence] = text.split('\n');
  const tagEnd = head.indexOf(']') + 1;
  const fixStart = head.lastIndexOf(' (');
  const tag = head.slice(0, tagEnd);
  return (
    <>
      <span className="rd-row">
        <span className={tag === '[error]' ? 'sa-term-warn' : 'sa-term-dim'}>{tag}</span>{' '}
        {head.slice(tagEnd + 1, fixStart)}{' '}
        <span className="sa-term-dim">{head.slice(fixStart + 1)}</span>
      </span>
      <span className="rd-row sa-term-dim">
        {evidence.join('\n')}
        {tail}
      </span>
    </>
  );
}
