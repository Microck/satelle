'use client';

import type { ReactNode } from 'react';
import { useReducedMotion } from './motion';
import { useCaptionIds } from './movable';
import { useTypewriter, type Beat } from './typewriter';
import './durability.css';

/**
 * Durability: the Session outlives the Controller process that started it.
 *
 * Two terminals on the same Linux machine, one line typed in each. Everything
 * else is empty space, because the argument needs nothing else: one process
 * admits a detached Turn and dies, a second process asks the Host about the
 * same Session id and gets a live answer.
 *
 * Three facts from the crates fix every string below.
 *
 * 1. `run --detach` reaches print_detached_session, whose human branch prints
 *    exactly two lines, `Session:` and `Status:`. `satelle status` reaches
 *    print_session_human, which prints six. They are different commands, so
 *    they print different blocks, and the demo does not pretend otherwise.
 * 2. A detached command returns at admission: `Session::start` seeds the
 *    Session with `Turn::starting`, so `--detach` prints `Status: starting`.
 *    The later `status` reports `running`. That difference is the point. The
 *    Session moved on after the process that launched it was gone.
 * 3. `--host` is optional on `status` (docs/reference/generated-cli.mdx), so
 *    the second command is the short form the tutorial uses. The Host alias
 *    still prints, because print_session_human takes the selected Host.
 */

const HOST_ALIAS = 'win-11-lab';
const SESSION_ID = 'rs_0193f2c1-8a4e-7c33-b0d1-5e9a4c17be02';
/** The Turn `run --detach` admitted. Shared with the other demos on the page. */
const TURN_ID = 'rt_0193f2c1-8a52-7f10-9c44-2b7e8d31af65';
/** Verbatim from docs/how-to/operate-session.mdx. */
const PROMPT = 'Prepare the workspace';

/**
 * The script. Human input is typed; machine output is `instant`, because the
 * Host answers in one write and typing it out would be a lie about what
 * happened. Each beat carries the tag that decides where it lands on screen.
 */
const BEATS: Beat[] = [
  { text: `satelle run --host ${HOST_ALIAS} --detach "${PROMPT}"`, kind: 'run' },
  {
    text: `Session: ${SESSION_ID}\nStatus: starting`,
    instant: true,
    // Long enough to read the two lines before the window goes quiet.
    hold: 700,
    kind: 'run-out',
  },
  { text: '', instant: true, hold: 420, kind: 'exit' },
  { text: `satelle status ${SESSION_ID}`, kind: 'status' },
  {
    text: [
      `Session: ${SESSION_ID}`,
      `Host: ${HOST_ALIAS}`,
      'Status: running',
      'Turns: 1',
      `Latest turn: ${TURN_ID}`,
      'Latest status: running',
    ].join('\n'),
    instant: true,
    kind: 'status-out',
  },
];

export default function DurabilityDemo() {
  const reduced = useReducedMotion();
  // useTypewriter decides whether to run at all in a state initializer, and
  // useReducedMotion cannot answer until after hydration, so the answer has to
  // arrive as a fresh mount. Keying on it is what puts the finished transcript
  // in front of a reduced motion reader instead of an empty window.
  return <Transcript key={String(reduced)} reduced={reduced} />;
}

function Transcript({ reduced }: { reduced: boolean }) {
  const { hostRef, typed, running, replay } = useTypewriter(BEATS, reduced);
  const { captionId, regionId } = useCaptionIds();

  // Every beat has exactly one place on screen, so the script is the only state
  // machine here. `typed` may end in a partial beat, which is the one being
  // typed right now.
  const shown = new Map(typed.map((beat) => [beat.kind, beat.text]));
  const last = typed.at(-1);
  const runCmd = shown.get('run') ?? '';
  const runOut = shown.get('run-out');
  const exited = shown.has('exit');
  const statusCmd = shown.get('status');
  const statusOut = shown.get('status-out');

  // One caret, in whichever window the operator is typing in. It trails the
  // text while a command is being typed and moves to a returned prompt once the
  // shell has answered. `run` and `status` are the only typed beats, so a
  // pending beat with either tag is a command still mid-flight.
  const typing = last && !last.done ? last.kind : null;
  const caret = exited
    ? typing === 'status'
      ? 'status-cmd'
      : 'status-prompt'
    : typing === 'run' || !runOut
      ? 'run-cmd'
      : 'run-prompt';

  return (
    <div className="du" ref={hostRef}>
      <p className="sa-caption sa-sr" id={captionId}>
        Two terminals on the same Linux machine, drawn rather than screenshotted.
        The script types itself once and the button replays it; the window
        furniture is illustrative and does nothing. Every printed line is what the
        command above it prints. The identifiers are well-formed examples, not a
        measured run.
      </p>

      {/* Announced once, when the script settles, so the claim does not depend
          on watching it happen. */}
      <p className="sa-sr" aria-live="polite">
        {statusOut && !running
          ? `The first Controller has exited. A second Controller reports Status running, Turns 1, on Session ${SESSION_ID}.`
          : ''}
      </p>

      <div className="du-stack" id={regionId} aria-describedby={captionId}>
        {/* The process that admitted the Turn, and then died. */}
        <Win
          tty="pts/2"
          focused={!exited}
          quiet={exited}
          lines={4}
          label="First Controller terminal, operator@thinkpad"
        >
          <Cmd
            text={runCmd}
            verb="satelle run"
            caret={caret === 'run-cmd'}
            blink={running}
          />
          {runOut ? <Out text={runOut} /> : null}
          {/* The shell's own note, not Satelle output: brackets and dim ink say
              so. Satelle stopped nothing, paused nothing and deleted nothing. */}
          {exited ? <div className="sa-in sa-term-dim">[process exited]</div> : null}
          {caret === 'run-prompt' ? <Prompt blink={running} /> : null}
        </Win>

        {/* A second process on the same machine. Nothing was handed to it:
            everything it knows, it asked the Host for. */}
        <Win
          tty="pts/5"
          focused={exited}
          quiet={false}
          lines={8}
          label="Second Controller terminal, operator@thinkpad"
        >
          {statusCmd === undefined ? null : (
            <Cmd
              text={statusCmd}
              verb="satelle status"
              caret={caret === 'status-cmd'}
              blink={running}
            />
          )}
          {statusOut ? <Out text={statusOut} /> : null}
          {caret === 'status-prompt' ? <Prompt blink={running} /> : null}
        </Win>
      </div>

      <div className="du-actions">
        <button type="button" className="sa-btn sa-btn-ghost" onClick={replay}>
          Replay
        </button>
      </div>
    </div>
  );
}

/**
 * A Controller window. `lines` reserves the height the script ends at, so the
 * card does not reflow while it types; a quiet window is a process that is
 * gone, keeping its frame and its scrollback, because a window that vanished
 * would prove nothing.
 */
function Win({
  tty,
  focused,
  quiet,
  lines,
  label,
  children,
}: {
  tty: string;
  focused: boolean;
  quiet: boolean;
  lines: 4 | 8;
  label: string;
  children: ReactNode;
}) {
  return (
    <section
      className="sa-win du-win"
      data-kind="controller"
      data-focused={focused}
      data-quiet={quiet}
      aria-label={label}
    >
      <div className="sa-win-bar">
        {/* Window furniture. Inert by design, so it is hidden from the tree. */}
        <span className="sa-win-lights" aria-hidden="true">
          <i />
          <i />
          <i />
        </span>
        <span className="sa-win-bar-grip">
          <span className="du-alias">operator@thinkpad</span>
        </span>
        <span className="sa-state du-end">
          {quiet ? <span className="sa-dot" data-state="stopped" /> : null}
          {tty}
        </span>
      </div>
      <div className="sa-win-body sa-term du-term" data-lines={lines}>
        {children}
      </div>
    </section>
  );
}

/**
 * A typed command line. `$ ` is punctuation rather than emphasis, and the
 * binary and subcommand carry the weight, but only once they have actually been
 * typed: slicing the live text keeps the bold from running ahead of the caret.
 */
function Cmd({
  text,
  verb,
  caret,
  blink,
}: {
  text: string;
  verb: string;
  caret: boolean;
  blink: boolean;
}) {
  return (
    <div className="du-cmd">
      <span className="sa-term-prompt">$ </span>
      <b>{text.slice(0, verb.length)}</b>
      {text.slice(verb.length)}
      {caret ? <span className="sa-caret" data-blink={blink} /> : null}
    </div>
  );
}

/**
 * A block of printed output, split at the label the CLI writes before each
 * value. It fades in whole, at the 0.24s block enter, because that is how it
 * arrives.
 */
function Out({ text }: { text: string }) {
  return (
    <div className="sa-enter">
      {text.split('\n').map((line) => {
        const mark = line.indexOf(': ');
        const value = line.slice(mark + 2);
        return (
          <div key={line}>
            <b>{line.slice(0, mark + 1)}</b>{' '}
            {/* The Session id is tinted wherever Satelle prints it as a value,
                in both windows, so the reader can see it is the same one. The
                copy the operator typed stays plain: the mark means "this is the
                identity the machine asserted". */}
            {value === SESSION_ID ? <span className="du-id">{value}</span> : value}
          </div>
        );
      })}
    </div>
  );
}

/** The prompt the shell returns to once a command has answered. */
function Prompt({ blink }: { blink: boolean }) {
  return (
    <div className="du-cmd">
      <span className="sa-term-prompt">$ </span>
      <span className="sa-caret" data-blink={blink} />
    </div>
  );
}
