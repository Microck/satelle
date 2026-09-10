'use client';

import { useCallback, useState, type ReactNode } from 'react';
import { useReducedMotion } from './motion';
import { useCaptionIds } from './movable';
import { useTypewriter, type Beat } from './typewriter';
import './agent.css';

/**
 * MCP: one agent session that types two things and gets two different answers.
 *
 * The demo exists to show one boundary, so it prints nothing else. The operator
 * asks about a Session and the agent reads it; the operator asks to change it
 * and the agent has no tool that could. Enabling mutations is what makes the
 * second call exist at all.
 *
 * Every machine string is fixed by the crates:
 *
 *   - `tools(enable_mutations)` in crates/satelle-cli/src/mcp/schema.rs always
 *     advertises eight read-only tools and adds seven mutation tools only when
 *     the flag is set. That is why `steer` is absent rather than refused, and
 *     why the counts in the title bar are 8 and 15.
 *   - `status` takes `session_id` (required) and returns `satelle.status.v2`,
 *     whose fields are `StatusReport` in crates/satelle-cli/src/output.rs. Its
 *     `status` is the latest Turn's state, so `stopped` here is a Turn state.
 *   - `steer` requires `session_id` and `prompt`. It shells out to
 *     `satelle steer ... --json`, which for a detached Turn reaches
 *     print_detached_session in crates/satelle-cli/src/main.rs and emits
 *     `satelle.steer.v2` with the freshly seeded Turn's state, `starting`.
 *
 * The Session id is the page's shared example. The `turns` field is an array of
 * Turns; the demo prints its length rather than its contents, and the caption
 * says so.
 */

const HOST_ALIAS = 'win-11-lab';
const SESSION_ID = 'rs_0193f2c1-8a4e-7c33-b0d1-5e9a4c17be02';
/** The prompt docs/how-to/operate-session.mdx steers with. */
const STEER_PROMPT = 'Open settings';
const FLAG = '--enable-mutations';

const ASK_STATUS = `Check on the Satelle session on ${HOST_ALIAS}.`;
const ASK_STEER = 'Now start a follow-up turn on it.';

const STATUS_CALL = `status({"session_id":"${SESSION_ID}"})`;
const STEER_CALL = `steer({"session_id":"${SESSION_ID}","prompt":"${STEER_PROMPT}"})`;

/**
 * Four of the seven fields `satelle.status.v2` carries, in the order the struct
 * serializes them. Written as `key: value` lines because the tool returns JSON
 * and this is a projection of it, not a line the binary prints.
 */
const STATUS_OUT = [
  'schema_version: satelle.status.v2',
  `host: ${HOST_ALIAS}`,
  'status: stopped',
  'turns: 2 entries',
].join('\n');

/** Three of the detached report's fields, same order, same projection. */
const STEER_OUT = [
  'schema_version: satelle.steer.v2',
  'status: starting',
  'turns: 3 entries',
].join('\n');

const REFUSAL =
  `steer is not in my tool list. This server runs without ${FLAG}, so it advertises ` +
  'the eight read-only tools and none of run, steer, stop, setup, repair, host_update, ' +
  'host_lifecycle. There is no call here for the Host to refuse.';

/**
 * Two scripts over the same opening. Human lines are typed; every machine line
 * is `instant`, because the server answers in one write and typing its reply
 * out would misrepresent what happened.
 *
 * Both are module constants: `useTypewriter` watches the array identity, so a
 * fresh array each render would restart the script forever.
 */
const READ_ONLY_SCRIPT: Beat[] = [
  { text: ASK_STATUS, kind: 'ask', hold: 340 },
  { text: STATUS_CALL, kind: 'call', instant: true, hold: 500 },
  { text: STATUS_OUT, kind: 'out', instant: true, hold: 760 },
  { text: ASK_STEER, kind: 'ask', hold: 340 },
  { text: REFUSAL, kind: 'refusal', instant: true },
];

const MUTATIONS_SCRIPT: Beat[] = [
  { text: ASK_STATUS, kind: 'ask', hold: 340 },
  { text: STATUS_CALL, kind: 'call', instant: true, hold: 500 },
  { text: STATUS_OUT, kind: 'out', instant: true, hold: 760 },
  { text: ASK_STEER, kind: 'ask', hold: 340 },
  { text: STEER_CALL, kind: 'call', instant: true, hold: 500 },
  { text: STEER_OUT, kind: 'out', instant: true },
];

type Mode = 'read-only' | 'mutations';

const SCRIPTS: Record<Mode, Beat[]> = {
  'read-only': READ_ONLY_SCRIPT,
  mutations: MUTATIONS_SCRIPT,
};

/** What `tools(enable_mutations)` advertises in each mode. */
const TOOL_COUNT: Record<Mode, number> = { 'read-only': 8, mutations: 15 };

export default function AgentDemo() {
  const reduced = useReducedMotion();
  // useTypewriter decides on its first render whether to animate at all, and
  // useReducedMotion cannot answer until after hydration: it starts false so the
  // server render and the first client render agree. Keying on it remounts once
  // with the right answer, which is what puts the finished script in front of a
  // reduced motion reader instead of an empty window.
  return <Session key={String(reduced)} reduced={reduced} />;
}

function Session({ reduced }: { reduced: boolean }) {
  const { captionId, regionId } = useCaptionIds();
  const [mode, setMode] = useState<Mode>('read-only');
  const { hostRef, typed, running, done, replay, finish } = useTypewriter(
    SCRIPTS[mode],
    reduced,
  );

  // Changing the server's flags reruns the session, so the reader watches the
  // same request answered differently rather than seeing an outcome swap in
  // place. Under reduced motion there is no reveal to watch, so the new script
  // is presented finished.
  const restart = useCallback(
    (next: Mode) => {
      setMode(next);
      if (reduced) finish();
      else replay();
    },
    [reduced, replay, finish],
  );

  // One caret. It trails a human line while that line is being typed, and sits
  // on a waiting prompt the rest of the time. `ask` is the only typed kind, so a
  // pending beat with any other kind is machine output landing.
  const last = typed.at(-1);
  const typing = Boolean(last && !last.done && last.kind === 'ask');
  // A landed block enters once, at the reference's 0.24s block reveal. Omitted
  // under reduced motion so a settled page carries no animation at all.
  const enter = !reduced;

  return (
    <div className="ag" ref={hostRef}>
      <p className="sa-caption sa-sr" id={captionId}>
        One agent session, drawn rather than screenshotted. The script types itself once;
        the primary button restarts the server with the other flag and reruns it, and the
        ghost button replays the current run. Tool names, argument keys and result field
        names are the product&apos;s own. The four lines under a call are fields of the
        JSON result, and <code>turns</code> is shown as its length rather than its
        contents. The Session id is a well-formed example, not a measured run.
      </p>

      {/* Announced once, when the session settles, so the claim does not depend
          on watching it happen. */}
      <p className="sa-sr" role="status" aria-live="polite">
        {!done
          ? ''
          : mode === 'read-only'
            ? 'The server advertises eight read-only tools. steer is not one of them, so the agent had no call to make.'
            : 'The server advertises fifteen tools. steer opened a third Turn, reported starting, owned by the Host.'}
      </p>

      <section
        className="sa-win"
        data-kind="controller"
        id={regionId}
        aria-label="Coding agent session against satelle mcp serve"
        aria-describedby={captionId}
      >
        <div className="sa-win-bar">
          {/* Window furniture: inert, and hidden from assistive technology. */}
          <span className="sa-win-lights" aria-hidden="true">
            <i />
            <i />
            <i />
          </span>
          <span className="sa-win-bar-grip">
            <span className="ag-bar-cmd">satelle mcp serve</span>
          </span>
          {/* The one number the flag changes, which is the whole argument: the
              flag advertises tools, it does not grant the Host anything. */}
          <span className="sa-faint sa-mono ag-bar-count">{TOOL_COUNT[mode]} tools</span>
        </div>

        <div className="sa-win-body sa-term ag-term">
          {typed.map((beat, index) => {
            const tail = typing && index === typed.length - 1 ? <Caret blink={running} /> : null;
            switch (beat.kind) {
              case 'ask':
                return <Ask key={index} text={beat.text} tail={tail} />;
              case 'call':
                return <Call key={index} text={beat.text} enter={enter} />;
              case 'out':
                return <Out key={index} text={beat.text} enter={enter} />;
              case 'refusal':
                return <Refusal key={index} text={beat.text} enter={enter} />;
              default:
                return null;
            }
          })}
          {/* The waiting prompt, which is also the whole window before the
              script starts. */}
          {typing ? null : <Ask text="" tail={<Caret blink={running} />} />}
        </div>
      </section>

      <div className="ag-actions">
        {mode === 'read-only' ? (
          <button
            type="button"
            className="sa-btn sa-btn-step"
            onClick={() => restart('mutations')}
          >
            Restart with mutations
          </button>
        ) : (
          <button
            type="button"
            className="sa-btn sa-btn-step"
            onClick={() => restart('read-only')}
          >
            Restart read-only
          </button>
        )}
        <button
          type="button"
          className="sa-btn sa-btn-ghost"
          onClick={() => (reduced ? finish() : replay())}
        >
          Replay
        </button>
      </div>
    </div>
  );
}

/** Blinks only while the script runs, so a settled page has no live animation. */
function Caret({ blink }: { blink: boolean }) {
  return <span className="sa-caret" data-blink={blink} />;
}

/**
 * A line the operator typed, or the empty prompt waiting for one. The marker is
 * punctuation, so it is hidden rather than read out.
 */
function Ask({ text, tail }: { text: string; tail: ReactNode }) {
  return (
    <p className="ag-ask">
      <span className="ag-mark" aria-hidden="true">
        &gt;
      </span>
      <span className="ag-ask-text">
        {text}
        {tail}
      </span>
    </p>
  );
}

/** A tool call: the tool name carries the weight, the arguments stay plain. */
function Call({ text, enter }: { text: string; enter: boolean }) {
  const cut = text.indexOf('(');
  return (
    <p className={enter ? 'ag-call sa-enter' : 'ag-call'}>
      <b>{text.slice(0, cut)}</b>
      {text.slice(cut)}
    </p>
  );
}

/**
 * The fields the call returned. `status` is a Turn state wherever it appears on
 * this page, so it carries the same dot as everywhere else.
 */
function Out({ text, enter }: { text: string; enter: boolean }) {
  return (
    <div className={enter ? 'ag-out sa-enter' : 'ag-out'}>
      {text.split('\n').map((line) => {
        const split = line.indexOf(': ');
        const key = line.slice(0, split);
        const value = line.slice(split + 2);
        return (
          <div key={key}>
            <b>{key}</b>
            {': '}
            {key === 'status' ? (
              <span className="ag-state">
                <span className="sa-dot" data-state={value} />
                {value}
              </span>
            ) : (
              value
            )}
          </div>
        );
      })}
    </div>
  );
}

/** The agent explaining an absence. The flag is the operative word in it. */
function Refusal({ text, enter }: { text: string; enter: boolean }) {
  const [before, after] = text.split(FLAG);
  return (
    <p className={enter ? 'ag-refusal sa-enter' : 'ag-refusal'}>
      {before}
      <b>{FLAG}</b>
      {after}
    </p>
  );
}
