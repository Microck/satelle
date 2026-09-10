'use client';

import { useCallback, useRef, useState } from 'react';
import { useReducedMotion } from './motion';
import { useCaptionIds } from './movable';
import { useTypewriter, type Beat } from './typewriter';
import './transports.css';

/**
 * Transports: one window, one link, one typed command.
 *
 * The card head already says what the three paths are, so the window does not
 * repeat it. What it shows instead is the thing a reader cannot read off a
 * sentence: what the chosen path actually authenticates.
 *
 * Every string here is the repository's own:
 *
 * - `transport` values `local`, `direct`, `ssh` and the binding keys `address`,
 *   `expected_host_id`, `api_token`, `ca_bundle` are the real ones
 *   (docs/reference/configuration.mdx, docs/how-to/connect-remote.mdx).
 * - `local-demo` is the built-in local Host binding
 *   (docs/tutorial/first-session.mdx).
 * - Direct requires HTTPS or WSS, a pinned Host identity, a file-backed bearer
 *   token, and an explicit CA bundle. All four, not any one of them
 *   (docs/how-to/connect-remote.mdx).
 * - SSH authenticates the tunnel and never replaces Satelle API authentication
 *   or Host identity verification (docs/how-to/connect-remote.mdx). The token
 *   and the identity check still travel inside it, which is why the tunnel is
 *   drawn around them rather than in place of them.
 * - The prompt is the tutorial's own first Turn.
 */

const HOST_ALIAS = 'win-11-lab';

/**
 * Both remote paths run the same command. The binding decides how the
 * Controller reaches the Host; it does not change what the operator types, and
 * that is the point of putting the two behind one command block.
 *
 * Every script is exactly one typed beat, which is what lets a tab switch
 * settle instantly under reduced motion.
 */
const REMOTE_RUN: Beat[] = [{ text: `satelle run --host ${HOST_ALIAS} "Open the browser"` }];
const LOCAL_RUN: Beat[] = [{ text: 'satelle run --host local-demo "Open the browser"' }];

type TransportId = 'local' | 'direct' | 'ssh';

type Transport = {
  /** The literal value of `transport` in a Host binding. */
  id: TransportId;
  /** Label on the link itself: the shape the call takes. */
  wire: string;
  /** The Host end of the link. */
  host: { name: string; note: string };
  /** What the path carries. Three at most, and never a bulleted column. */
  tokens: string[];
  /** True when the tokens are absences rather than material. */
  absent?: boolean;
  /** Set when the link runs inside a wrapper that authenticates separately. */
  tunnel?: string;
  /** True when both ends are the same machine, so nothing crosses a network. */
  oneMachine?: boolean;
  script: Beat[];
  /** Spoken once on selection. Carries the claims the tokens compress. */
  announce: string;
};

const TRANSPORTS: Transport[] = [
  {
    id: 'local',
    wire: 'local call',
    host: { name: 'local-demo', note: 'this machine' },
    tokens: ['no address', 'no api_token', 'no ca_bundle'],
    absent: true,
    oneMachine: true,
    script: LOCAL_RUN,
    announce:
      'Local. The Controller and the Host Daemon are one machine, so the call crosses no network and the binding carries no address, no api_token and no ca_bundle.',
  },
  {
    id: 'direct',
    wire: 'https:// wss://',
    host: { name: HOST_ALIAS, note: 'Windows 11' },
    tokens: ['expected_host_id', 'api_token', 'ca_bundle'],
    script: REMOTE_RUN,
    announce:
      'Direct. The link is HTTPS or WSS, and it carries a pinned expected_host_id, a bearer api_token read from an owner-only file, and an explicit ca_bundle. All four, not any one of them.',
  },
  {
    id: 'ssh',
    wire: 'ssh tunnel',
    host: { name: HOST_ALIAS, note: 'Windows 11' },
    tokens: ['api_token', 'expected_host_id'],
    tunnel: 'ssh tunnel',
    script: REMOTE_RUN,
    announce:
      'SSH. The Satelle link runs inside an SSH tunnel and still carries the api_token and the expected_host_id check inside it. SSH authenticates the tunnel; it replaces neither Satelle API authentication nor Host identity verification.',
  },
];

export default function TransportsDemo() {
  const reduced = useReducedMotion();
  // useTypewriter decides in a state initializer whether to animate at all, and
  // useReducedMotion cannot answer until after hydration: it starts false so the
  // server and first client render agree. Remounting on the answer is what puts
  // the finished command in front of a reduced motion reader.
  return <Picker key={String(reduced)} reduced={reduced} />;
}

function Picker({ reduced }: { reduced: boolean }) {
  const { captionId, regionId } = useCaptionIds();
  const [active, setActive] = useState(0);
  const transport = TRANSPORTS[active];
  const { hostRef, typed, running, replay, finish } = useTypewriter(transport.script, reduced);
  // Roving tabindex needs the nodes so selection can carry focus with it.
  const tabRefs = useRef<Array<HTMLButtonElement | null>>([]);
  const panelId = `${regionId}-panel`;

  /**
   * Switching path retypes that path's command, so the reader watches the
   * command land on the new binding rather than seeing text swap in place.
   * Under reduced motion there is no reveal to watch, so it lands finished.
   */
  const pick = useCallback(
    (next: number) => {
      setActive(next);
      if (reduced) finish();
      else replay();
    },
    [reduced, replay, finish],
  );

  /**
   * Arrow-key navigation with a single tab stop. Selection follows focus, which
   * is right here because the panel costs nothing to show. Both axes move: the
   * strip is a row on a wide card and wraps on a narrow one.
   */
  function onTabKeyDown(event: React.KeyboardEvent<HTMLButtonElement>, index: number) {
    const last = TRANSPORTS.length - 1;
    let next = index;
    if (event.key === 'ArrowRight' || event.key === 'ArrowDown') {
      next = index === last ? 0 : index + 1;
    } else if (event.key === 'ArrowLeft' || event.key === 'ArrowUp') {
      next = index === 0 ? last : index - 1;
    } else if (event.key === 'Home') {
      next = 0;
    } else if (event.key === 'End') {
      next = last;
    } else {
      return;
    }
    event.preventDefault();
    pick(next);
    tabRefs.current[next]?.focus();
  }

  return (
    <div className="tr" ref={hostRef}>
      <p className="sa-caption sa-sr" id={captionId}>
        Three paths from the Controller to the Host. Click a tab or use the arrow keys to
        pick one, and the button retypes its command. The link is drawn rather than
        measured and the aliases are examples, but what each path authenticates is the
        product&rsquo;s own security model.
      </p>

      <p className="sa-sr" role="status" aria-live="polite">
        {transport.announce}
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
            <span className="tr-bar-user">operator@thinkpad</span>
            <span className="sa-faint">Linux</span>
          </span>
          <span className="sa-faint sa-mono tr-bar-key">
            transport = &quot;{transport.id}&quot;
          </span>
        </div>

        <div className="tr-pick">
          <span className="sa-label" id={`${regionId}-pick`}>
            transport
          </span>
          <div className="tr-tabs" role="tablist" aria-labelledby={`${regionId}-pick`}>
            {TRANSPORTS.map((candidate, index) => (
              <button
                key={candidate.id}
                type="button"
                role="tab"
                id={`${regionId}-tab-${candidate.id}`}
                className="tr-tab"
                ref={(node) => {
                  tabRefs.current[index] = node;
                }}
                aria-selected={index === active}
                aria-controls={panelId}
                tabIndex={index === active ? 0 : -1}
                onClick={() => pick(index)}
                onKeyDown={(event) => onTabKeyDown(event, index)}
              >
                {candidate.id}
              </button>
            ))}
          </div>
        </div>

        {/* One panel, relabelled by whichever tab is selected. Three panels
            would be three copies of one link and one command block. */}
        <div
          role="tabpanel"
          id={panelId}
          className="tr-panel"
          aria-labelledby={`${regionId}-tab-${transport.id}`}
          // Holds no focusable content, so the panel is the reading stop.
          tabIndex={0}
        >
          <div className="tr-path" data-one-machine={Boolean(transport.oneMachine)}>
            {transport.oneMachine ? (
              // Local removes the network, not the boundary: the Host Daemon
              // still admits the work and still owns durable state.
              <span className="tr-path-tag sa-label">one machine</span>
            ) : null}
            <div className="tr-row">
              <span className="tr-end">
                <b>Controller</b>
                <span className="tr-end-note">operator@thinkpad</span>
              </span>
              <span className="tr-wire">
                <span className="tr-wire-name sa-mono">{transport.wire}</span>
                <span className="tr-rule" />
              </span>
              <span className="tr-end" data-role="host">
                <b className="sa-mono">{transport.host.name}</b>
                <span className="tr-end-note">{transport.host.note}</span>
              </span>
            </div>
          </div>

          {/* The tunnel is drawn around the tokens, not in place of them: that
              is the one thing about this path a reader gets wrong. */}
          <div className="tr-carry" data-tunnel={Boolean(transport.tunnel)}>
            <span className="sa-label">
              {transport.tunnel ? `carries inside the ${transport.tunnel}` : 'carries'}
            </span>
            <ul className="tr-tokens" data-absent={Boolean(transport.absent)}>
              {transport.tokens.map((token) => (
                <li key={token}>
                  <code>{token}</code>
                </li>
              ))}
            </ul>
          </div>

          <div className="tr-cmd sa-term">
            <span className="sa-term-prompt">$ </span>
            {typed[0]?.text ?? ''}
            {/* Blinks only while the command is being typed, so a settled page
                carries no live animation. */}
            <span className="sa-caret" data-blink={running} />
          </div>
        </div>

        <div className="tr-actions">
          <button
            type="button"
            className="sa-btn sa-btn-ghost"
            onClick={() => (reduced ? finish() : replay())}
          >
            Retype the command
          </button>
        </div>
      </section>
    </div>
  );
}
