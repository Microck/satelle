'use client';

import type { Stage, StageProps } from '../stage';
import './godot.css';

/**
 * NeonCollector, drawn as a script editor beside the game window. Everything
 * quoted here comes from the showcase task's own assets: the starter main.gd
 * with its two TODO stubs, the fixed main.gd that replaces them, the HUD format
 * `"COINS: %d/%d" % [score, TOTAL_COINS]`, the SECTOR CLEARED panel with its
 * PLAY AGAIN button, and the issue's acceptance criteria.
 *
 * Nothing in the game window is a live control. The player square moves by
 * committing a new position per step, never along an animated path.
 */

/** One node in the "coins" group. Five of them, as TOTAL_COINS says. */
type Coin = { name: string; x: number; y: number };

/* Play area coordinates in the SVG's own user units, viewBox 160 x 100. This is
   a drawn level, not a capture of one. */
const COINS: Coin[] = [
  { name: 'Coin1', x: 32, y: 66 },
  { name: 'Coin2', x: 58, y: 30 },
  { name: 'Coin3', x: 90, y: 68 },
  { name: 'Coin4', x: 115, y: 30 },
  { name: 'Coin5', x: 141, y: 66 },
];

/** Where the player spawns, and where a reloaded scene puts it back. */
const SPAWN = { x: 16, y: 82 };
const PLAYER_SIDE = 14;

/** Two low walls, leaving a middle corridor so the coin route reads as a level. */
const WALLS = [
  { x: 22, y: 46, w: 30, h: 8 },
  { x: 96, y: 46, w: 44, h: 8 },
];

/** The coin the starter's player walks through without collecting. */
const MISSED_COIN = 'Coin3';

type CodeLine = { text: string; kind?: 'add' | 'todo' };

/**
 * The visible excerpt of main.gd: the three functions the Turn touches, from
 * `func _ready` on line 11 down, so the panel stays readable instead of
 * scrolling a whole file. The gates are monotone, so `gated` never arrives
 * before the collect_coin body it extends.
 */
function codeLines(gates: {
  wired: boolean;
  collects: boolean;
  gated: boolean;
  restarts: boolean;
}): CodeLine[] {
  const lines: CodeLine[] = [
    { text: 'func _ready() -> void:' },
    { text: '    score_label.text = "COINS: 0/%d" % TOTAL_COINS' },
    { text: '    win_panel.visible = false' },
    { text: '' },
  ];

  if (gates.wired) {
    lines.push(
      { text: '    for coin in get_tree().get_nodes_in_group("coins"):', kind: 'add' },
      { text: '        coin.body_entered.connect(_on_coin_body_entered.bind(coin))', kind: 'add' },
    );
  } else {
    lines.push(
      {
        text: '    # TODO: Connect every node in the "coins" group so touching it calls',
        kind: 'todo',
      },
      {
        text: '    # collect_coin(coin). The starter intentionally leaves this broken.',
        kind: 'todo',
      },
    );
  }

  lines.push({ text: '' }, { text: 'func collect_coin(coin: Area2D) -> void:' });

  if (gates.collects) {
    lines.push(
      {
        text: '    if not is_instance_valid(coin) or coin.is_queued_for_deletion():',
        kind: 'add',
      },
      { text: '        return', kind: 'add' },
      { text: '', kind: 'add' },
      { text: '    coin.queue_free()', kind: 'add' },
      { text: '    score += 1', kind: 'add' },
      { text: '    score_label.text = "COINS: %d/%d" % [score, TOTAL_COINS]', kind: 'add' },
    );
  } else {
    lines.push(
      {
        text: '    # TODO: Remove the collected coin, increment score, refresh ScoreLabel,',
        kind: 'todo',
      },
      { text: '    # and reveal WinPanel after all five coins are collected.', kind: 'todo' },
      { text: '    pass', kind: 'todo' },
    );
  }

  if (gates.gated) {
    lines.push(
      { text: '', kind: 'add' },
      { text: '    if score >= TOTAL_COINS:', kind: 'add' },
      { text: '        player.set_physics_process(false)', kind: 'add' },
      { text: '        win_panel.visible = true', kind: 'add' },
    );
  }

  lines.push({ text: '' }, { text: 'func reset_game() -> void:' });

  if (gates.restarts) {
    lines.push({ text: '    get_tree().reload_current_scene()', kind: 'add' });
  } else {
    lines.push(
      { text: '    # TODO: Reload the current scene so the player can play again.', kind: 'todo' },
      { text: '    pass', kind: 'todo' },
    );
  }

  return lines;
}

function Project({ step, reduced }: StageProps) {
  // Step gates. Each one is the state *after* that action commits, so the whole
  // interior stays a pure function of one number.
  const ranStarter = step >= 1;
  const wired = step >= 2;
  const collects = step >= 3;
  const gated = step >= 4;
  const restarts = step >= 5;
  const saved = step >= 6;
  const cleared = step >= 8;
  const reloaded = step >= 9;

  // Coins clear as the verification run advances: one at step 6, three at step
  // 7, all five at step 8. PLAY AGAIN then puts five coins back.
  const collected = reloaded ? 0 : cleared ? 5 : step >= 7 ? 3 : saved ? 1 : 0;
  const showWinPanel = cleared && !reloaded;

  // The player sits on whichever coin it last touched, and starts, or restarts,
  // at the spawn point. Positions commit per step.
  const player =
    !ranStarter || reloaded
      ? SPAWN
      : collected === 5
        ? COINS[4]
        : collected === 3
          ? COINS[2]
          : collected === 1
            ? COINS[0]
            : COINS[2];

  // The starter run is up until the first edit; the repaired run is up from the
  // save onward. In between the scene is stopped so main.gd can be edited.
  const playing = (ranStarter && !wired) || saved;
  const fileState = saved ? 'saved' : wired ? 'modified' : 'unchanged';
  const lines = codeLines({ wired, collects, gated, restarts });

  return (
    <div className="gd" data-reduced={reduced}>
      {/* desk.tsx carries the visible caption for the whole demo. This one is
          the stage's own statement, so a screen reader hears which parts of
          this interior are drawn before it reaches them. */}
      <p className="sa-caption sa-sr">
        A drawn script editor and game window, built from this page&apos;s own tokens.
        Both are illustrative: nothing here runs the project, so the PLAY AGAIN button in
        the SECTOR CLEARED panel is disabled. Advance the Turn from the Controller window
        to change what they show.
      </p>

      <div className="gd-pane gd-script">
        <div className="gd-pane-head">
          <span className="gd-tabs" role="presentation">
            <span className="gd-tab">main.tscn</span>
            <span className="gd-tab" data-active="true">
              main.gd
            </span>
          </span>
          <span className="sa-faint sa-mono">lines 11-{10 + lines.length}</span>
          <span className="gd-saved" data-state={fileState}>
            {fileState}
          </span>
        </div>

        <div className="sa-scroll gd-codewrap">
          {/* Lines repeat inside one excerpt (blank lines, `pass`), so the key
              carries the index as well as the text. */}
          <pre className="gd-code">
            <code>
              {lines.map((line, index) => (
                <span
                  key={`${index}-${line.text}`}
                  className="gd-line"
                  data-kind={line.kind}
                >
                  {line.text}
                </span>
              ))}
            </code>
          </pre>
        </div>
      </div>

      <div className="gd-pane gd-view">
        <div className="gd-pane-head">
          <span className="sa-label">Game window</span>
          <span className="gd-legend">
            <span className="gd-key">
              <span className="gd-swatch" data-kind="coin" aria-hidden="true" />
              coin
            </span>
            <span className="gd-key">
              <span className="gd-swatch" data-kind="player" aria-hidden="true" />
              player
            </span>
          </span>
        </div>

        {/* HUD/TopBar/ScoreLabel, in the format main.gd writes into it. */}
        <div className="gd-hud">
          <span className="sa-mono">COINS: {collected}/5</span>
        </div>

        <div className="gd-playwrap">
          <svg
            className="gd-play"
            viewBox="0 0 160 100"
            role="img"
            aria-label={`Play area diagram: ${5 - collected} of five coins left, HUD reads COINS: ${collected} of 5${
              showWinPanel ? ', SECTOR CLEARED panel over the play area' : ''
            }`}
          >
            {WALLS.map((wall) => (
              <rect
                key={`${wall.x}-${wall.y}`}
                className="gd-wall"
                x={wall.x}
                y={wall.y}
                width={wall.w}
                height={wall.h}
                rx="1.5"
              />
            ))}

            {COINS.slice(collected).map((coin) => (
              <circle
                key={coin.name}
                className="gd-coin"
                cx={coin.x}
                cy={coin.y}
                r="4"
                data-missed={ranStarter && !saved && coin.name === MISSED_COIN}
              />
            ))}

            {/* The position is the SVG presentation attribute rather than a
                style: it is the computed transform either way, so the CSS
                transition still runs, and a browser that will not animate it
                still puts the square in the right place. */}
            <rect
              className="gd-player"
              x={-PLAYER_SIDE / 2}
              y={-PLAYER_SIDE / 2}
              width={PLAYER_SIDE}
              height={PLAYER_SIDE}
              rx="2"
              data-frozen={showWinPanel}
              transform={`translate(${player.x} ${player.y})`}
            />
          </svg>

          {showWinPanel ? (
            <div className="gd-win">
              <span className="gd-win-title">SECTOR CLEARED</span>
              {/* Disabled on purpose: a live button here would imply this page
                  runs the project. The Host runs it, not the page. */}
              <button type="button" className="gd-win-btn" disabled>
                PLAY AGAIN
              </button>
              <span className="sa-sr">
                Drawn panel. This button is illustrative and does nothing.
              </span>
            </div>
          ) : null}
        </div>

        {reloaded ? (
          /* The issue's acceptance criteria, once the whole flow has run. */
          <ul className="gd-checks">
            <li>five coins at start</li>
            <li>each coin removed once</li>
            <li>COINS: 0/5 to COINS: 5/5</li>
            <li>SECTOR CLEARED after the fifth</li>
            <li>PLAY AGAIN reloads main.tscn</li>
            <li>WASD and arrow keys still move</li>
          </ul>
        ) : (
          <StatusLine step={step} playing={playing} />
        )}
      </div>
    </div>
  );
}

/**
 * The editor's status line under the play area, which is also where the scene's
 * run state is reported. Always present so the pane height holds still between
 * steps. The thresholds mirror the step gates in Project, which are the order
 * of the Turn script.
 */
function StatusLine({ step, playing }: { step: number; playing: boolean }) {
  const icon = playing ? <PlayIcon /> : <StopIcon />;
  if (step >= 8) {
    return (
      <p className="gd-status" data-tone="ok">
        {icon}win gate stopped player physics and revealed WinPanel
      </p>
    );
  }
  if (step >= 6) {
    return <p className="gd-status">{icon}WASD and arrow keys still move the player</p>;
  }
  if (step >= 2) {
    return <p className="gd-status">{icon}scene stopped while main.gd is edited</p>;
  }
  if (step >= 1) {
    return (
      <p className="gd-status" data-tone="warn">
        {icon}contact ignored, no node in the coins group was connected
      </p>
    );
  }
  return <p className="gd-status">{icon}scene not running, five coins placed</p>;
}

function PlayIcon() {
  return (
    <svg
      width="1em"
      height="1em"
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth="1.5"
      strokeLinejoin="round"
      aria-hidden="true"
      focusable="false"
    >
      <path d="M8 5.5 18.5 12 8 18.5Z" />
    </svg>
  );
}

function StopIcon() {
  return (
    <svg
      width="1em"
      height="1em"
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth="1.5"
      aria-hidden="true"
      focusable="false"
    >
      <rect x="6.75" y="6.75" width="10.5" height="10.5" rx="1.5" />
    </svg>
  );
}

export const godotStage: Stage = {
  id: 'godot',
  pick: 'Finish the coin loop and win state',
  app: 'Godot',
  file: 'NeonCollector',
  prompt:
    'Open the NeonCollector Godot project and run it. Fix the unfinished coin-collection workflow in main.gd: touching each of the five coins must remove it, increment the HUD to COINS: n/5, and reveal the existing SECTOR CLEARED panel after all five are collected. The PLAY AGAIN button must reload the scene. Preserve the existing visual design and player controls. Save the working project in place and run it once to verify the complete flow.',
  budget: { minutes: 20, steps: 160 },
  steps: [
    {
      event: 'turn_started',
      label: 'Turn admitted',
      message: 'Turn admitted on host win-11-lab, desktop session console',
    },
    {
      event: 'turn_progress',
      label: 'Run the starter',
      message: 'ran main.tscn, the player crossed a coin and COINS stayed 0/5',
    },
    {
      event: 'turn_progress',
      label: 'Wire coins group',
      message: 'connected body_entered for every node in the coins group to collect_coin',
    },
    {
      event: 'turn_progress',
      label: 'Remove and score',
      message: 'filled collect_coin: queue_free the coin, score += 1, rewrite ScoreLabel',
    },
    {
      event: 'turn_progress',
      label: 'Gate the win panel',
      message: 'added the score >= TOTAL_COINS gate that stops player physics and shows WinPanel',
    },
    {
      event: 'turn_progress',
      label: 'Wire play again',
      message: 'filled reset_game with get_tree().reload_current_scene()',
    },
    {
      event: 'turn_progress',
      label: 'Save and re-run',
      message: 'saved main.gd in place, ran main.tscn, first coin cleared at COINS: 1/5',
    },
    {
      event: 'turn_progress',
      label: 'Clear three coins',
      message: 'second and third coins cleared, HUD read COINS: 3/5',
    },
    {
      event: 'turn_progress',
      label: 'Reveal the panel',
      message: 'fourth and fifth coins cleared at COINS: 5/5, SECTOR CLEARED became visible',
    },
    {
      event: 'turn_completed',
      label: 'Verify play again',
      message: 'PLAY AGAIN reloaded main.tscn, WASD and arrow movement unchanged',
    },
  ],
  Render: Project,
};
