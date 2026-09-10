'use client';

import { Retype, TYPEIN_MS } from '../typewriter';
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

type CodeLine = {
  text: string;
  kind?: 'add' | 'todo';
  /**
   * The Turn step that writes this line. Only `add` lines have one, and it is
   * what orders the typing: every line of a block mounts on the same frame, so
   * without it the whole block grows rightward at once.
   */
  step?: number;
  /**
   * The Turn step whose pointer aims at this line, because this is where that
   * step's code lands: the first line of a stub the step replaces, or the line
   * it appends after. Tagged on the line rather than worked out from a step
   * number, so it cannot drift out of step with the excerpt. No two lines of
   * one render carry the same `aim`, which is what keeps exactly one element
   * marked.
   */
  aim?: number;
};

/**
 * How long each line of the excerpt waits before it types itself.
 *
 * A line's lead is the characters written before it within its own step's
 * batch, at the rate the primitive writes new text at, so line N + 1 starts as
 * line N finishes and the block is written top to bottom.
 *
 * Batches are counted separately rather than across the whole excerpt: lines
 * from earlier steps finished long ago and keep their own state, and a reader
 * who jumps straight to a late step still gets each block written in order
 * rather than one flat parallel smear.
 */
function typeLeads(lines: CodeLine[]): number[] {
  const written = new Map<number, number>();
  return lines.map((line) => {
    if (line.step === undefined) return 0;
    const before = written.get(line.step) ?? 0;
    written.set(line.step, before + line.text.length);
    return before * TYPEIN_MS;
  });
}

/**
 * The excerpt of main.gd the pane holds: the three functions the Turn touches,
 * from `func _ready` on line 11 down, rather than a whole file. The code box is
 * shorter than the excerpt gets and is pinned to its end, so what a reader sees
 * is always the block the Turn has just written. The gates are monotone, so
 * `gated` never arrives before the collect_coin body it extends.
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
      { text: '    for coin in get_tree().get_nodes_in_group("coins"):', kind: 'add', step: 2 },
      {
        text: '        coin.body_entered.connect(_on_coin_body_entered.bind(coin))',
        kind: 'add',
        step: 2,
      },
    );
  } else {
    lines.push(
      {
        text: '    # TODO: Connect every node in the "coins" group so touching it calls',
        kind: 'todo',
        // Step 2 writes over this stub, so this is where its two lines land.
        aim: 2,
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
        step: 3,
      },
      { text: '        return', kind: 'add', step: 3 },
      { text: '', kind: 'add', step: 3 },
      { text: '    coin.queue_free()', kind: 'add', step: 3 },
      { text: '    score += 1', kind: 'add', step: 3 },
      {
        text: '    score_label.text = "COINS: %d/%d" % [score, TOTAL_COINS]',
        kind: 'add',
        step: 3,
        // The win gate is the one step that replaces no stub: step 4 appends it
        // to the end of this body, so this is the line its code lands after and
        // the line its pointer stands on. `collect_coin` always ends here by the
        // time step 4 can run, since the gates are monotone.
        aim: 4,
      },
    );
  } else {
    lines.push(
      {
        text: '    # TODO: Remove the collected coin, increment score, refresh ScoreLabel,',
        kind: 'todo',
        // Step 3 writes over this stub.
        aim: 3,
      },
      { text: '    # and reveal WinPanel after all five coins are collected.', kind: 'todo' },
      { text: '    pass', kind: 'todo' },
    );
  }

  if (gates.gated) {
    lines.push(
      { text: '', kind: 'add', step: 4 },
      { text: '    if score >= TOTAL_COINS:', kind: 'add', step: 4 },
      { text: '        player.set_physics_process(false)', kind: 'add', step: 4 },
      { text: '        win_panel.visible = true', kind: 'add', step: 4 },
    );
  }

  lines.push({ text: '' }, { text: 'func reset_game() -> void:' });

  if (gates.restarts) {
    lines.push({ text: '    get_tree().reload_current_scene()', kind: 'add', step: 5 });
  } else {
    lines.push(
      {
        text: '    # TODO: Reload the current scene so the player can play again.',
        kind: 'todo',
        // Step 5 writes over this stub.
        aim: 5,
      },
      { text: '    pass', kind: 'todo' },
    );
  }

  return lines;
}

/**
 * The element the pointer aims at while it travels to step `next`.
 *
 * The render being crossed is the project *after* step `next - 1`, so a key may
 * only name something that exists then. The four edit steps resolve to the one
 * line of the excerpt that step's code lands on, tagged `aim` where the line is
 * written; it moves down and scrolls as the file grows, which is exactly what a
 * fixed coordinate could not follow.
 *
 * They used to resolve to the excerpt's *last* line instead, on the grounds
 * that appended code appears at the end. Only the win gate is appended: the
 * other three steps write over a stub in the middle of the file, so the pointer
 * sat on `reset_game`'s `pass` for all four steps in a row, never moving, while
 * the event line said `_ready` and then `collect_coin`.
 */
type Target = 'play' | 'line' | 'coin' | 'again' | null;

function targetOf(next: number): Target {
  switch (next) {
    // The coin the starter's player walks through without collecting. It is the
    // defect the message reports and the only thing in the viewport this step
    // changes: it goes hollow and dashed with the player standing on it. The
    // whole play area was marked here once, which parked the pointer in the
    // empty middle of the level while the change happened down and to the right.
    case 1:
      return 'coin';
    case 2:
    case 3:
    case 4:
    case 5:
      return 'line'; // the line in main.gd this step's code lands on
    // Both of these are about coins being cleared, so both point at the coin
    // the message names. The file state chip was tried for the save step and
    // sits at the very top of the pane, inside the control aura, where the
    // pointer is half off the screen; the step's message is about the run and
    // the first coin anyway.
    case 6:
    case 7:
      return 'coin';
    case 8:
      return 'play'; // the win panel does not exist yet: mark what will hold it
    case 9:
      return 'again'; // PLAY AGAIN, which by now is on screen
    default:
      return null;
  }
}

function Project({ step, next, reduced }: StageProps) {
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
  const leads = typeLeads(lines);
  const target = targetOf(next);
  // Which coin the pointer stands on. The save step clears the first coin, so
  // that is where the run starts; the starter's run and the verification's
  // second pair both end on the coin the starter walked through, so those two
  // share it. Matched by name, because the drawn list has the coins already
  // collected sliced off the front of it.
  const coinTarget = next === 6 ? COINS[0].name : MISSED_COIN;

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
                  data-cu-target={(target === 'line' && line.aim === next) || undefined}
                >
                  {/* A line the Turn has just written is written out, not
                      pasted in. Only `add` lines do this: they mount when the
                      step that writes them commits, so each one types itself
                      once and the lines already in the file stay put. `delayMs`
                      is what makes the block read top to bottom, since all of
                      its lines mount on the same frame. A blank line has
                      nothing to write, and routing one through Retype would
                      park a caret on it for the whole of its own lead. */}
                  {line.kind === 'add' && line.text ? (
                    <Retype value={line.text} animate={!reduced} typeIn delayMs={leads[index]} />
                  ) : (
                    line.text
                  )}
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
            data-cu-target={target === 'play' || undefined}
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
                data-cu-target={(target === 'coin' && coin.name === coinTarget) || undefined}
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
              <button
                type="button"
                className="gd-win-btn"
                disabled
                data-cu-target={target === 'again' || undefined}
              >
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
    // Pointer targets are fractions of the stage box, measured off the built
    // page at 1440 with Chromium rather than guessed. Every one of them is
    // somewhere the reader can actually see: the Controller window floats over
    // the bottom left of the Host, so a target is either in the game pane on
    // the right or in the top band of the script pane, which is the part of the
    // excerpt the code box keeps in view.
    //
    // They are the server's fallback and nothing else. Every step but the first
    // marks its element, so once hydrated what the pointer measures is the coin,
    // the line, the panel or the button that `targetOf` names, wherever the
    // reflowing interior has put it.
    {
      event: 'turn_started',
      label: 'Turn admitted',
      message: 'Turn admitted on host win-11-lab, desktop session console',
      // The player square at its spawn, where the run is about to start.
      // Nothing has been committed yet, so there is no action here.
      at: { x: 0.727, y: 0.601 },
    },
    {
      event: 'turn_progress',
      label: 'Run the starter',
      message: 'ran main.tscn, the player crossed a coin and COINS stayed 0/5',
      // The coin the starter walked through: drawn hollow and dashed at this
      // step, with the player standing on it. The Host is reporting what the
      // run did rather than taking input, so the pointer only moves.
      at: { x: 0.867, y: 0.54 },
    },
    {
      event: 'turn_progress',
      label: 'Wire coins group',
      message: 'connected body_entered for every node in the coins group to collect_coin',
      // The connect() call, second of the two lines this step writes into
      // _ready and the one that names collect_coin.
      at: { x: 0.258, y: 0.144 },
      act: 'type',
    },
    {
      event: 'turn_progress',
      label: 'Remove and score',
      message: 'filled collect_coin: queue_free the coin, score += 1, rewrite ScoreLabel',
      // Last line of the block, the ScoreLabel rewrite the message ends on.
      at: { x: 0.235, y: 0.28 },
      act: 'type',
    },
    {
      event: 'turn_progress',
      label: 'Gate the win panel',
      message: 'added the score >= TOTAL_COINS gate that stops player physics and shows WinPanel',
      // The gate line itself, `if score >= TOTAL_COINS:`.
      at: { x: 0.127, y: 0.225 },
      act: 'type',
    },
    {
      event: 'turn_progress',
      label: 'Wire play again',
      message: 'filled reset_game with get_tree().reload_current_scene()',
      // reset_game's one line, at the end of the excerpt.
      at: { x: 0.157, y: 0.389 },
      act: 'type',
    },
    {
      event: 'turn_progress',
      label: 'Save and re-run',
      message: 'saved main.gd in place, ran main.tscn, first coin cleared at COINS: 1/5',
      // Coin1's slot, now holding the player square that cleared it, which is
      // the outcome the message ends on. The main.gd tab is the other drawn
      // thing this step changes, but the pane head sits 17px below the top of
      // the stage, inside the control ring, and the pointer is kept off the
      // ring. No click either: Ctrl+S and walking the player are keystrokes,
      // and the only thing this Turn clicks in the game window is PLAY AGAIN.
      at: { x: 0.758, y: 0.533 },
    },
    {
      event: 'turn_progress',
      label: 'Clear three coins',
      message: 'second and third coins cleared, HUD read COINS: 3/5',
      // The HUD counter, which is what this step is a reading of.
      at: { x: 0.731, y: 0.066 },
    },
    {
      event: 'turn_progress',
      label: 'Reveal the panel',
      message: 'fourth and fifth coins cleared at COINS: 5/5, SECTOR CLEARED became visible',
      // The panel's own title, on the words rather than in the middle of the
      // overlay that fills the play area. The panel revealing itself is the
      // game responding to the gate, so the pointer only moves.
      at: { x: 0.848, y: 0.451 },
    },
    {
      event: 'turn_completed',
      label: 'Verify play again',
      message: 'PLAY AGAIN reloaded main.tscn, WASD and arrow movement unchanged',
      // Where PLAY AGAIN stood one step ago. The click reloads the scene, which
      // takes the panel away, so by the time this step draws there is no button
      // under the pointer. The play area keeps its top edge while the pane
      // relaxes, so this is still the point the button occupied.
      at: { x: 0.848, y: 0.508 },
      act: 'click',
    },
  ],
  Render: Project,
};
