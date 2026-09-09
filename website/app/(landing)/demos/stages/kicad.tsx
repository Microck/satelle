'use client';

import type { ReactNode } from 'react';
import type { Stage, StageProps } from '../stage';
import './kicad.css';

/**
 * Status light board, drawn as a PCB editor canvas.
 *
 * Every value the task specifies comes from its own board file and
 * Board_Requirements.txt: six footprints (J1, J2, R1, R2, C1, D1) at their real
 * positions, three nets (GND, +5V, LED_A), a 60 mm x 40 mm Edge.Cuts outline,
 * 0.40 mm tracks, and a filled GND zone on B.Cu.
 *
 * Footprint coordinates in the source file are absolute millimetres against a
 * board origin near 100,58: J1 at 106,78, R1 at 120,72, R2 at 136,72, C1 at
 * 120,88, D1 at 136,88, J2 at 151,78. Subtracting that origin and adding a 4 mm
 * offset gives the SVG coordinates below, so the viewBox is in real millimetres
 * and a 0.40 mm track is literally stroke-width 0.4.
 *
 * Footprint sizes are not in the task data, and true 0805 passives on a 60 mm
 * board come out too small to read as parts, so the four chip footprints are
 * drawn at a hand-assembly size. Positions, the outline, and the track width
 * stay at their real values.
 *
 * The DRC unconnected count is not a claim about a measured run. It counts the
 * ratsnest connections actually drawn in this diagram (2 for +5V, 3 for LED_A,
 * 4 for GND, nine in total) and falls to zero as tracks replace them.
 */

type NetName = '+5V' | 'LED_A' | 'GND';

/** Real millimetres: the 60x40 board plus 1.5 mm of editor canvas around it. */
const VIEW_BOX = '2.5 2.5 63 43';
const BOARD = { x: 4, y: 4, width: 60, height: 40 };
/** Copper pour is inset from Edge.Cuts so the fill stays inside the outline. */
const ZONE = { x: 4.5, y: 4.5, width: 59, height: 39 };

type Pad =
  | { kind: 'tht'; x: number; y: number; d: number; hole: number }
  | { kind: 'smd'; x: number; y: number; w: number; h: number };

type Part = {
  ref: string;
  /** Silkscreen body outline. */
  body: { x: number; y: number; width: number; height: number };
  pads: Pad[];
  /** Reference designator placement, kept clear of every track below. */
  label: { x: number; y: number; anchor: 'start' | 'middle' | 'end' };
  /** Cathode bar on the silkscreen. D1 only, so polarity reads correctly. */
  cathode?: { x: number; y1: number; y2: number };
};

const PARTS: Part[] = [
  // Two-pin through-hole connectors, 3.5 mm pitch. J1 takes +5V and GND in,
  // J2 takes LED_A and GND out.
  {
    ref: 'J1',
    body: { x: 7.5, y: 20, width: 5, height: 8 },
    pads: [
      { kind: 'tht', x: 10, y: 22.25, d: 2.2, hole: 1.1 },
      { kind: 'tht', x: 10, y: 25.75, d: 2.2, hole: 1.1 },
    ],
    label: { x: 10, y: 18.8, anchor: 'middle' },
  },
  {
    ref: 'J2',
    body: { x: 52.5, y: 20, width: 5, height: 8 },
    pads: [
      { kind: 'tht', x: 55, y: 22.25, d: 2.2, hole: 1.1 },
      { kind: 'tht', x: 55, y: 25.75, d: 2.2, hole: 1.1 },
    ],
    label: { x: 58.6, y: 24.8, anchor: 'start' },
  },
  // Series resistor R1, bleed resistor R2, decoupling capacitor C1, indicator
  // D1. All two-pad surface mount, pads overhanging the body the way they do.
  {
    ref: 'R1',
    body: { x: 22.4, y: 16.8, width: 3.2, height: 2.4 },
    pads: [
      { kind: 'smd', x: 22.1, y: 18, w: 2, h: 2.8 },
      { kind: 'smd', x: 25.9, y: 18, w: 2, h: 2.8 },
    ],
    label: { x: 24, y: 15.4, anchor: 'middle' },
  },
  {
    ref: 'R2',
    body: { x: 38.4, y: 16.8, width: 3.2, height: 2.4 },
    pads: [
      { kind: 'smd', x: 38.1, y: 18, w: 2, h: 2.8 },
      { kind: 'smd', x: 41.9, y: 18, w: 2, h: 2.8 },
    ],
    label: { x: 40, y: 15.4, anchor: 'middle' },
  },
  {
    ref: 'C1',
    body: { x: 22.4, y: 32.8, width: 3.2, height: 2.4 },
    pads: [
      { kind: 'smd', x: 22.1, y: 34, w: 2, h: 2.8 },
      { kind: 'smd', x: 25.9, y: 34, w: 2, h: 2.8 },
    ],
    label: { x: 24, y: 31.4, anchor: 'middle' },
  },
  {
    ref: 'D1',
    body: { x: 38.2, y: 32.6, width: 3.6, height: 2.8 },
    pads: [
      { kind: 'smd', x: 38.1, y: 34, w: 2, h: 3 },
      { kind: 'smd', x: 41.9, y: 34, w: 2, h: 3 },
    ],
    label: { x: 40, y: 31.4, anchor: 'middle' },
    cathode: { x: 41.3, y1: 32.9, y2: 35.1 },
  },
];

/**
 * Ratsnest: the unrouted connections KiCad draws between pads on one net.
 * Nine of them, which is the minimum spanning set for three pads on +5V, four
 * on LED_A, and five on GND.
 */
const RATSNEST: { net: NetName; x1: number; y1: number; x2: number; y2: number }[] = [
  { net: '+5V', x1: 10, y1: 22.25, x2: 22.1, y2: 18 },
  { net: '+5V', x1: 22.1, y1: 18, x2: 22.1, y2: 34 },
  { net: 'LED_A', x1: 25.9, y1: 18, x2: 38.1, y2: 18 },
  { net: 'LED_A', x1: 38.1, y1: 18, x2: 38.1, y2: 34 },
  { net: 'LED_A', x1: 38.1, y1: 18, x2: 55, y2: 22.25 },
  { net: 'GND', x1: 10, y1: 25.75, x2: 25.9, y2: 34 },
  { net: 'GND', x1: 25.9, y1: 34, x2: 41.9, y2: 34 },
  { net: 'GND', x1: 41.9, y1: 34, x2: 41.9, y2: 18 },
  { net: 'GND', x1: 41.9, y1: 18, x2: 55, y2: 25.75 },
];

/** Row order in the Nets panel, matching the order the script routes them. */
const NET_ORDER: NetName[] = ['+5V', 'LED_A', 'GND'];

/**
 * Pads per net, read off the six footprints. A net with n pads needs n-1
 * connections to be complete, which is why the ratsnest starts at nine.
 */
const PAD_COUNT: Record<NetName, number> = { '+5V': 3, LED_A: 4, GND: 5 };

/**
 * Tracks, as polyline point lists in millimetres. Corners are 45 degrees, which
 * is what a router produces, and every point sits inside the Edge.Cuts outline.
 * +5V and LED_A stay on F.Cu; GND leaves F.Cu at a via and runs on B.Cu.
 */
const POWER_TRACKS = [
  '10,22.25 13.85,22.25 18.1,18 22.1,18',
  '22.1,18 19.1,21 19.1,31 22.1,34',
];

const SIGNAL_TRACKS = [
  '25.9,18 38.1,18',
  '38.1,18 35.1,21 35.1,31 38.1,34',
  // Around the top of the board to reach J2, because both LED_A pads on R2 and
  // D1 face left and a track cannot cross the parts.
  '38.1,18 38.1,13 43.1,8 51,8 55,12 55,22.25',
];

/** Short F.Cu stubs from each GND pad to the via that drops it to B.Cu. */
const GROUND_STUBS = [
  '10,25.75 10,29',
  '25.9,34 28.9,37',
  '41.9,34 44.9,37',
  '41.9,18 46,18 49,21',
  '55,25.75 55,29',
];

/** Where copper changes layer. Five vias, one per GND pad. */
const VIAS = [
  { x: 10, y: 29 },
  { x: 28.9, y: 37 },
  { x: 44.9, y: 37 },
  { x: 49, y: 21 },
  { x: 55, y: 29 },
];

/** B.Cu: a trunk along the bottom of the board with a spur to each via. */
const GROUND_TRACKS = [
  '10,40 55,40',
  '10,29 10,40',
  '28.9,37 28.9,40',
  '44.9,37 44.9,40',
  '49,21 49,40',
  '55,29 55,40',
];

/**
 * Net name annotations. Each one sits beside its net in both phases, so the
 * label still points at copper once the ratsnest it started next to is gone.
 */
const NET_LABELS: { net: NetName; x: number; y: number; anchor: 'start' | 'middle' | 'end' }[] = [
  { net: '+5V', x: 14.6, y: 25.2, anchor: 'start' },
  { net: 'LED_A', x: 32, y: 20.6, anchor: 'middle' },
  { net: 'GND', x: 47.4, y: 24.4, anchor: 'end' },
];

const LAYERS: { name: string; key: string }[] = [
  { name: 'F.Cu', key: 'f' },
  { name: 'B.Cu', key: 'b' },
  { name: 'Edge.Cuts', key: 'edge' },
];

const FAB_FILES = [
  'status_light-F_Cu.gbr',
  'status_light-B_Cu.gbr',
  'status_light-Edge_Cuts.gbr',
  'status_light-PTH.drl',
];

/**
 * The element the pointer aims at while it travels to step `next`.
 *
 * Most of this stage keeps its coordinates on purpose. The board is a fixed SVG
 * viewBox, so a point on it is a genuine point: routing to a pad, dropping a
 * via, filling a zone. Marking an element there would be less accurate, not
 * more.
 *
 * The side panel is the part that reflows, since the DRC counters, the
 * Requirements list and the fabrication file list replace one another in the
 * same slot. Those steps are the ones worth marking.
 */
type Target = 'panel' | 'drc' | 'slot' | null;

function targetOf(next: number): Target {
  switch (next) {
    // The brief is read from a file, not from the screen. What this step puts on
    // screen is the Requirements list, which is not there yet, so the pointer
    // goes to the panel that will hold it.
    case 1:
      return 'panel';
    case 7:
      return 'drc';
    // Both output steps write into the same panel slot, which the Requirements
    // list occupies until the fabrication list replaces it.
    case 8:
    case 9:
      return 'slot';
    // Everything else is a point on the board: see the note above.
    default:
      return null;
  }
}

function Board({ step, next }: StageProps) {
  // Step gates. Each one is the state *after* that action commits, so the whole
  // interior is a pure function of one number and a test can jump anywhere.
  const briefRead = step >= 1;
  const netsChecked = step >= 2;
  const power = step >= 3;
  const signal = step >= 4;
  const ground = step >= 5;
  const zoned = step >= 6;
  const drcRun = step >= 7;
  const saved = step >= 8;
  const exported = step >= 9;

  const routed: Record<NetName, boolean> = { '+5V': power, LED_A: signal, GND: ground };
  const routing: Record<NetName, string> = {
    '+5V': 'F.Cu',
    LED_A: 'F.Cu',
    GND: zoned ? 'B.Cu + zone' : 'B.Cu',
  };
  const unconnected = NET_ORDER.reduce(
    (open, net) => (routed[net] ? open : open + PAD_COUNT[net] - 1),
    0,
  );

  const canvasLabel =
    'Board layout diagram, 60 by 40 millimetres, six footprints J1, J2, R1, R2, C1 and D1. ' +
    (unconnected > 0
      ? `${unconnected} unconnected items drawn as dashed ratsnest lines.`
      : 'Every net routed with 0.40 millimetre tracks and no unconnected items.') +
    (zoned ? ' A filled GND zone covers the back copper layer.' : '');

  return (
    <div className="kc">
      <div className="kc-bar">
        <span className="kc-file sa-mono">
          {saved ? 'submission/status_light_final.kicad_pcb' : 'status_light.kicad_pcb'}
        </span>
        <span className="kc-spec sa-mono">
          <span className="sa-faint">outline</span> 60.00 x 40.00 mm
        </span>
        <span className="kc-spec sa-mono">
          <span className="sa-faint">track</span> 0.40 mm
        </span>
      </div>

      <div className="kc-panes">
        <div className="sa-scroll kc-canvas">
          <div className="kc-canvas-inner">
            <svg viewBox={VIEW_BOX} role="img" aria-label={canvasLabel}>
              <defs>
                {/* Editor grid at 5 mm, aligned to the board corner. Static: it
                    is a pattern, so nothing repaints. */}
                <pattern
                  id="kc-grid-dots"
                  x="1.5"
                  y="1.5"
                  width="5"
                  height="5"
                  patternUnits="userSpaceOnUse"
                >
                  <circle cx="2.5" cy="2.5" r="0.12" className="kc-gridpt" />
                </pattern>
              </defs>

              <rect {...BOARD} className="kc-substrate" />
              <rect {...BOARD} fill="url(#kc-grid-dots)" />

              {/* B.Cu pour first, so it sits behind every track. */}
              {zoned ? <rect {...ZONE} className="kc-zone" /> : null}

              {ground ? <Tracks points={GROUND_TRACKS} layer="b" /> : null}

              {power ? <Tracks points={POWER_TRACKS} layer="f" /> : null}
              {signal ? <Tracks points={SIGNAL_TRACKS} layer="f" /> : null}
              {ground ? <Tracks points={GROUND_STUBS} layer="f" /> : null}

              {/* A ratsnest line disappears the moment its net is routed. */}
              {RATSNEST.map((link) => {
                if (routed[link.net]) return null;
                return (
                  <line
                    key={`${link.net}-${link.x1}-${link.y1}-${link.x2}-${link.y2}`}
                    x1={link.x1}
                    y1={link.y1}
                    x2={link.x2}
                    y2={link.y2}
                    className="kc-rats"
                  />
                );
              })}

              {ground
                ? VIAS.map((via) => (
                    <g key={`${via.x}-${via.y}`}>
                      <circle cx={via.x} cy={via.y} r="0.55" className="kc-via" />
                      <circle cx={via.x} cy={via.y} r="0.22" className="kc-drill" />
                    </g>
                  ))
                : null}

              {PARTS.map((part) => (
                <g key={part.ref}>
                  <rect {...part.body} className="kc-silk" />
                  {part.cathode ? (
                    <line
                      x1={part.cathode.x}
                      y1={part.cathode.y1}
                      x2={part.cathode.x}
                      y2={part.cathode.y2}
                      className="kc-silk-mark"
                    />
                  ) : null}
                  {part.pads.map((pad) =>
                    pad.kind === 'tht' ? (
                      <g key={`${pad.x}-${pad.y}`}>
                        <circle cx={pad.x} cy={pad.y} r={pad.d / 2} className="kc-pad" />
                        <circle cx={pad.x} cy={pad.y} r={pad.hole / 2} className="kc-drill" />
                      </g>
                    ) : (
                      <rect
                        key={`${pad.x}-${pad.y}`}
                        x={pad.x - pad.w / 2}
                        y={pad.y - pad.h / 2}
                        width={pad.w}
                        height={pad.h}
                        rx="0.15"
                        className="kc-pad"
                      />
                    ),
                  )}
                  <text
                    x={part.label.x}
                    y={part.label.y}
                    textAnchor={part.label.anchor}
                    className="kc-ref"
                  >
                    {part.ref}
                  </text>
                </g>
              ))}

              {netsChecked
                ? NET_LABELS.map((label) => (
                    <text
                      key={label.net}
                      x={label.x}
                      y={label.y}
                      textAnchor={label.anchor}
                      className="kc-netname"
                    >
                      {label.net}
                    </text>
                  ))
                : null}

              {/* Edge.Cuts last so the outline reads on top of the pour. */}
              <rect {...BOARD} className="kc-edge" />
            </svg>
          </div>
        </div>

        <div className="kc-side" data-cu-target={targetOf(next) === 'panel' || undefined}>
          <section className="kc-block">
            <span className="sa-label">DRC</span>
            <table className="kc-table" data-cu-target={targetOf(next) === 'drc' || undefined}>
              <caption className="sa-sr">Design rule check counters</caption>
              <tbody>
                <tr>
                  <th scope="row">Unconnected items</th>
                  <td className="kc-count" data-clear={unconnected === 0}>
                    {unconnected}
                  </td>
                </tr>
                <tr>
                  <th scope="row">Errors</th>
                  {/* The ratsnest count above is live, but an error count only
                      exists once DRC has actually been run, and nothing in this
                      script introduces a violation. */}
                  <td className="kc-count" data-clear={drcRun ? true : undefined}>
                    {drcRun ? 0 : '--'}
                  </td>
                </tr>
              </tbody>
            </table>
            <p className="kc-drc-state">
              <span className="sa-dot" data-state={drcRun ? 'completed' : undefined} />
              <span className="sa-mono">{drcRun ? 'clean' : 'not run'}</span>
            </p>
          </section>

          {netsChecked ? (
            <section className="kc-block">
              <span className="sa-label">Nets</span>
              <table className="kc-table kc-table-nets">
                <caption className="sa-sr">
                  Nets on the board and the layer each one is routed on
                </caption>
                <thead>
                  <tr>
                    <th scope="col">Net</th>
                    <th scope="col">Pads</th>
                    <th scope="col">Routing</th>
                  </tr>
                </thead>
                <tbody>
                  {NET_ORDER.map((net) => (
                    <tr key={net}>
                      <th scope="row">{net}</th>
                      <td>{PAD_COUNT[net]}</td>
                      <td data-routed={routed[net]}>
                        {routed[net] ? routing[net] : 'unrouted'}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </section>
          ) : null}

          {briefRead && !exported ? (
            <section className="kc-block">
              <span className="sa-label">Requirements</span>
              <ul className="kc-reqs" data-cu-target={targetOf(next) === 'slot' || undefined}>
                <Requirement done={netsChecked}>Keep six footprints and net names</Requirement>
                <Requirement done={ground}>0.40 mm tracks, copper inside Edge.Cuts</Requirement>
                <Requirement done={zoned}>Filled GND zone on B.Cu</Requirement>
                <Requirement done={drcRun}>DRC with no unconnected items or errors</Requirement>
              </ul>
            </section>
          ) : null}

          {exported ? (
            <section className="kc-block">
              <span className="kc-path sa-mono">submission/fabrication/</span>
              <ul className="kc-files">
                {FAB_FILES.map((file) => (
                  <li key={file}>{file}</li>
                ))}
              </ul>
            </section>
          ) : null}
        </div>
      </div>

      <div className="kc-layers">
        {LAYERS.map((layer) => (
          <span key={layer.name} className="kc-layer sa-mono">
            <span className="kc-swatch" data-layer={layer.key} />
            {layer.name}
          </span>
        ))}
        <span className="kc-tally sa-faint sa-mono">
          6 footprints / 3 nets / {ground ? VIAS.length : 0} vias
        </span>
      </div>
    </div>
  );
}

/**
 * One requirement the Turn has to satisfy. These summarise the brief rather
 * than quoting it, so the panel labels them "Requirements" and not by filename.
 * The tick is a ::before glyph, so the done or pending state is repeated in
 * text a screen reader can reach.
 */
function Requirement({ done, children }: { done: boolean; children: ReactNode }) {
  return (
    <li data-done={done}>
      <span className="sa-sr">{done ? 'done, ' : 'pending, '}</span>
      {children}
    </li>
  );
}

/** One layer's worth of 0.40 mm copper. Front is the accent, back is the ramp. */
function Tracks({ points, layer }: { points: string[]; layer: 'f' | 'b' }) {
  return (
    <>
      {points.map((line) => (
        <polyline key={line} points={line} className={`kc-track kc-track-${layer}`} />
      ))}
    </>
  );
}

export const kicadStage: Stage = {
  id: 'kicad',
  pick: 'Route a PCB and export fabrication files',
  app: 'PCB Editor',
  file: 'status_light.kicad_pcb',
  prompt:
    'Open status_light.kicad_pcb in KiCad PCB Editor. Keep all six footprints and net names. Route every ratsnest connection using 0.40 mm tracks, keeping copper inside the 60 mm x 40 mm Edge.Cuts outline. Add a filled GND zone on B.Cu. Run DRC until there are no unconnected items or errors. Save the finished board as submission/status_light_final.kicad_pcb, then export Gerber files and an Excellon drill file into submission/fabrication/.',
  budget: { minutes: 25, steps: 220 },
  /**
   * Pointer choreography. Every `at` was measured off the rendered stage at a
   * 1440 px viewport, as a fraction of the .desk-stage box: board points come
   * from the SVG's own millimetre grid through its screen matrix, panel points
   * from the element's client box. Routing is the physical work here, so each
   * route step drags to the far end of the copper it lays and the three of them
   * sweep left, right, then down across the board.
   */
  steps: [
    {
      event: 'turn_started',
      label: 'Turn admitted',
      message: 'Turn admitted on host win-11-lab, desktop session console',
      // Nothing has been touched yet: the pointer waits on the J1 pads, where
      // the first track starts.
      at: { x: 0.211, y: 0.312 },
    },
    {
      event: 'turn_progress',
      label: 'Read the brief',
      message: 'opened status_light.kicad_pcb, read Board_Requirements.txt',
      // The brief itself is not on screen; what this step puts on screen is the
      // Requirements list it was read from.
      at: { x: 0.869, y: 0.314 },
      act: 'click',
    },
    {
      event: 'turn_progress',
      label: 'Check the netlist',
      message: 'confirmed footprints J1 J2 R1 R2 C1 D1 and nets GND +5V LED_A',
      // Selecting a net on the board is what labels all three of them, so the
      // pointer goes to the LED_A label rather than to the Nets panel, which
      // would sit under where the previous click already left it.
      at: { x: 0.356, y: 0.268 },
      act: 'click',
    },
    {
      event: 'turn_progress',
      label: 'Route +5V',
      message: 'routed +5V on F.Cu with 0.40 mm tracks, J1 to R1 to C1',
      // End of the +5V run: C1's left pad, at 22.1,34 mm.
      at: { x: 0.29, y: 0.426 },
      act: 'drag',
    },
    {
      event: 'turn_progress',
      label: 'Route LED_A',
      message: 'routed LED_A on F.Cu, R1 to R2 to D1 and out to J2',
      // End of the LED_A run: J2's top pad at 55,22.25 mm, right across the
      // board from where +5V finished.
      at: { x: 0.507, y: 0.292 },
      act: 'drag',
    },
    {
      event: 'turn_progress',
      label: 'Route GND',
      message: 'dropped 5 vias, routed GND on B.Cu inside the Edge.Cuts outline',
      // The via at 10,29 mm, where J1's GND pad drops to B.Cu: it ends the first
      // ground stub, so the drag sweeps back across the board from J2. The vias
      // on the bottom trunk are level with the Controller window, which sits
      // over that corner of the Host, and would hide the pointer.
      at: { x: 0.211, y: 0.369 },
      act: 'drag',
    },
    {
      event: 'turn_progress',
      label: 'Fill GND zone',
      message: 'added a filled GND zone on B.Cu behind the routed copper',
      // Middle of the B.Cu pour: a fill is commanded from inside the zone.
      at: { x: 0.369, y: 0.312 },
      act: 'click',
    },
    {
      event: 'turn_progress',
      label: 'Run DRC',
      message: 'ran DRC, 0 unconnected items and 0 errors',
      at: { x: 0.869, y: 0.137 },
      act: 'click',
    },
    {
      event: 'turn_progress',
      label: 'Save the board',
      message: 'saved submission/status_light_final.kicad_pcb',
      // The submission slot in the side panel: the Requirements list sits here
      // until the fabrication list replaces it at the same place, so the two
      // output steps land on the same block.
      at: { x: 0.869, y: 0.498 },
      act: 'click',
    },
    {
      event: 'turn_completed',
      label: 'Export fabrication',
      message:
        'exported F.Cu, B.Cu and Edge.Cuts gerbers plus status_light-PTH.drl to submission/fabrication/',
      // The drill file, last line of the fabrication list this step writes.
      at: { x: 0.869, y: 0.547 },
      act: 'click',
    },
  ],
  Render: Board,
};
