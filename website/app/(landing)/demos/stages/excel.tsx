'use client';

import { useRetype } from '../typewriter';
import type { Stage, StageProps } from '../stage';
import './excel.css';

/**
 * Q3 sales cleanup, drawn as a spreadsheet. Every number here comes from the
 * showcase task's own assets: 34 data rows with four duplicate Order IDs
 * (Q3-1003, Q3-1008, Q3-1015, Q3-1026), one broken Revenue formula in J5 that
 * drops the discount term, and the control totals from Checks.txt.
 */

type Row = {
  id: string;
  region: string;
  rep: string;
  product: string;
  units: number;
  price: number;
  cost: number;
  discount: number;
  /** True for the second copy of a repeated Order ID. */
  duplicate?: boolean;
  /** True for the row whose Revenue formula omits the discount term. */
  broken?: boolean;
};

const ROWS: Row[] = [
  { id: 'Q3-1001', region: 'West', rep: 'Quinn', product: 'Nova Webcam', units: 11, price: 149, cost: 84, discount: 0.05 },
  { id: 'Q3-1002', region: 'North', rep: 'Jordan', product: 'Arc Dock', units: 14, price: 189, cost: 112, discount: 0.1 },
  { id: 'Q3-1003', region: 'South', rep: 'Morgan', product: 'Pulse Mouse', units: 17, price: 79, cost: 38, discount: 0 },
  { id: 'Q3-1003', region: 'South', rep: 'Morgan', product: 'Pulse Mouse', units: 17, price: 79, cost: 38, discount: 0, duplicate: true },
  { id: 'Q3-1004', region: 'East', rep: 'Casey', product: 'Halo Headset', units: 6, price: 109, cost: 61, discount: 0.05, broken: true },
  { id: 'Q3-1005', region: 'West', rep: 'Quinn', product: 'Orbit Keyboard', units: 9, price: 129, cost: 72, discount: 0.1 },
  { id: 'Q3-1006', region: 'North', rep: 'Jordan', product: 'Nova Webcam', units: 12, price: 149, cost: 84, discount: 0 },
  { id: 'Q3-1007', region: 'South', rep: 'Morgan', product: 'Arc Dock', units: 15, price: 189, cost: 112, discount: 0.05 },
  { id: 'Q3-1008', region: 'East', rep: 'Casey', product: 'Pulse Mouse', units: 4, price: 79, cost: 38, discount: 0.1 },
  { id: 'Q3-1008', region: 'East', rep: 'Casey', product: 'Pulse Mouse', units: 4, price: 79, cost: 38, discount: 0.1, duplicate: true },
];

/** The first repeated Order ID on the sheet, which is where the sweep starts. */
const FIRST_DUPLICATE = ROWS.findIndex((row) => row.duplicate);

const MONTHS = [
  { label: 'Jul', revenue: 13701.8, profit: 5562.8 },
  { label: 'Aug', revenue: 11826.35, profit: 4835.35 },
  { label: 'Sep', revenue: 13915.95, profit: 5810.95 },
];
const GRAND = { revenue: 39444.1, profit: 16209.1, margin: 0.41093851805466475 };

const money = (value: number) =>
  value.toLocaleString('en-US', { minimumFractionDigits: 2, maximumFractionDigits: 2 });
const percent = (value: number) => `${(value * 100).toFixed(1)}%`;

/** Revenue, honouring the missing discount term until the formula is repaired. */
function revenueOf(row: Row, repaired: boolean) {
  const discount = row.broken && !repaired ? 0 : row.discount;
  return row.units * row.price * (1 - discount);
}

/**
 * The one element the pointer aims at while it travels to step `next`, as a key
 * the render matches against.
 *
 * The pointer measures the marked element live, against the render it is
 * crossing, and that render is the sheet *after* step `next - 1`. So every key
 * here has to name something already drawn at that point: where a step creates
 * something, the key names what will hold it, or the control that makes it.
 *
 * Nothing here may resolve to the sheet tabs at the left of the strip or to the
 * middle of the grid's bottom edge: the Controller window covers the Host's
 * bottom left corner, measured at 1440 as out to x 0.583 and down from y 0.466
 * of the stage, and a pointer under it is invisible. Nor to the formula bar,
 * whose centre lands at 0.525, 0.026, under both the top of the control aura
 * and the aura's own label pill at x 0.41 to 0.59.
 */
type Target =
  | 'file'
  | 'duplicate'
  | 'revenue'
  | 'profitHead'
  | 'newSheet'
  | 'summary'
  | 'total'
  | null;

function targetOf(next: number): Target {
  switch (next) {
    // Opening the workbook and saving the copy both act on its name, which is
    // the one drawn thing either message names.
    case 1:
    case 2:
      return 'file';
    // The duplicate rows themselves, while they are still on the sheet. A
    // coordinate could only ever point at whatever took their place.
    case 3:
      return 'duplicate';
    // Drawn J5: the Revenue cell of the broken row, which turns from the wrong
    // figure to the right one and which shows the formula being written while
    // it happens. The formula bar carries the same edit and keeps the caret,
    // being the only field wide enough to read a formula at this size, but it
    // cannot be the target: its centre is 17px from the top of the stage, under
    // the aura's label.
    case 4:
      return 'revenue';
    // The Profit column header, the first of the two columns the fill crosses.
    case 5:
      return 'profitHead';
    // The Summary sheet does not exist yet, so the pointer works the control
    // that makes one. That control is drawn at the right end of the tab strip
    // because the sheet tabs at its left end are behind the Controller window.
    case 6:
      return 'newSheet';
    // The pane the chart lands in. It is on screen by this step, so the thing
    // that will hold the chart can be marked rather than the chart itself.
    case 7:
      return 'summary';
    // The grand totals this step checks against Checks.txt. The check list is
    // not drawn until the step commits; the totals it agrees with are.
    case 8:
      return 'total';
    // Admitting the Turn touches nothing on the sheet, so nothing is marked and
    // the step's own coordinate stands.
    default:
      return null;
  }
}

function Sheet({ step, next, reduced }: StageProps) {
  // Step gates. Each one is the state *after* that action commits.
  const inSubmission = step >= 2;
  const deduped = step >= 3;
  const repaired = step >= 4;
  const derived = step >= 5;
  const summarised = step >= 6;
  const charted = step >= 7;
  const verified = step >= 8;
  const target = targetOf(next);

  const rows = deduped ? ROWS.filter((row) => !row.duplicate) : ROWS;
  const activeCell = repaired ? 'J5' : step === 3 ? 'A5' : 'A1';
  const formula = repaired
    ? '=F5*G5*(1-I5)'
    : step >= 1
      ? '=F5*G5'
      : '';
  // The formula bar is typed rather than swapped, and the "repaired" badge
  // waits for the typing to finish: it was appearing on the first keystroke,
  // calling the formula repaired while it was still being written.
  //
  // It types only for the repair, which is the one step whose message says the
  // Turn typed. The broken formula was in the workbook when it opened, so it is
  // simply there beforehand: writing it out the moment the workbook opened put
  // a blinking caret at the top of the sheet while the pointer was down in the
  // tab strip clicking the file, which is two claims at once about where the
  // Turn is working, and neither of them is what that step's message says.
  const typed = useRetype(formula, !reduced && repaired);
  // True while the repair is being written. The pointer stands on the cell, so
  // the cell has to show the edit; see the overlay below.
  const editing = repaired && typed.editing;

  return (
    <div className="xl">
      <div className="xl-bar">
        <span className="xl-cellref sa-mono">{activeCell}</span>
        <span className="xl-formula sa-mono">
          {formula ? (
            <>
              {/* The repair rewrites this field, so it is typed rather than
                  swapped: the broken formula's tail is deleted and the corrected
                  one is written in its place. Watching `=F5*G5` become
                  `=F5*G5*(1-I5)` is the clearest thing on the stage. */}
              {typed.shown}
              {typed.editing ? (
                <i className="sa-caret" data-blink="true" aria-hidden="true" />
              ) : null}
              {repaired && !typed.editing ? <span className="xl-fixed">repaired</span> : null}
            </>
          ) : (
            <span className="sa-faint">fx</span>
          )}
        </span>
      </div>

      <div className="xl-panes" data-summary={summarised}>
        <div className="sa-scroll xl-gridwrap">
          <table className="xl-grid">
            <caption className="sa-sr">
              Orders sheet, {deduped ? '30 unique orders' : '34 rows including 4 duplicates'}
            </caption>
            <thead>
              <tr>
                <th scope="col" className="xl-rownum" />
                {['Order ID', 'Region', 'Rep', 'Product', 'Units', 'Price', 'Revenue', 'COGS', 'Profit', 'Margin %'].map(
                  (head) => (
                    <th
                      scope="col"
                      key={head}
                      data-cu-target={(target === 'profitHead' && head === 'Profit') || undefined}
                    >
                      {head}
                    </th>
                  ),
                )}
              </tr>
            </thead>
            <tbody>
              {rows.map((row, index) => {
                const revenue = revenueOf(row, repaired);
                const cogs = row.units * row.cost;
                const profit = revenue - cogs;
                return (
                  <tr
                    key={`${row.id}-${index}`}
                    data-dup={!deduped && row.duplicate}
                    data-broken={row.broken && !repaired}
                  >
                    <th scope="row" className="xl-rownum">
                      {index + 2}
                    </th>
                    {/* Only the first of the repeated IDs is marked: two marks
                        would leave the pointer's choice to document order. */}
                    <td
                      data-cu-target={
                        (target === 'duplicate' && !deduped && index === FIRST_DUPLICATE) ||
                        undefined
                      }
                    >
                      {row.id}
                    </td>
                    <td>{row.region}</td>
                    <td>{row.rep}</td>
                    <td className="xl-wide">{row.product}</td>
                    <td className="xl-num">{row.units}</td>
                    <td className="xl-num">{money(row.price)}</td>
                    {/* Marked whether or not the repair has landed: the cell is
                        the same cell before and after, so the pointer that
                        typed in it stays in it. */}
                    <td
                      className="xl-num"
                      data-fixed={row.broken && repaired}
                      data-editing={(row.broken && editing) || undefined}
                      data-cu-target={(target === 'revenue' && row.broken) || undefined}
                    >
                      {money(revenue)}
                      {/* The edit, drawn in the cell the pointer is standing
                          on. The caret stays in the formula bar, which is the
                          only field wide enough to read the formula at this
                          size, but a step whose message says it typed has to
                          show something happening under the pointer: a cell
                          whose number simply changes reads as the pointer
                          having missed whatever did it.
                          Drawn over the cell rather than in it, so thirteen
                          characters of formula cannot widen an eight character
                          column and shove the rest of the row sideways
                          mid-edit. A spreadsheet's own edit box overhangs its
                          neighbours in exactly this way. */}
                      {row.broken && editing ? (
                        <span className="xl-edit sa-mono" aria-hidden="true">
                          {typed.shown}
                        </span>
                      ) : null}
                    </td>
                    <td className="xl-num">{money(cogs)}</td>
                    <td className="xl-num">{derived ? money(profit) : ''}</td>
                    <td className="xl-num">{derived ? percent(profit / revenue) : ''}</td>
                  </tr>
                );
              })}
              <tr className="xl-more">
                <th scope="row" className="xl-rownum">
                  &hellip;
                </th>
                <td colSpan={10}>
                  {deduped ? '22 further unique orders' : '24 further rows'}
                </td>
              </tr>
            </tbody>
          </table>
        </div>

        {summarised ? (
          <div className="xl-summary" data-cu-target={target === 'summary' || undefined}>
            <span className="sa-label">Summary</span>
            <div className="sa-scroll xl-summary-scroll">
              <table className="xl-grid xl-grid-summary">
              <thead>
                <tr>
                  <th scope="col">Month</th>
                  <th scope="col">Revenue</th>
                  <th scope="col">Profit</th>
                  <th scope="col">Margin %</th>
                </tr>
              </thead>
              <tbody>
                {MONTHS.map((month) => (
                  <tr key={month.label}>
                    <th scope="row">{month.label}</th>
                    <td className="xl-num">{money(month.revenue)}</td>
                    <td className="xl-num">{money(month.profit)}</td>
                    <td className="xl-num">{percent(month.profit / month.revenue)}</td>
                  </tr>
                ))}
                <tr className="xl-total" data-cu-target={target === 'total' || undefined}>
                  <th scope="row">Grand Total</th>
                  <td className="xl-num">{money(GRAND.revenue)}</td>
                  <td className="xl-num">{money(GRAND.profit)}</td>
                  <td className="xl-num">{(GRAND.margin * 100).toFixed(3)}%</td>
                </tr>
              </tbody>
              </table>
            </div>

            {charted ? <RevenueProfitChart /> : null}

            {verified ? (
              <ul className="xl-checks">
                <li>Unique orders 30</li>
                <li>Grand Revenue 39,444.10</li>
                <li>Grand Profit 16,209.10</li>
                <li>Grand Margin 41.094%</li>
                <li>Source workbook unchanged</li>
              </ul>
            ) : null}
          </div>
        ) : null}
      </div>

      <div className="xl-tabs" role="presentation">
        <span className="xl-tab" data-active={!summarised}>
          Orders
        </span>
        {summarised ? (
          <span className="xl-tab" data-active>
            Summary
          </span>
        ) : null}
        {/* The control that adds a sheet, which is what the pointer works to
            build the Summary sheet: the sheet itself cannot be marked before it
            exists. Drawn at the right end of the strip because the Controller
            window covers the left end, where the tabs are. */}
        <span className="xl-newsheet" data-cu-target={target === 'newSheet' || undefined}>
          + sheet
        </span>
        <span className="xl-file sa-faint" data-cu-target={target === 'file' || undefined}>
          {inSubmission ? 'submission/Q3_Sales_Submission.xlsx' : 'Q3_Sales_Challenge.xlsx'}
        </span>
      </div>
    </div>
  );
}

/** Monthly Revenue against Profit. Two polylines, no library, no animation. */
function RevenueProfitChart() {
  const width = 260;
  const height = 92;
  const pad = { top: 8, right: 8, bottom: 16, left: 8 };
  const max = Math.max(...MONTHS.map((month) => month.revenue)) * 1.08;
  const x = (index: number) =>
    pad.left + (index * (width - pad.left - pad.right)) / (MONTHS.length - 1);
  const y = (value: number) =>
    height - pad.bottom - (value / max) * (height - pad.top - pad.bottom);
  const path = (pick: (month: (typeof MONTHS)[number]) => number) =>
    MONTHS.map((month, index) => `${x(index)},${y(pick(month))}`).join(' ');

  return (
    <figure className="xl-chart">
      <figcaption className="sa-label">Revenue against Profit</figcaption>
      <svg viewBox={`0 0 ${width} ${height}`} role="img" aria-label="Line chart: monthly revenue and profit for July, August, and September">
        <line
          x1={pad.left}
          x2={width - pad.right}
          y1={height - pad.bottom}
          y2={height - pad.bottom}
          stroke="var(--sa-6)"
          strokeWidth="1"
        />
        <polyline
          points={path((month) => month.revenue)}
          fill="none"
          stroke="var(--sa-accent)"
          strokeWidth="1.5"
        />
        <polyline
          points={path((month) => month.profit)}
          fill="none"
          stroke="var(--sa-10)"
          strokeWidth="1.5"
          strokeDasharray="3 2"
        />
        {MONTHS.map((month, index) => (
          <g key={month.label}>
            <circle cx={x(index)} cy={y(month.revenue)} r="2" fill="var(--sa-accent)" />
            <circle cx={x(index)} cy={y(month.profit)} r="2" fill="var(--sa-10)" />
            <text
              x={x(index)}
              y={height - 4}
              textAnchor="middle"
              fill="var(--sa-9)"
              fontSize="13"
              fontFamily="var(--font-mono)"
            >
              {month.label}
            </text>
          </g>
        ))}
      </svg>
    </figure>
  );
}

export const excelStage: Stage = {
  id: 'excel',
  pick: 'Clean Q3 sales and build a dashboard',
  app: 'Calc',
  file: 'Q3_Sales_Challenge.xlsx',
  prompt:
    'Open Q3_Sales_Challenge.xlsx and read Instructions.txt and Checks.txt. Work in a copy named submission/Q3_Sales_Submission.xlsx. Remove duplicate records by Order ID, repair all Revenue and COGS formulas, and fill formulas down. Add Profit and Margin % formulas. Create a Summary sheet with Jul, Aug, and Sep, plus a Grand Total row. Add a line chart comparing monthly Revenue and Profit. Verify the grand totals against Checks.txt.',
  budget: { minutes: 18, steps: 140 },
  steps: [
    // These coordinates are the fallback, for the server render and for a
    // reader without JavaScript. What the pointer actually aims at is the
    // element `targetOf` marks, measured live: the sheet reflows under almost
    // every one of these steps, so a fixed coordinate went stale the moment the
    // pointer set off for it.
    {
      event: 'turn_started',
      label: 'Turn admitted',
      message: `Turn admitted on host win-11-lab, desktop session console`,
      // Top left of the grid: where the work is about to start. Nothing is
      // committed yet, so there is no action here.
      at: { x: 0.091, y: 0.074 },
    },
    {
      event: 'turn_progress',
      label: 'Read the brief',
      message: 'opened Q3_Sales_Challenge.xlsx, read Instructions.txt and Checks.txt',
      // The workbook name in the tab strip, which is the drawn thing this
      // message names and what the pointer is marked onto.
      at: { x: 0.915, y: 0.921 },
      act: 'click',
    },
    {
      event: 'turn_progress',
      label: 'Copy the workbook',
      message: 'saved a working copy as submission/Q3_Sales_Submission.xlsx',
      // Save As enters the copy's name, and the label under the caret becomes
      // it. The label is end-aligned, so its centre moves left as the longer
      // submission path replaces the original name: the pointer is measured
      // against the name it lands on and then stays where it typed.
      at: { x: 0.874, y: 0.921 },
      act: 'type',
    },
    {
      event: 'turn_progress',
      label: 'Remove duplicates',
      message: 'removed 4 duplicate Order ID rows, 30 unique orders remain',
      // Column A of row 5, the first of the repeated IDs. The pointer is
      // marked onto that cell while the duplicates are still on the sheet,
      // which is the layout it crosses; they are gone once it lands.
      at: { x: 0.086, y: 0.236 },
      act: 'drag',
    },
    {
      event: 'turn_progress',
      label: 'Repair formulas',
      message: 'repaired J5 to =F5*G5*(1-I5), filled Revenue and COGS through row 31',
      // Drawn J5: the Revenue cell of row 5, which shows the formula being
      // written and then the repaired figure. The formula bar mirrors the edit
      // and holds the caret, but it sits 17px from the top of the stage, inside
      // the control ring, so it cannot be where the pointer stands.
      at: { x: 0.665, y: 0.236 },
      act: 'type',
    },
    {
      event: 'turn_progress',
      label: 'Add derived columns',
      message: 'added Profit and Margin % formulas in columns L and M',
      // The Profit column header, the first of the two the fill runs across.
      // Placed on the header rather than between the two, which put the drag
      // trail through the right edge of the stage at 390.
      at: { x: 0.851, y: 0.074 },
      act: 'drag',
    },
    {
      event: 'turn_progress',
      label: 'Build the summary',
      message: 'built Summary sheet with Jul, Aug, Sep and a Grand Total row',
      // The new sheet control at the right end of the tab strip. The Summary
      // sheet is not there to be pointed at yet, and its tab would land at the
      // left end of the strip, which the Controller window covers.
      at: { x: 0.735, y: 0.088 },
      act: 'click',
    },
    {
      event: 'turn_progress',
      label: 'Insert the chart',
      message: 'inserted a line chart comparing monthly Revenue and Profit',
      // The Summary pane, which is what holds the chart once it is inserted.
      at: { x: 0.847, y: 0.456 },
      act: 'click',
    },
    {
      event: 'turn_completed',
      label: 'Verify totals',
      message: 'grand totals match Checks.txt, source workbook unchanged',
      // The Grand Total row the checks agree with. A read, so the pointer
      // only moves.
      at: { x: 0.848, y: 0.629 },
    },
  ],
  Render: Sheet,
};
