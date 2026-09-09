'use client';

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

function Sheet({ step }: StageProps) {
  // Step gates. Each one is the state *after* that action commits.
  const inSubmission = step >= 2;
  const deduped = step >= 3;
  const repaired = step >= 4;
  const derived = step >= 5;
  const summarised = step >= 6;
  const charted = step >= 7;
  const verified = step >= 8;

  const rows = deduped ? ROWS.filter((row) => !row.duplicate) : ROWS;
  const activeCell = repaired ? 'J5' : step === 3 ? 'A5' : 'A1';
  const formula = repaired
    ? '=F5*G5*(1-I5)'
    : step >= 1
      ? '=F5*G5'
      : '';

  return (
    <div className="xl">
      <div className="xl-bar">
        <span className="xl-cellref sa-mono">{activeCell}</span>
        <span className="xl-formula sa-mono">
          {formula ? (
            <>
              {formula}
              {repaired ? <span className="xl-fixed">repaired</span> : null}
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
                    <th scope="col" key={head}>
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
                    <td>{row.id}</td>
                    <td>{row.region}</td>
                    <td>{row.rep}</td>
                    <td className="xl-wide">{row.product}</td>
                    <td className="xl-num">{row.units}</td>
                    <td className="xl-num">{money(row.price)}</td>
                    <td className="xl-num" data-fixed={row.broken && repaired}>
                      {money(revenue)}
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
          <div className="xl-summary">
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
                <tr className="xl-total">
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
        <span className="xl-file sa-faint">
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
    // Pointer targets are fractions of the stage box, measured off the built
    // page at 1440 with Chromium rather than guessed. Two of them are placed
    // around the Controller window, which sits over the bottom left corner of
    // the Host and hides the left end of the sheet tab strip.
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
      // The workbook name in the tab strip is the drawn thing this message
      // names. The sheet tabs at the other end of the strip are behind the
      // Controller window, so the pointer works the right end of it.
      at: { x: 0.915, y: 0.921 },
      act: 'click',
    },
    {
      event: 'turn_progress',
      label: 'Copy the workbook',
      message: 'saved a working copy as submission/Q3_Sales_Submission.xlsx',
      // Save As enters the copy's name, and the label under the caret becomes
      // it. The label is end-aligned, so its centre moves left as the longer
      // submission path replaces the original name.
      at: { x: 0.874, y: 0.921 },
      act: 'type',
    },
    {
      event: 'turn_progress',
      label: 'Remove duplicates',
      message: 'removed 4 duplicate Order ID rows, 30 unique orders remain',
      // The duplicates are gone by the time this step draws, so the pointer
      // rests where the selection ran: column A of row 5, the cell the
      // reference box names at this step, dragged down the repeated IDs.
      at: { x: 0.086, y: 0.236 },
      act: 'drag',
    },
    {
      event: 'turn_progress',
      label: 'Repair formulas',
      message: 'repaired J5 to =F5*G5*(1-I5), filled Revenue and COGS through row 31',
      // J5 itself: the Revenue cell of row 5, which turns from the broken
      // figure to the repaired one under the caret. The formula bar mirrors the
      // same edit but sits 17px from the top of the stage, inside the control
      // ring, so the typing is shown in the cell.
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
      // The new pane's own Summary heading, on the word rather than the middle
      // of the full-width label. The Summary sheet tab reads the same thing but
      // the Controller window covers it.
      at: { x: 0.735, y: 0.088 },
      act: 'click',
    },
    {
      event: 'turn_progress',
      label: 'Insert the chart',
      message: 'inserted a line chart comparing monthly Revenue and Profit',
      // The plot area, where the inserted chart lands.
      at: { x: 0.847, y: 0.456 },
      act: 'click',
    },
    {
      event: 'turn_completed',
      label: 'Verify totals',
      message: 'grand totals match Checks.txt, source workbook unchanged',
      // The checks against Checks.txt. A read, so the pointer only moves.
      at: { x: 0.848, y: 0.629 },
    },
  ],
  Render: Sheet,
};
