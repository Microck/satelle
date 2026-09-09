'use client';

import type { ReactNode } from 'react';
import type { Stage, StageProps } from '../stage';
import './filing.css';

/**
 * A court filing being formatted to a style guide, drawn as a US Letter page
 * preview beside the guide's own compliance list.
 *
 * This stage has one job: make *formatting* visible. Body text is therefore
 * drawn as ruled lines rather than as prose, because at page-preview scale the
 * reader has to see the layout change and cannot read the words. Every rule in
 * the list is a line of Court_Style_Guide.txt from the task assets, and the
 * case number 25-CV-0421 is the guide's own. Party names, the county, and the
 * counsel initials are invented but short and plausible; the four section
 * headings are the task's real strings and there is no fake legal prose.
 */

/** Vertical leading of a block. Double is the guide's rule for body text. */
type Lead = 'single' | 'double';

/**
 * Every formatting decision the interior needs, derived from the step gates in
 * one place so each drawn part reads one flag instead of re-deriving it.
 */
type Fmt = {
  margins: boolean;
  headings: boolean;
  twoColumn: boolean;
  runningHead: boolean;
  body: Lead;
  signature: Lead;
};

/**
 * One rule from Court_Style_Guide.txt and the step that lands it. The labels
 * keep the guide's own keys with the values shortened to fit the column, and
 * the last row comes from the prompt's "Do not overwrite the draft".
 */
type Rule = { rule: string; at: number };

const RULES: readonly Rule[] = [
  { rule: 'Paper: US Letter', at: 3 },
  { rule: 'Margins: 1 in all sides', at: 3 },
  { rule: 'Body font: Times New Roman 12 pt', at: 4 },
  { rule: 'Body paragraphs: double-spaced', at: 4 },
  { rule: 'Headings: centered bold caps', at: 5 },
  { rule: 'Caption: two columns', at: 6 },
  { rule: 'Header: 25-CV-0421', at: 7 },
  { rule: 'Footer: centered page number', at: 7 },
  { rule: 'Signature blocks: single-spaced', at: 8 },
  { rule: 'CERTIFICATE OF SERVICE: new page', at: 8 },
  { rule: 'Wording: preserved', at: 9 },
  { rule: 'Output: Motion_to_Compel_FINAL.docx', at: 2 },
  { rule: 'Draft: not overwritten', at: 9 },
];

/** Caption lines: parties on the left, court and case on the right, which is
 *  the shape the guide asks for. Only the case number is a real value. */
const CAPTION_PARTIES = [
  'MERIDIAN LOGISTICS,',
  'Plaintiff,',
  'v.',
  'NORTHGATE FREIGHT,',
  'Defendant.',
];
const CAPTION_COURT = ['SUPERIOR COURT', 'Case No. 25-CV-0421'];

const SIGNATURE = ['Respectfully submitted,', '/s/ A. Reyes', 'Counsel for Plaintiff'];
const CERT_SIGNATURE = ['/s/ A. Reyes', 'Counsel for Plaintiff'];

const DRAFT = 'Motion_to_Compel_DRAFT.docx';
const FINAL = 'submission/Motion_to_Compel_FINAL.docx';

// `reduced` is deliberately unread: every transition in this stage is CSS, and
// the shared reduced-motion rule in landing.css collapses all of them, so the
// interior needs no JavaScript branch to honour the preference.
function Filing({ step }: StageProps) {
  // Step gates. Each one is the state *after* that action commits, so the whole
  // interior is a pure function of one number and stays drivable by a click, a
  // key, or a test.
  const guideRead = step >= 1;
  const copied = step >= 2;
  const margins = step >= 3;
  const bodyType = step >= 4;
  const headings = step >= 5;
  const twoColumn = step >= 6;
  const runningHead = step >= 7;
  // Step 8 lands two of the guide's rules at once: the signature blocks tighten
  // back to single spacing and the certificate moves onto a page of its own.
  const signatureTight = step >= 8;
  const certificateSplit = step >= 8;
  const verified = step >= 9;

  const fmt: Fmt = {
    margins,
    headings,
    twoColumn,
    runningHead,
    body: bodyType ? 'double' : 'single',
    // The blanket double-space at step 4 catches the signature block too, which
    // is why the guide states the single-spacing rule separately and why step 8
    // has something to fix.
    signature: bodyType && !signatureTight ? 'double' : 'single',
  };

  const applied = RULES.filter((rule) => step >= rule.at).length;
  const pages = certificateSplit ? 2 : 1;

  // Spoken description of the drawn page, since the page itself is a diagram
  // and its 8 px text is not meant to be read.
  const pageOneLabel = `Page 1 preview: ${
    margins ? 'US Letter with one inch margins' : 'page setup not applied'
  }, caption in ${twoColumn ? 'two columns' : 'one column'}, headings ${
    headings ? 'centered, bold and uppercase' : 'left aligned in mixed case'
  }, body ${fmt.body}-spaced, signature block ${fmt.signature}-spaced, ${
    runningHead ? 'case number header and centered page number' : 'no header or page number'
  }, ${
    certificateSplit
      ? 'certificate of service moved to page 2'
      : 'certificate of service running on from the signature block'
  }.`;

  return (
    <div className="fl">
      <div className="fl-head">
        <span className="sa-label">Page preview</span>
        <span className="fl-type sa-mono" data-set={bodyType}>
          {bodyType ? 'Times New Roman 12 pt, double-spaced' : 'body type not applied'}
        </span>
        <span className="fl-pagecount sa-mono">{pages === 1 ? '1 page' : '2 pages'}</span>
      </div>

      <div className="fl-body">
        <figure className="sa-scroll fl-sheetwrap">
          <figcaption className="sa-sr">
            Illustrative page preview. Body text is drawn as ruled lines, not as document
            wording. The style guide table carries the same state as text.
          </figcaption>
          <div className="fl-sheet">
            <Page number={1} fmt={fmt} label={pageOneLabel}>
              <Caption fmt={fmt} />
              <Heading text="Motion to Compel" fmt={fmt} />
              <Body lines={2} lead={fmt.body} />
              <Heading text="Argument" fmt={fmt} />
              <Body lines={3} lead={fmt.body} />
              <Heading text="Conclusion" fmt={fmt} />
              <Body lines={2} lead={fmt.body} />
              <Signature lines={SIGNATURE} lead={fmt.signature} />
              {/* Before the break the certificate runs straight on from the
                  signature block, which is the fault the last rule fixes. */}
              {certificateSplit ? null : <Certificate fmt={fmt} />}
            </Page>

            {certificateSplit ? (
              <Page
                number={2}
                fmt={fmt}
                label="Page 2 preview: certificate of service starts the page, centered in bold uppercase, with the case number header and a centered page number."
              >
                <Certificate fmt={fmt} />
              </Page>
            ) : null}
          </div>
        </figure>

        <div className="fl-rules">
          <div className="fl-rules-head">
            <span className="sa-label">Court_Style_Guide.txt</span>
            {guideRead ? (
              <span className="fl-count sa-mono">
                {applied} of {RULES.length} applied
              </span>
            ) : null}
          </div>

          {guideRead ? (
            <table className="fl-grid">
              <caption className="sa-sr">
                Rules from Court_Style_Guide.txt and whether the Turn has applied each one
              </caption>
              <thead>
                <tr>
                  <th scope="col">Rule</th>
                  <th scope="col">State</th>
                </tr>
              </thead>
              <tbody>
                {RULES.map((rule) => {
                  const done = step >= rule.at;
                  return (
                    <tr key={rule.rule} data-done={done}>
                      <th scope="row">{rule.rule}</th>
                      <td className="fl-state">
                        <span className="sa-sr">{done ? 'applied' : 'pending'}</span>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          ) : (
            <p className="fl-unread">Not opened yet.</p>
          )}
        </div>
      </div>

      <div className="fl-foot">
        <span className="sa-label">Editing</span>
        <span className="fl-path">{copied ? FINAL : DRAFT}</span>
        {copied ? (
          <span className="fl-source">
            <span className="sa-label">Draft</span>
            {DRAFT}
            {verified ? <span className="fl-untouched">unchanged</span> : null}
          </span>
        ) : null}
      </div>
    </div>
  );
}

/**
 * One drawn US Letter page. Inside it, one em is 1/34 of the page height, so
 * one inch is exactly 34/11 em and margins, leading, and page furniture are all
 * written in real inches (see filing.css).
 */
function Page({
  number,
  fmt,
  label,
  children,
}: {
  number: number;
  fmt: Fmt;
  label: string;
  children: ReactNode;
}) {
  return (
    <div className="fl-page" data-margins={fmt.margins} role="img" aria-label={label}>
      {fmt.margins ? <span className="fl-guide" /> : null}
      {fmt.runningHead ? <span className="fl-runhead">25-CV-0421</span> : null}
      <div className="fl-content">{children}</div>
      {fmt.runningHead ? <span className="fl-folio">{number}</span> : null}
    </div>
  );
}

/** The case caption. One column in the draft, two once step 6 commits. */
function Caption({ fmt }: { fmt: Fmt }) {
  return (
    <div className="fl-caption" data-columns={fmt.twoColumn ? 2 : 1}>
      <div className="fl-caption-col">
        {CAPTION_PARTIES.map((line) => (
          <span key={line}>{line}</span>
        ))}
      </div>
      <div className="fl-caption-col">
        {CAPTION_COURT.map((line) => (
          <span key={line}>{line}</span>
        ))}
      </div>
    </div>
  );
}

/**
 * A section heading. The document holds the mixed-case wording; the guide's
 * uppercase is a formatting rule, so it is applied with text-transform rather
 * than by rewriting the string, because no wording may change.
 */
function Heading({ text, fmt }: { text: string; fmt: Fmt }) {
  return (
    <p className="fl-heading" data-formatted={fmt.headings}>
      {text}
    </p>
  );
}

/** A body paragraph, drawn as ruled lines so the leading is what shows. */
function Body({ lines, lead }: { lines: number; lead: Lead }) {
  return (
    <div className="fl-para" data-lead={lead}>
      {Array.from({ length: lines }, (_, index) => (
        <span key={index} className="fl-line" data-last={index === lines - 1} />
      ))}
    </div>
  );
}

function Signature({ lines, lead }: { lines: readonly string[]; lead: Lead }) {
  return (
    <div className="fl-sig" data-lead={lead}>
      {lines.map((line) => (
        <span key={line}>{line}</span>
      ))}
    </div>
  );
}

/** The certificate of service: on page 1 before the break, page 2 after it. */
function Certificate({ fmt }: { fmt: Fmt }) {
  return (
    <>
      <Heading text="Certificate of Service" fmt={fmt} />
      <Body lines={2} lead={fmt.body} />
      <Signature lines={CERT_SIGNATURE} lead={fmt.signature} />
    </>
  );
}

export const filingStage: Stage = {
  id: 'filing',
  pick: 'Format a court filing to a style guide',
  app: 'Writer',
  file: 'Motion_to_Compel_DRAFT.docx',
  prompt:
    'Open Motion_to_Compel_DRAFT.docx and follow Court_Style_Guide.txt. Preserve all wording. Format the document on US Letter with one-inch margins, Times New Roman 12 pt body text, double-spaced body paragraphs, centered bold uppercase section headings, a two-column case caption, the case-number header, and centered automatic page numbers. Keep signature blocks single-spaced. Start CERTIFICATE OF SERVICE on a new page. Save the result as submission/Motion_to_Compel_FINAL.docx. Do not overwrite the draft.',
  budget: { minutes: 18, steps: 140 },
  // Pointer targets are fractions of the stage box, measured off the drawn page
  // and the guide pane in a 1440 build. Two shifts matter: the page's text block
  // narrows when the margins land at step 3, so every target inside it moves,
  // and the one page becomes a two page spread at step 8, which re-centres the
  // spread and slides page 1 left. Each `at` is measured in the layout that step
  // commits to, not the layout it starts from.
  steps: [
    {
      event: 'turn_started',
      label: 'Turn admitted',
      message: 'Turn admitted on host win-11-lab, desktop session console',
      // The draft's own title, left aligned and mixed case: the pointer rests on
      // the document as opened, before any rule has been applied to it.
      at: { x: 0.293, y: 0.197 },
    },
    {
      event: 'turn_progress',
      label: 'Read the style guide',
      message: 'opened Motion_to_Compel_DRAFT.docx and read Court_Style_Guide.txt',
      // The pane header naming Court_Style_Guide.txt. The pane under it turns
      // from "Not opened yet." into the rule table as this step commits.
      at: { x: 0.803, y: 0.079 },
      act: 'click',
    },
    {
      event: 'turn_progress',
      label: 'Copy the draft',
      message: 'saved a working copy as submission/Motion_to_Compel_FINAL.docx',
      // Save As types the copy's name. The Editing strip at the foot of the page
      // carries that name, but its start is under the floating Controller
      // window, so the pointer takes the other drawn place the name appears:
      // the guide's own Output rule, which ticks with this step.
      at: { x: 0.818, y: 0.557 },
      act: 'type',
    },
    {
      event: 'turn_progress',
      label: 'Page and margins',
      message: 'set US Letter with 1 inch margins on every side',
      // The left rule of the margin guide, at half its height. The guide's own
      // centre is the middle of the text block, which is not a margin, so the
      // pointer takes the line it drags in.
      at: { x: 0.274, y: 0.304 },
      act: 'drag',
    },
    {
      event: 'turn_progress',
      label: 'Body type and spacing',
      message: 'applied Times New Roman 12 pt and double-spaced the body paragraphs',
      // The three line paragraph under ARGUMENT, the longest body block and so
      // the one whose leading visibly opens up when this step commits.
      at: { x: 0.355, y: 0.287 },
      act: 'click',
    },
    {
      event: 'turn_progress',
      label: 'Center the headings',
      message: 'centered MOTION TO COMPEL, ARGUMENT and CONCLUSION in bold uppercase',
      // The centre line of the text block at the first heading, which is where
      // MOTION TO COMPEL arrives. Before the step it sits to the left of this
      // point, so the heading moves to meet the pointer.
      at: { x: 0.355, y: 0.219 },
      act: 'click',
    },
    {
      event: 'turn_progress',
      label: 'Split the caption',
      message: 'split the caption into two columns, parties left, court right',
      // The middle of the caption block, which is exactly where the rule between
      // the two columns lands, so the pointer ends on the split it pulled.
      at: { x: 0.355, y: 0.144 },
      act: 'drag',
    },
    {
      event: 'turn_progress',
      label: 'Header and page numbers',
      message: 'added the 25-CV-0421 header and centered automatic page numbers',
      // The header strip in the top margin: the case number is the one string
      // this step enters, so the pointer types it where it appears. The centred
      // page number lands in the same action, at the foot of the same page.
      at: { x: 0.421, y: 0.089 },
      act: 'type',
    },
    {
      event: 'turn_progress',
      label: 'Signature and page break',
      message:
        'single-spaced the signature blocks and started CERTIFICATE OF SERVICE on page 2',
      // The top of page 2, where the certificate heading arrives. While the
      // pointer is travelling there is still one page, so this point sits in the
      // empty sheet beside it: the page break opens the page under the click.
      at: { x: 0.469, y: 0.123 },
      act: 'click',
    },
    {
      event: 'turn_completed',
      label: 'Verify and save',
      message:
        'wording unchanged, saved submission/Motion_to_Compel_FINAL.docx, draft untouched',
      // The "Wording: preserved" rule in the compliance list, which is the guide
      // line this step's first claim answers. Nothing is typed or clicked here,
      // so the pointer only reads down the list the Turn is being judged against.
      at: { x: 0.788, y: 0.513 },
    },
  ],
  Render: Filing,
};
