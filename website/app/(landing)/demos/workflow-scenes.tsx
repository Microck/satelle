'use client';

import * as React from 'react';
import { PROMPTS, typed, type Frame } from './exploration-data';
import { DemoCursor } from './workflow-motion';

type SceneProps = { frame: Frame; moving: boolean };
function Typed({ text, frame, step = 0, ms = 1600 }: { text: string; frame: Frame; step?: number; ms?: number }) {
  const value = typed(text, frame, step, ms);
  return <><span className="sw-sr">{text}</span><span aria-hidden="true">{value}<span className="sw-caret" data-typing={value.length < text.length}>▎</span></span></>;
}
function Lights() { return <span className="sw-lights" aria-hidden="true"><i /><i /><i /></span>; }
function Pointer({ frame }: { frame: Frame }) {
  return <DemoCursor target={frame.target} progress={frame.pointer} click={frame.local >= 620 && frame.local < 1000} visible={!frame.done} />;
}
function BrowserBar({ address }: { address: string }) {
  return <div className="sw-browser-bar"><Lights /><span aria-hidden="true">‹ &nbsp; ›</span><span className="sw-address">{address}</span><span aria-hidden="true">↗</span></div>;
}
function Request({ children }: { children: React.ReactNode }) {
  return <div className="sw-request"><span className="sw-request-mark" aria-hidden="true">↗</span><p>{children}</p></div>;
}
export function ToolDetails({ label, input, fields }: { label: string; input: object; fields: object }) {
  return <details className="sw-tool-details"><summary>{label}<span>Inspect example</span></summary><div><p>Arguments</p><pre>{JSON.stringify(input, null, 2)}</pre><p>Selected result fields, not the full response</p><pre>{JSON.stringify(fields, null, 2)}</pre></div></details>;
}

/** A browser-based functional check, not a security scan or a test runner UI. */
export function QaScene({ frame }: SceneProps) {
  const step = frame.committed;
  const checkout = step >= 2;
  const accepted = step >= 4;
  return <div className="sw-qa">
    <Request><Typed text={PROMPTS.qa} frame={frame} ms={1900} /></Request>
    <div className="sw-browser sw-pointer-surface">
      <BrowserBar address={`shop.example / ${accepted ? 'review' : checkout ? 'checkout' : 'shop'}`} />
      <div className="sw-shop-nav"><strong>FORM / GOODS</strong><span data-cursor="qa-checkout">Bag ({step >= 1 ? 1 : 0})</span></div>
      <div className="sw-qa-layout">
        <div className="sw-store">
          {!checkout ? <>
            <div className="sw-product-art" aria-hidden="true"><div className="sw-lamp-shade" /><div className="sw-lamp-stem" /><div className="sw-lamp-foot" /></div>
            <div className="sw-product-line"><div><strong>Studio lamp</strong><span>Warm light. A quieter desk.</span></div><span>$48</span></div>
            <div className="sw-fake-button" data-cursor="qa-add">{step >= 1 ? 'Added to bag ✓' : 'Add to bag'}</div>
          </> : <>
            <span className="sw-mini-label">{accepted ? '02 / REVIEW' : '01 / DETAILS'}</span>
            <h4>{accepted ? 'Review your order' : 'Checkout'}</h4>
            <div className="sw-order-line"><span>Studio lamp × 1</span><strong>$48</strong></div>
            <div className="sw-form-label">Email address</div>
            <div className="sw-fake-input" data-cursor="qa-email">{frame.step === 3 ? typed('not-an-email', frame, 3, 1250) : step >= 3 ? 'not-an-email' : 'you@example.com'}</div>
            {accepted ? <div className="sw-validation-gap">Invalid email accepted. No validation shown.</div> : <div className="sw-form-hint">Order confirmation goes to this address.</div>}
            <div className="sw-fake-button" data-cursor="qa-continue">{accepted ? 'Place order' : 'Continue'}</div>
            <p className="sw-stop-note">Test stops before placing an order.</p>
          </>}
        </div>
        <aside className="sw-qa-notes" aria-label="Illustrative QA observations">
          <div className="sw-mini-label">EXAMPLE QA NOTES</div>
          <strong>Checkout walkthrough</strong>
          <div className="sw-check-row" data-done={step >= 1}><span>{step >= 1 ? '✓' : '○'}</span>Cart updates</div>
          <div className="sw-check-row" data-done={step >= 2}><span>{step >= 2 ? '✓' : '○'}</span>Checkout opens</div>
          <div className="sw-check-row" data-issue={accepted}><span>{accepted ? '!' : '○'}</span>Email validation</div>
          <div className="sw-finding" data-cursor="qa-finding" data-visible={step >= 5}>
            <span className="sw-mini-label">NEEDS REVIEW</span>
            <strong>Invalid email gets through.</strong>
            <p>The checkout accepts “not-an-email” and opens the order review.</p>
            <span className="sw-finding-location">/checkout · Email address</span>
          </div>
        </aside>
      </div>
      <Pointer frame={frame} />
    </div>
  </div>;
}

/** Only configured aliases are listed. config_check does not contact a Host. */
export function ChatScene({ frame }: SceneProps) {
  const step = frame.committed;
  return <div className="sw-chat">
    <div className="sw-chat-bar"><span>Claude Desktop</span><span className="sw-mini-label">SATELLE / MCP</span></div>
    <div className="sw-chat-conversation">
      <div className="sw-chat-user"><Typed text={PROMPTS.hosts} frame={frame} ms={1200} /></div>
      <div className="sw-chat-reply" data-visible={step >= 1}>
        <span className="sw-avatar" aria-hidden="true">C</span><div>
          <span className="sw-tool-line">✓ &nbsp; config_check <span>all: true</span></span>
          {step >= 2 && <div className="sw-reveal"><p>Your configured Hosts:</p><div className="sw-host-list">
            <div><span className="sw-computer" aria-hidden="true">▱</span><strong>studio-mac</strong><span>Configured</span></div>
            <div><span className="sw-computer" aria-hidden="true">▱</span><strong>ops-pc</strong><span>Configured</span></div>
          </div><p className="sw-muted">Configuration found. Live readiness is checked separately.</p></div>}
        </div>
      </div>
      <div className="sw-chat-user sw-second-question" data-visible={frame.step >= 3}><Typed text={PROMPTS.chat} frame={frame} step={3} ms={1850} /></div>
      <div className="sw-chat-reply" data-visible={step >= 4}>
        <span className="sw-avatar" aria-hidden="true">C</span><div>
          <span className="sw-tool-line">✓ &nbsp; run <span>studio-mac · detached</span></span>
          {step >= 5 && <p className="sw-reveal">Task admitted on <strong>studio-mac</strong>. The first Turn is <strong>starting</strong>.</p>}
        </div>
      </div>
    </div>
    <div className="sw-chat-compose"><span>Reply to Claude…</span><span aria-hidden="true">↑</span></div>
    <p className="sw-app-assumption">Example server has mutation tools enabled.</p>
  </div>;
}

/** The same file stays on ops-pc: browser download, native picker, browser upload.
 * The transcript is an illustrated Claude Code conversation, not Satelle logs. */
export function TransferScene({ frame }: SceneProps) {
  const step = frame.committed;
  const destination = step >= 4;
  const picked = step >= 6;
  const uploaded = step >= 8;
  return <div className="sw-transfer">
    <div className="sw-cli-header"><Lights /><strong>Claude Code</strong><span>Satelle MCP</span></div>
    <div className="sw-cli-conversation">
      <div className="sw-cli-prompt"><span aria-hidden="true">›</span><div><Typed text={PROMPTS.transfer} frame={frame} ms={2850} /></div></div>
      <div className="sw-cli-response" data-visible={step >= 1}><span>●</span><div><strong>satelle · run</strong><span>ops-pc · detached admission: starting</span></div></div>
    </div>
    <div className="sw-transfer-host sw-pointer-surface">
      <div className="sw-host-strip"><span>HOST DESKTOP / ops-pc</span><span>Illustrative task</span></div>
      <div className="sw-transfer-tabs"><span data-active={!destination}>Reports</span><span data-active={destination} data-cursor="destination">Finance files</span></div>
      <div className="sw-transfer-address">{destination ? 'files.example / Finance' : 'reports.example / dashboard'}</div>
      {!destination ? <div className="sw-dashboard">
        <aside aria-hidden="true"><strong>ACME</strong><span>Overview</span><span data-cursor="reports" data-active={step >= 2}>Reports</span><span>Settings</span></aside>
        <div className="sw-dashboard-main"><div className="sw-dashboard-title"><h4>{step >= 2 ? 'Monthly reports' : 'Overview'}</h4><span>September</span></div>
          <div className="sw-metric-row"><div><span>Revenue</span><strong>$24,800</strong></div><div><span>Orders</span><strong>312</strong></div></div>
          <div className="sw-report-row"><span>September.csv<small>Monthly summary</small></span><span className="sw-fake-button" data-cursor="download">{step >= 3 ? 'Downloaded ✓' : 'Download'}</span></div>
          <div className="sw-download-tray" data-visible={step >= 3}>↓ &nbsp; Downloads / September.csv</div>
        </div>
      </div> : <div className="sw-files">
        <div className="sw-files-heading"><h4>Finance</h4><span>Team workspace</span></div>
        {uploaded ? <div className="sw-upload-success sw-reveal"><span>✓</span><div><strong>September.csv</strong><p>Upload complete · Finance</p></div></div> : <>
          <div className="sw-dropzone"><span className="sw-file-icon" aria-hidden="true">↥</span><strong>{picked ? 'September.csv' : 'Add the monthly report'}</strong><span>{picked ? 'Selected from Downloads on ops-pc' : 'Choose a file from this computer'}</span><span className="sw-fake-button" data-cursor="choose-file">Choose file</span></div>
          <div className="sw-upload-row"><span>{step >= 7 ? 'Uploading September.csv…' : picked ? 'Ready to upload' : 'No file selected'}</span><span className="sw-fake-button" data-cursor="upload">Upload</span></div>
          {step >= 7 && <div className="sw-upload-progress"><i style={{ width: `${frame.step > 7 ? 100 : Math.min(100, Math.max(0, frame.local - 720) / 9)}%` }} /></div>}
        </>}
        {step === 5 && <div className="sw-file-picker sw-reveal"><div className="sw-picker-title">Open <span>Downloads</span></div><div className="sw-picker-file" data-cursor="local-file"><span>▤</span><strong>September.csv</strong><span>CSV file</span></div><div className="sw-picker-bottom"><span>On ops-pc</span><span className="sw-fake-button">Open</span></div></div>}
      </div>}
      <Pointer frame={frame} />
    </div>
  </div>;
}

function Landscape({ mountains = false }: { mountains?: boolean }) {
  return <div className={`sw-landscape ${mountains ? 'sw-mountains' : 'sw-dunes'}`} aria-hidden="true"><i /><i /><i /></div>;
}
/** Generic macOS illustration. No permissions dialog is approved by the demo. */
export function WallpaperScene({ frame }: SceneProps) {
  const step = frame.committed;
  const changed = step >= 3;
  const settings = step >= 1 && step < 4;
  return <div className="sw-wallpaper">
    <Request><Typed text={PROMPTS.wallpaper} frame={frame} ms={1850} /></Request>
    <div className="sw-mac sw-pointer-surface" data-changed={changed}>
      <Landscape /><div className="sw-new-wallpaper" style={{ opacity: frame.step === 3 ? Math.min(1, Math.max(0, frame.local - 720) / 650) : changed ? 1 : 0 }}><Landscape mountains /></div>
      <div className="sw-mac-menu"><strong>{settings ? 'System Settings' : 'Finder'}</strong><span>File</span><span>Edit</span><span>View</span><span className="sw-mac-host">studio-mac</span></div>
      <div className="sw-desktop-label" data-visible={!settings}><span>YOUR HOST / macOS</span><strong>{changed ? 'A different view.' : 'Your everyday desktop.'}</strong></div>
      {settings && <div className="sw-settings sw-reveal">
        <div className="sw-settings-title"><span data-cursor="close-settings"><Lights /></span><strong>System Settings</strong></div>
        <div className="sw-settings-content"><aside><span>Appearance</span><span>Desktop &amp; Dock</span><span data-cursor="wallpaper" data-active={step >= 2}>Wallpaper</span></aside>
          <div className="sw-wallpaper-options"><h4>{step >= 2 ? 'Wallpaper' : 'Appearance'}</h4>{step >= 2 ? <><span className="sw-muted">Choose your desktop background.</span><div className="sw-wallpaper-thumbnails"><div><Landscape /><span>Dunes</span></div><div data-cursor="mountains" data-selected={changed}><Landscape mountains /><span>Mountains {changed ? '✓' : ''}</span></div></div><p className="sw-current-wallpaper">Current: {changed ? 'Mountains' : 'Dunes'}</p></> : <><div className="sw-appearance-options"><span>Light</span><span>Dark</span><span>Auto</span></div><p className="sw-muted">Choose Wallpaper in the sidebar.</p></>}</div>
        </div>
      </div>}
      <div className="sw-mac-dock" aria-hidden="true"><span>▣</span><span>◎</span><span>▤</span><span data-cursor="settings">⚙</span></div>
      <div className="sw-wallpaper-result" data-visible={step >= 5}>✓ &nbsp; Wallpaper changed on studio-mac</div>
      <Pointer frame={frame} />
    </div>
  </div>;
}
