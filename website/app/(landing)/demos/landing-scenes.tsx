'use client';
import * as React from 'react';
import { CHAT_MESSAGES, CLAWD, COMMIT_DELAY, DRAG_DURATION, PHOTO_FILE, PROMPTS, REPORT_FILE, SITES, ease, messagePop, phase, qaWidth, typed, type SceneProps } from './exploration-data';
import { Brand, Icon, Lights, Photo } from './workflow-ui';
import { GestureCursor } from './workflow-gesture';

function Titlebar({ children, controls }: { children: React.ReactNode; controls?: React.ReactNode }) {
  return <div className="rf-titlebar"><Lights /><span>{children}</span>{controls}</div>;
}
function Request({ children }: { children: React.ReactNode }) { return <div className="rf-request"><span>↗</span><p>{children}</p></div>; }
function FakeButton({ target, children, primary = false }: { target?: string; children: React.ReactNode; primary?: boolean }) {
  return <span className="rf-button" data-primary={primary} data-cursor={target}>{children}</span>;
}

/** A seeded local storefront: visibly broken CSS, not an allegation about a
 * real third-party website. The browser frame, not the user's page, is resized. */
export function ResponsiveQaScene({ frame, moving }: SceneProps) {
  const width = qaWidth(frame);
  const narrow = width < 76;
  const reproduced = frame.committed >= 6;
  return <div className="wf-stage rf-stage rf-qa">
    <Request>{typed(PROMPTS.qa, frame, 0, 2000)}</Request>
    <div className="rf-desktop-label"><Icon name="monitor" /><span>studio-mac · browser QA</span><small>{narrow ? 'Narrow window' : 'Wide window'}</small></div>
    <div className="rf-qa-area">
      <div className="rf-resize-browser" style={{ width: `${width}%` }} data-narrow={narrow}>
        <Titlebar>{SITES.qa}</Titlebar>
        <div className="rf-storefront"><div className="rf-store-nav"><b>FORM / GOODS</b><span>Shop &nbsp; About &nbsp; Bag</span></div>
          <div className="rf-product"><div className="rf-lamp"><i /><i /><i /></div><div className="rf-product-copy"><small>THE DESK COLLECTION</small><h4>A quieter workspace.</h4><p>Studio lamp · soft, focused light.</p></div></div>
          <div className="rf-buy-viewport" data-broken={narrow}><div className="rf-buy-row"><span>Studio lamp <b>$48</b></span><span className="rf-buy-button">Add to bag →</span></div></div>
          <p className="rf-fixture-caption">Your storefront · seeded QA fixture</p>
        </div>
        <span className="rf-resize-handle" data-cursor="qa-resize">◢</span>
      </div>
      <span className="rf-resize-end rf-end-narrow" data-cursor="qa-narrow" />
      <span className="rf-resize-end rf-end-wide" data-cursor="qa-wide" />
      <div className="rf-overflow-callout" style={{ visibility: narrow ? 'visible' : 'hidden' }}><span>←</span><b>Clipped<br />button</b></div>
    </div>
    <div className="rf-qa-finding" data-found={narrow}><small>{narrow ? 'ISSUE FOUND · RESPONSIVE LAYOUT' : 'RESPONSIVE QA'}</small><strong>{narrow ? 'The purchase button leaves the viewport.' : 'Checking the same page at different widths.'}</strong><p>{reproduced ? 'Reproduced: wide → narrow. The fixed-width row clips the call to action.' : narrow ? 'The row stays wide when the browser gets narrow.' : 'The cursor drags the actual browser edge.'}</p></div>
    <GestureCursor frame={frame} moving={moving} />
  </div>;
}

/** Append complete messages. Deterministic scroll keeps the newest reply in
 * view and freezes with Pause. No typing, opacity transition or sidebar. */
class Conversation extends React.Component<SceneProps & { children: React.ReactNode }> {
  private viewport: HTMLDivElement | null = null;
  private content: HTMLDivElement | null = null;
  private target = 0;
  private from = 0;
  private changedAt = 0;
  private previous = -1;
  private observer?: ResizeObserver;
  componentDidMount() {
    this.scroll();
    if (typeof ResizeObserver !== 'undefined' && this.viewport && this.content) {
      this.observer = new ResizeObserver(() => this.scroll(!this.props.moving));
      this.observer.observe(this.viewport);
      this.observer.observe(this.content);
    }
  }
  componentWillUnmount() { this.observer?.disconnect(); }
  componentDidUpdate() { this.scroll(); }
  private scroll(resized = false) {
    if (!this.viewport || !this.content) return;
    const elapsed = this.props.frame.elapsed;
    const target = Math.max(0, this.content.scrollHeight - this.viewport.clientHeight);
    if (resized || this.previous < 0 || elapsed < this.previous || (!this.props.moving && elapsed !== this.previous)) {
      this.viewport.scrollTop = target; this.from = target; this.target = target; this.changedAt = elapsed;
    } else {
      if (target !== this.target) { this.from = this.viewport.scrollTop; this.target = target; this.changedAt = elapsed; }
      this.viewport.scrollTop = this.from + (this.target - this.from) * ease(Math.min(1, Math.max(0, (elapsed - this.changedAt) / 320)));
    }
    this.previous = elapsed;
  }
  render() { return <div className="rf-chat-scroll" ref={node => { this.viewport = node; }}><div className="rf-chat-thread" ref={node => { this.content = node; }}>{this.props.children}</div></div>; }
}
export function SimpleChatScene({ frame, moving }: SceneProps) {
  return <div className="wf-stage rf-stage rf-chat">
    <header className="rf-chat-title"><Lights /><Brand name="chatgpt" /><b>ChatGPT</b><small>Concept</small></header>
    <Conversation frame={frame} moving={moving}>
      {CHAT_MESSAGES.filter(message => message.step <= frame.committed).map(message => <div key={message.step} className={`rf-message rf-${message.role}`} data-message={message.step} style={messagePop(frame, message.step)}>
        {message.role === 'assistant' && <Brand name="chatgpt" />}
        <div>{'tool' in message && <small>{message.tool}</small>}<p>{message.text}</p>{'file' in message && <div className="rf-chat-file"><Icon name="file" /><span>launch-brief.pdf<small>Saved on studio-mac</small></span><b>✓</b></div>}</div>
      </div>)}
    </Conversation>
    <div className="rf-composer"><span>Message ChatGPT…</span><span>＋ &nbsp; ↑</span></div>
  </div>;
}

/** Draw the compact Unicode block cells as SVG quadrants. This preserves the
 * classic Clawd silhouette without relying on a fallback font for block art. */
export function Clawd() {
  const quadrants: Record<string, number[]> = { '█': [0,1,2,3], '▐': [1,3], '▛': [0,1,2], '▜': [0,1,3], '▌': [0,2], '▝': [1], '▘': [0] };
  return <svg className="rf-clawd" viewBox="0 0 80 48" shapeRendering="crispEdges" role="img" aria-label="Classic Clawd terminal mascot">{CLAWD.split('\n').flatMap((line, y) => Array.from(line).flatMap((glyph, x) => (quadrants[glyph] ?? []).map(q => <rect key={`${x}-${y}-${q}`} x={x * 10 + (q % 2) * 5} y={y * 16 + Math.floor(q / 2) * 8} width="5" height="8" fill="currentColor" />)))}</svg>;
}
function Terminal({ frame }: SceneProps) {
  return <div className="rf-terminal">
    <Titlebar controls={<span className="rf-native-controls"><span data-cursor="terminal-minimize">−</span><span>□</span><span>×</span></span>}>Claude Code — ~/reports</Titlebar>
    <div className="rf-terminal-body"><div className="rf-welcome"><Clawd /><div><b>Claude Code</b><small>Welcome back!</small><small>~/reports</small></div></div>
      <div className="rf-terminal-prompt"><b>❯</b><span>{typed(PROMPTS.transfer, frame, 0, 2900)}</span></div>
      {frame.committed >= 1 && <div className="rf-terminal-result"><p>● <b>satelle - run (MCP)</b></p><p>　(host: "ops-pc", detach: true)</p><p>　⎿ status: starting</p><small>Selected result · task admitted</small></div>}
      <div className="rf-terminal-input">❯ <span>▌</span></div><small className="rf-terminal-hint">{frame.committed >= 1 ? 'esc to interrupt' : '? for shortcuts'}</small>
    </div>
  </div>;
}
function Analytics({ c }: { c: number }) {
  return <div className="rf-app-body"><div className="rf-app-heading"><Brand name="analytics" /><h4>Traffic acquisition</h4><FakeButton target="ga-export">Export ↗</FakeButton></div>
    <small className="rf-app-subtitle">Google Analytics · last month · sample data</small>
    <div className="rf-metrics"><div><small>Sessions</small><strong>12,480</strong></div><div><small>Engaged sessions</small><strong>9,210</strong></div></div>
    <div className="rf-report-chart"><svg viewBox="0 0 400 95" preserveAspectRatio="none"><path d="M0 25H400M0 65H400" stroke="var(--sa-6)" /><path d="m0 75 35-15 30 9 35-33 35 15 35-22 30 14 40-26 40 13 35-18 50 4" fill="none" stroke="var(--sa-11)" strokeWidth="2" /></svg></div>
    <div className="rf-file-row"><Icon name="file" /><span>{REPORT_FILE}</span><small>CSV</small></div>
    {c === 3 && <div className="rf-menu rf-export-menu"><b>Download file</b><span data-cursor="ga-csv">CSV <Icon name="download" /></span><span>PDF</span></div>}
    {c >= 4 && <div className="rf-status-note">✓ &nbsp; Saved to Downloads on ops-pc</div>}
  </div>;
}
function FilePicker({ kind, selected, pictures = true }: { kind: 'report' | 'photo'; selected: boolean; pictures?: boolean }) {
  return <div className="rf-picker"><Titlebar>Open file</Titlebar><div className="rf-picker-path"><Icon name="folder" />{kind === 'report' ? 'Downloads' : pictures ? 'Pictures' : 'Recents'}</div><div className="rf-picker-content"><aside><span>Desktop</span><span>Downloads</span><span data-cursor="slack-pictures" data-active={kind === 'photo' && pictures}>Pictures</span></aside><div>
    {kind === 'report' ? <div className="rf-picker-file" data-cursor="transfer-file" data-selected={selected}><Icon name="file" /><span>{REPORT_FILE}</span></div> : pictures ? <div className="rf-picker-photo" data-cursor="slack-file" data-selected={selected}><Photo /><span>{PHOTO_FILE}</span></div> : <p className="rf-picker-empty">Choose your photo from Pictures.</p>}
  </div></div><footer><FakeButton>Cancel</FakeButton><FakeButton primary target={kind === 'report' ? 'transfer-open' : 'slack-open'}>Open</FakeButton></footer></div>;
}
function Drive({ frame }: SceneProps) {
  const c = frame.committed;
  return <div className="rf-app-body"><div className="rf-app-heading"><Brand name="drive" /><h4>My Drive {c >= 6 && <span> / Reports</span>}</h4><FakeButton target="drive-new">＋ New</FakeButton></div><small className="rf-app-subtitle">Google Drive · sample account</small>
    <div className="rf-drive-list"><small>Name</small>{c < 6 ? <div className="rf-file-row" data-cursor="drive-folder"><Icon name="folder" /><b>Reports</b><span>›</span></div> : c < 10 ? <p className="rf-empty">Upload the monthly report here.</p> : <div className="rf-file-row rf-delivered"><Icon name="file" /><b>{REPORT_FILE}</b><span>✓</span></div>}</div>
    {c === 7 && <div className="rf-menu rf-new-menu"><span>New folder</span><span data-cursor="drive-upload"><Icon name="upload" /> File upload</span></div>}
    {c >= 8 && c <= 9 && <div className="rf-modal-layer"><FilePicker kind="report" selected={c >= 9} /></div>}
    {c >= 10 && <div className="rf-upload-note"><Icon name="file" /><span>{c >= 11 ? 'Upload complete' : 'Uploading report…'}</span><b>{c >= 11 ? '✓' : ''}</b><i><i style={{ width: `${100 * phase(frame, 10, 1100, COMMIT_DELAY)}%` }} /></i></div>}
  </div>;
}
export function CompactTransferScene({ frame, moving }: SceneProps) {
  const minimize = ease(phase(frame, 2, 900, COMMIT_DELAY));
  const c = frame.committed;
  // Collapse into the matching taskbar item, at full opacity. The click must
  // land first; only then does the browser underneath become exposed.
  return <div className="wf-stage rf-stage rf-transfer">
    <div className="rf-host-browser"><Titlebar>ops-pc · Host browser</Titlebar><div className="rf-tabs"><span data-active={c < 5}>Analytics</span><span data-active={c >= 5} data-cursor="drive-tab">Google Drive</span></div><div className="rf-url">{c >= 5 ? SITES.drive : SITES.analytics}</div>{c >= 5 ? <Drive frame={frame} moving={moving} /> : <Analytics c={c} />}</div>
    <div className="rf-taskbar"><span className="rf-taskbar-terminal">❯ &nbsp;Claude Code</span><span>ops-pc</span></div>
    <div className="rf-terminal-layer" data-minimized={minimize === 1} style={{ visibility: minimize === 1 ? 'hidden' : 'visible', transform: `translate(calc(${minimize} * (88px - 50%)), calc(${minimize} * (50% + 14.5px))) scale(${1 - minimize * 0.87}, ${1 - minimize * 0.965})` }}><Terminal frame={frame} moving={moving} /></div>
    <GestureCursor frame={frame} moving={moving} />
  </div>;
}

function Profile({ saved }: { saved: boolean }) {
  return <div className="rf-profile"><div className="rf-profile-heading"><h4>Your profile</h4><FakeButton target="slack-edit">Edit</FakeButton></div><div className="rf-profile-avatar"><Photo variant={saved ? 'new' : 'old'} /></div><b>You</b><small>Active · Satelle workspace</small>{saved && <div className="rf-status-note">✓ &nbsp; Profile photo updated</div>}</div>;
}
function EditProfile({ saved }: { saved: boolean }) {
  return <div className="rf-edit-profile"><h4>Edit your profile</h4><div><div className="rf-profile-avatar"><Photo variant={saved ? 'new' : 'old'} /></div><div><small>Profile photo</small><FakeButton target="slack-upload">Upload Photo</FakeButton><small>PNG, JPG or GIF</small></div></div><footer><FakeButton>Cancel</FakeButton><FakeButton primary target="slack-save">Save Changes</FakeButton></footer></div>;
}
function Crop({ frame }: SceneProps) {
  const progress = ease(phase(frame, 8, DRAG_DURATION, COMMIT_DELAY));
  return <div className="rf-crop"><h4>Crop your photo</h4><div className="rf-crop-preview"><div style={{ transform: `scale(${1 + progress * 0.2})` }}><Photo /></div><i /></div><div className="rf-crop-slider"><span>−</span><div><i style={{ width: `${35 + progress * 30}%` }} /><b data-cursor="slack-crop" style={{ left: `${35 + progress * 30}%` }} /><b className="rf-endpoint" data-cursor="slack-crop-end" style={{ left: '65%' }} /></div><span>＋</span></div><footer><FakeButton>Cancel</FakeButton><FakeButton primary target="slack-crop-save">Save</FakeButton></footer></div>;
}
export function CompactSlackScene({ frame, moving }: SceneProps) {
  const c = frame.committed;
  return <div className="wf-stage rf-stage rf-slack">
    <header className="rf-slack-title"><Lights /><Brand name="slack" /><b>Slack</b><small>Satelle workspace</small></header>
    <div className="rf-slack-layout"><aside><span><Icon name="home" />Home</span><span><Icon name="chat" />DMs</span><div data-cursor="slack-account" className="rf-account"><Photo variant={c >= 10 ? 'new' : 'old'} /></div></aside><div className="rf-slack-main">
      {c < 2 ? <><div className="rf-channel-title"># design</div><div className="rf-slack-prompt"><small>Task on studio-mac</small><p>{typed(PROMPTS.slack, frame, 0, 1800)}</p></div><div className="rf-slack-composer">Message #design</div></> : <Profile saved={c >= 10} />}
    </div></div>
    {c === 1 && <div className="rf-menu rf-account-menu"><b>You · active</b><span data-cursor="slack-profile">Profile</span><span>Preferences</span></div>}
    {c >= 3 && c < 10 && <div className="rf-modal-layer"><EditProfile saved={c >= 9} /></div>}
    {c >= 4 && c <= 6 && <div className="rf-modal-layer rf-front"><FilePicker kind="photo" selected={c >= 6} pictures={c >= 5} /></div>}
    {c >= 7 && c <= 8 && <div className="rf-modal-layer rf-front"><Crop frame={frame} moving={moving} /></div>}
    <GestureCursor frame={frame} moving={moving} />
  </div>;
}
