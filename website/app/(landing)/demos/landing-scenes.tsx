'use client';
import * as React from 'react';
import * as data from './exploration-data';
import * as ui from './workflow-ui';
import * as gestures from './workflow-gesture';
import * as mark from '../mark';
function Titlebar({ children, controls }: { children: React.ReactNode; controls?: React.ReactNode }) {
    return <div className="rf-titlebar">
        <ui.Lights />
        <span>{children}</span>{controls}</div>;
}
function Request({ children }: { children: React.ReactNode }) {
    return <div className="rf-request">
        <span>{"\u2197"}</span>
        <p>{children}</p>
        </div>;
}
function FakeButton({ target, children, primary = false }: { target?: string; children: React.ReactNode; primary?: boolean }) {
    return <span className="rf-button" data-primary={primary} data-cursor={target}>{children}</span>;
}
/** A seeded local storefront: visibly broken CSS, not a claim about a real
 * third-party site. Only the browser inside the demo is resized. */
export function ResponsiveQaScene({ frame, moving }: data.SceneProps) {
    const width = data.qaWidth(frame);
    const narrow = width < 76;
    const reproduced = frame.committed >= 6;
    return <div className="wf-stage rf-stage rf-qa" data-fixture="seeded-responsive-storefront">
        <Request>{data.typed(data.PROMPTS.qa, frame, 0, 2000)}</Request>
        <div className="rf-desktop-label">
        <ui.Icon name="monitor"/>
        <span>{"studio-mac \u00B7 browser QA"}</span>
        <small>{narrow ? 'Narrow window' : 'Wide window'}</small>
        </div>
        <div className="rf-qa-area">
        <div className="rf-resize-browser" style={{ width: `${width}%` }} data-narrow={narrow}>
        <Titlebar>{data.SITES.qa}</Titlebar>
        <div className="rf-storefront">
        <div className="rf-store-nav">
        <b>{"FORM / GOODS"}</b>
        <span>{"Shop \u00A0 About \u00A0 Bag"}</span>
        </div>
        <div className="rf-product">
        <div className="rf-lamp">
        <i />
        <i />
        <i />
        </div>
        <div className="rf-product-copy">
        <small>{"THE DESK COLLECTION"}</small>
        <h4>{"A quieter workspace."}</h4>
        <p>{"Studio lamp \u00B7 soft, focused light."}</p>
        </div>
        </div>
        <div className="rf-buy-viewport" data-broken={narrow}>
        <div className="rf-buy-row">
        <span>{"Studio lamp "}<b>{"$48"}</b>
        </span>
        <span className="rf-buy-button">{"Add to bag \u2192"}</span>
        </div>
        </div>
        </div>
        <span className="rf-resize-handle" data-cursor="qa-resize">{"\u25E2"}</span>
        </div>
        <span className="rf-resize-end rf-end-narrow" data-cursor="qa-narrow"/>
        <span className="rf-resize-end rf-end-wide" data-cursor="qa-wide"/>
        <div className="rf-overflow-callout" style={{ visibility: narrow ? 'visible' : 'hidden' }}>
        <span>{"\u2190"}</span>
        <b>{"Clipped"}<br />{"button"}</b>
        </div>
        </div>
        <div className="rf-qa-finding" data-found={narrow}>
        <small>{narrow ? 'ISSUE FOUND · RESPONSIVE LAYOUT' : 'RESPONSIVE QA'}</small>
        <strong>{narrow ? 'The purchase button leaves the viewport.' : 'Checking the same page at different widths.'}</strong>
        <p>{reproduced ? 'Reproduced: wide → narrow. The fixed-width row clips the call to action.' : narrow ? 'The row stays wide when the browser gets narrow.' : 'The cursor drags the actual browser edge.'}</p>
        </div>
        <gestures.GestureCursor frame={frame} moving={moving}/>
        </div>;
}
/** Append whole messages, and scroll with the same clock as the animation. */
class Conversation extends React.Component<data.SceneProps & { children: React.ReactNode }> {
    private observer?: ResizeObserver;
    private viewport: HTMLDivElement | null = null;
    private content: HTMLDivElement | null = null;
    target = 0;
    from = 0;
    changedAt = 0;
    previous = -1;
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
    scroll(resized = false) {
        if (!this.viewport || !this.content)
            return;
        const elapsed = this.props.frame.elapsed;
        const target = Math.max(0, this.content.scrollHeight - this.viewport.clientHeight);
        if (resized || this.previous < 0 || elapsed < this.previous || (!this.props.moving && elapsed !== this.previous)) {
            this.viewport.scrollTop = target;
            this.from = target;
            this.target = target;
            this.changedAt = elapsed;
        }
        else {
            if (target !== this.target) {
                this.from = this.viewport.scrollTop;
                this.target = target;
                this.changedAt = elapsed;
            }
            this.viewport.scrollTop = this.from + (this.target - this.from) * data.ease(Math.min(1, Math.max(0, (elapsed - this.changedAt) / 320)));
        }
        this.previous = elapsed;
    }
    render() {
        return <div className="rf-chat-scroll" ref={node => { this.viewport = node; }}>
        <div className="rf-chat-thread" ref={node => { this.content = node; }}>{this.props.children}</div>
        </div>;
    }
}
function McpActivityCard({ activity, step, frame }: { activity: data.McpActivity; step: number; frame: data.Frame }) {
    const running = activity.state === 'running';
    const live = running && frame.committed === step;
    const rotation = live ? Math.max(0, frame.elapsed - data.COMMIT_DELAY) / 4 % 360 : 0;
    return <div className="rf-mcp-activity" data-mcp-state={activity.state}>
        <div className="rf-mcp-heading">
        <span className="rf-mcp-logo">
        <mark.Mark size={21}/>
        </span>
        <b>{"Satelle "}<small>{"MCP"}</small>
        </b>
        <span className="rf-mcp-state">{running ? <svg width="13" height="13" viewBox="0 0 16 16" fill="none" style={{ transform: `rotate(${rotation}deg)` }}>
        <circle cx="8" cy="8" r="5.5" stroke="var(--sa-7)"/>
        <path d="M8 2.5a5.5 5.5 0 0 1 5.5 5.5" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round"/>
        </svg> : <ui.Icon name="check" size={13}/>}{activity.state}</span>
        </div>
        <div className="rf-mcp-detail">
        <span>{activity.action}</span>
        <span className="rf-mcp-tools">{activity.tools.map(tool => <code key={tool}>{tool}</code>)}</span>
        </div>
        </div>;
}
export function SimpleChatScene({ frame, moving }: data.SceneProps) {
    return <div className="wf-stage rf-stage rf-chat">
        <header className="rf-chat-title">
        <ui.Lights />
        <ui.Brand name="chatgpt"/>
        <b>{"ChatGPT"}</b>
        <small title="Design concept: a compatible remote MCP bridge is not included in Satelle.">{"Concept"}</small>
        </header>
        <Conversation frame={frame} moving={moving}>{data.CHAT_MESSAGES.filter(message => message.step <= frame.committed).map(message => <div key={message.step} className={`rf-message rf-${message.role}`} data-message={message.step} style={data.messagePop(frame, message.step)}>{message.role === 'assistant' && <ui.Brand name="chatgpt"/>}<div>{'tool' in message && <McpActivityCard activity={data.MCP_ACTIVITIES[message.step]} step={message.step} frame={frame}/>}<p>{message.text}</p>{'file' in message && <div className="rf-chat-file">
        <ui.Icon name="file"/>
        <span>{"launch-brief.pdf"}<small>{"Saved on studio-mac"}</small>
        </span>
        <b>{"\u2713"}</b>
        </div>}</div>
        </div>)}</Conversation>
        <div className="rf-composer">
        <span>{"Message ChatGPT\u2026"}</span>
        <span>{"\uFF0B \u00A0 \u2191"}</span>
        </div>
        </div>;
}
/** Classic Unicode block cells rendered independently of fallback font spacing. */
export function Clawd() {
    const quadrants: Record<string, number[]> = { '█': [0, 1, 2, 3], '▐': [1, 3], '▛': [0, 1, 2], '▜': [0, 1, 3], '▌': [0, 2], '▝': [1], '▘': [0] };
    return <svg className="rf-clawd" viewBox="0 0 80 48" shapeRendering="crispEdges" role="img" aria-label="Classic Clawd terminal mascot">{data.CLAWD.split('\n').flatMap((line, y) => Array.from(line).flatMap((glyph, x) => (quadrants[glyph] ?? []).map(q => <rect key={`${x}-${y}-${q}`} x={x * 10 + (q % 2) * 5} y={y * 16 + Math.floor(q / 2) * 8} width="5" height="8" fill="currentColor"/>)))}</svg>;
}
function Terminal({ frame }: data.SceneProps) {
    return <div className="rf-terminal">
        <Titlebar controls={<span className="rf-native-controls">
        <span data-cursor="terminal-minimize">{"\u2212"}</span>
        <span>{"\u25A1"}</span>
        <span>{"\u00D7"}</span>
        </span>}>{"Claude Code \u2014 ~/reports"}</Titlebar>
        <div className="rf-terminal-body">
        <div className="rf-welcome">
        <Clawd />
        <div>
        <b>{"Claude Code"}</b>
        <small>{"Welcome back!"}</small>
        <small>{"~/reports"}</small>
        </div>
        </div>
        <div className="rf-terminal-prompt">
        <b>{"\u276F"}</b>
        <span>{data.typed(data.PROMPTS.transfer, frame, 0, 2900)}</span>
        </div>{frame.committed >= 1 && <div className="rf-terminal-result">
        <p>{"\u25CF "}<b>{"satelle - run (MCP)"}</b>
        </p>
        <p>{"\u3000(host: \"ops-pc\", detach: true)"}</p>
        <p>{"\u3000\u23BF status: starting"}</p>
        <small>{"Selected result \u00B7 task admitted"}</small>
        </div>}<div className="rf-terminal-input">{"\u276F "}<span>{"\u258C"}</span>
        </div>
        <small className="rf-terminal-hint">{frame.committed >= 1 ? 'esc to interrupt' : '? for shortcuts'}</small>
        </div>
        </div>;
}
function Analytics({ c }: { c: number }) {
    return <div className="rf-app-body">
        <div className="rf-app-heading">
        <ui.Brand name="analytics"/>
        <h4>{"Traffic acquisition"}</h4>
        <FakeButton target="ga-export">{"Export \u2197"}</FakeButton>
        </div>
        <small className="rf-app-subtitle">{"Google Analytics \u00B7 last month \u00B7 sample data"}</small>
        <div className="rf-metrics">
        <div>
        <small>{"Sessions"}</small>
        <strong>{"12,480"}</strong>
        </div>
        <div>
        <small>{"Engaged sessions"}</small>
        <strong>{"9,210"}</strong>
        </div>
        </div>
        <div className="rf-report-chart">
        <svg viewBox="0 0 400 95" preserveAspectRatio="none">
        <path d="M0 25H400M0 65H400" stroke="var(--sa-6)"/>
        <path d="m0 75 35-15 30 9 35-33 35 15 35-22 30 14 40-26 40 13 35-18 50 4" fill="none" stroke="var(--sa-11)" strokeWidth="2"/>
        </svg>
        </div>
        <div className="rf-file-row">
        <ui.Icon name="file"/>
        <span>{data.REPORT_FILE}</span>
        <small>{"CSV"}</small>
        </div>{c === 3 && <div className="rf-menu rf-export-menu">
        <b>{"Download file"}</b>
        <span data-cursor="ga-csv">{"CSV "}<ui.Icon name="download"/>
        </span>
        <span>{"PDF"}</span>
        </div>}{c >= 4 && <div className="rf-status-note">{"\u2713 \u00A0 Saved to Downloads on ops-pc"}</div>}</div>;
}
function FilePicker({ kind, selected, pictures = true }: { kind: 'report' | 'photo'; selected: boolean; pictures?: boolean }) {
    return <div className="rf-picker">
        <Titlebar>{"Open file"}</Titlebar>
        <div className="rf-picker-path">
        <ui.Icon name="folder"/>{kind === 'report' ? 'Downloads' : pictures ? 'Pictures' : 'Recents'}</div>
        <div className="rf-picker-content">
        <aside>
        <span>{"Desktop"}</span>
        <span>{"Downloads"}</span>
        <span data-cursor="slack-pictures" data-active={kind === 'photo' && pictures}>{"Pictures"}</span>
        </aside>
        <div>{kind === 'report' ? <div className="rf-picker-file" data-cursor="transfer-file" data-selected={selected}>
        <ui.Icon name="file"/>
        <span>{data.REPORT_FILE}</span>
        </div> : pictures ? <div className="rf-picker-photo" data-cursor="slack-file" data-selected={selected}>
        <ui.Photo />
        <span>{data.PHOTO_FILE}</span>
        </div> : <p className="rf-picker-empty">{"Choose your photo from Pictures."}</p>}</div>
        </div>
        <footer>
        <FakeButton>{"Cancel"}</FakeButton>
        <FakeButton primary={true} target={kind === 'report' ? 'transfer-open' : 'slack-open'}>{"Open"}</FakeButton>
        </footer>
        </div>;
}
function Drive({ frame }: data.SceneProps) {
    const c = frame.committed;
    return <div className="rf-app-body">
        <div className="rf-app-heading">
        <ui.Brand name="drive"/>
        <h4>{"My Drive "}{c >= 6 && <span>{" / Reports"}</span>}</h4>
        <FakeButton target="drive-new">{"\uFF0B New"}</FakeButton>
        </div>
        <small className="rf-app-subtitle">{"Google Drive \u00B7 sample account"}</small>
        <div className="rf-drive-list">
        <small>{"Name"}</small>{c < 6 ? <div className="rf-file-row" data-cursor="drive-folder">
        <ui.Icon name="folder"/>
        <b>{"Reports"}</b>
        <span>{"\u203A"}</span>
        </div> : c < 10 ? <p className="rf-empty">{"Upload the monthly report here."}</p> : <div className="rf-file-row rf-delivered">
        <ui.Icon name="file"/>
        <b>{data.REPORT_FILE}</b>
        <span>{"\u2713"}</span>
        </div>}</div>{c === 7 && <div className="rf-menu rf-new-menu">
        <span>{"New folder"}</span>
        <span data-cursor="drive-upload">
        <ui.Icon name="upload"/>{" File upload"}</span>
        </div>}{c >= 8 && c <= 9 && <div className="rf-modal-layer">
        <FilePicker kind="report" selected={c >= 9}/>
        </div>}{c >= 10 && <div className="rf-upload-note">
        <ui.Icon name="file"/>
        <span>{c >= 11 ? 'Upload complete' : 'Uploading report…'}</span>
        <b>{c >= 11 ? '✓' : ''}</b>
        <i>
        <i style={{ width: `${100 * data.phase(frame, 10, 1100, data.COMMIT_DELAY)}%` }}/>
        </i>
        </div>}</div>;
}
export function CompactTransferScene({ frame, moving }: data.SceneProps) {
    const minimize = data.terminalMinimize(frame);
    const c = frame.committed;
    // A 320ms, fully opaque collapse anchored to the actual bottom-left corner.
    // The minus click commits first; no taskbar or intermediate miniature remains.
    return <div className="wf-stage rf-stage rf-transfer">
        <div className="rf-host-browser">
        <Titlebar>{"ops-pc \u00B7 Host browser"}</Titlebar>
        <div className="rf-tabs">
        <span data-active={c < 5}>{"Analytics"}</span>
        <span data-active={c >= 5} data-cursor="drive-tab">{"Google Drive"}</span>
        </div>
        <div className="rf-url">{c >= 5 ? data.SITES.drive : data.SITES.analytics}</div>{c >= 5 ? <Drive frame={frame} moving={moving}/> : <Analytics c={c}/>}</div>
        <div className="rf-terminal-layer" data-minimized={minimize === 1} style={{ visibility: minimize === 1 ? 'hidden' : 'visible', transform: `scale(${1 - minimize})` }}>
        <Terminal frame={frame} moving={moving}/>
        </div>
        <gestures.GestureCursor frame={frame} moving={moving}/>
        </div>;
}
function Profile({ saved }: { saved: boolean }) {
    return <div className="rf-profile">
        <div className="rf-profile-heading">
        <h4>{"Your profile"}</h4>
        <FakeButton target="slack-edit">{"Edit"}</FakeButton>
        </div>
        <div className="rf-profile-avatar">
        <ui.Photo variant={saved ? 'new' : 'old'}/>
        </div>
        <b>{"You"}</b>
        <small>{"Active \u00B7 Satelle workspace"}</small>{saved && <div className="rf-status-note">{"\u2713 \u00A0 Profile photo updated"}</div>}</div>;
}
function EditProfile({ saved }: { saved: boolean }) {
    return <div className="rf-edit-profile">
        <h4>{"Edit your profile"}</h4>
        <div>
        <div className="rf-profile-avatar">
        <ui.Photo variant={saved ? 'new' : 'old'}/>
        </div>
        <div>
        <small>{"Profile photo"}</small>
        <FakeButton target="slack-upload">{"Upload Photo"}</FakeButton>
        <small>{"PNG, JPG or GIF"}</small>
        </div>
        </div>
        <footer>
        <FakeButton>{"Cancel"}</FakeButton>
        <FakeButton primary={true} target="slack-save">{"Save Changes"}</FakeButton>
        </footer>
        </div>;
}
function Crop({ frame }: data.SceneProps) {
    const progress = data.ease(data.phase(frame, 8, data.DRAG_DURATION, data.COMMIT_DELAY));
    return <div className="rf-crop">
        <h4>{"Crop your photo"}</h4>
        <div className="rf-crop-preview">
        <div style={{ transform: `scale(${1 + progress * 0.2})` }}>
        <ui.Photo />
        </div>
        <i />
        </div>
        <div className="rf-crop-slider">
        <span>{"\u2212"}</span>
        <div>
        <i style={{ width: `${35 + progress * 30}%` }}/>
        <b data-cursor="slack-crop" style={{ left: `${35 + progress * 30}%` }}/>
        <b className="rf-endpoint" data-cursor="slack-crop-end" style={{ left: '65%' }}/>
        </div>
        <span>{"\uFF0B"}</span>
        </div>
        <footer>
        <FakeButton>{"Cancel"}</FakeButton>
        <FakeButton primary={true} target="slack-crop-save">{"Save"}</FakeButton>
        </footer>
        </div>;
}
export function CompactSlackScene({ frame, moving }: data.SceneProps) {
    const c = frame.committed;
    return <div className="wf-stage rf-stage rf-slack">
        <header className="rf-slack-title">
        <ui.Lights />
        <ui.Brand name="slack"/>
        <b>{"Slack"}</b>
        <small>{"Satelle workspace"}</small>
        </header>
        <div className="rf-slack-layout">
        <aside>
        <span>
        <ui.Icon name="home"/>{"Home"}</span>
        <span>
        <ui.Icon name="chat"/>{"DMs"}</span>
        <div data-cursor="slack-account" className="rf-account">
        <ui.Photo variant={c >= 10 ? 'new' : 'old'}/>
        </div>
        </aside>
        <div className="rf-slack-main">{c < 2 ? <React.Fragment>
        <div className="rf-channel-title">{"# design"}</div>
        <div className="rf-slack-prompt">
        <small>{"Task on studio-mac"}</small>
        <p>{data.typed(data.PROMPTS.slack, frame, 0, 1800)}</p>
        </div>
        <div className="rf-slack-composer">{"Message #design"}</div>
        </React.Fragment> : <Profile saved={c >= 10}/>}</div>
        </div>{c === 1 && <div className="rf-menu rf-account-menu">
        <b>{"You \u00B7 active"}</b>
        <span data-cursor="slack-profile">{"Profile"}</span>
        <span>{"Preferences"}</span>
        </div>}{c >= 3 && c < 10 && <div className="rf-modal-layer">
        <EditProfile saved={c >= 9}/>
        </div>}{c >= 4 && c <= 6 && <div className="rf-modal-layer rf-front">
        <FilePicker kind="photo" selected={c >= 6} pictures={c >= 5}/>
        </div>}{c >= 7 && c <= 8 && <div className="rf-modal-layer rf-front">
        <Crop frame={frame} moving={moving}/>
        </div>}<gestures.GestureCursor frame={frame} moving={moving}/>
        </div>;
}
