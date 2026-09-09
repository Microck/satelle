'use client';

import * as React from 'react';
import {
  CLI_OUTPUT, DEFAULT_SELECTION, DEMOS, HOST, MCP_EXAMPLE, MONTHS, READ_TOOLS,
  RELEASE, SESSION, money, parseSelection, toggleSelection, type DemoId,
} from './exploration-data';
import './explorations.css';

type IdProps = { id: string };
type GalleryProps = { explore?: boolean };
type GalleryState = { selected: DemoId[]; preview: boolean; message: string };

/** Complete initial HTML; interactions only change local illustrative state.
 * No Host calls, commands, credentials, timers, or new product interfaces. */
export default class DemoGallery extends React.Component<GalleryProps, GalleryState> {
  state: GalleryState = { selected: [...DEFAULT_SELECTION], preview: false, message: '' };

  componentDidMount() {
    if (!this.props.explore) return;
    this.readUrl();
    window.addEventListener('popstate', this.readUrl);
  }
  componentWillUnmount() { window.removeEventListener('popstate', this.readUrl); }
  private readUrl = () => {
    const params = new URLSearchParams(window.location.search);
    const selected = parseSelection(params.get('demos'));
    this.setState({ selected, preview: params.get('view') === 'selection' && selected.length === 4, message: '' });
  };
  private syncUrl = () => {
    if (!this.props.explore) return;
    const url = new URL(window.location.href);
    url.searchParams.set('demos', this.state.selected.join(','));
    if (this.state.preview) url.searchParams.set('view', 'selection');
    else url.searchParams.delete('view');
    try { window.history.replaceState(window.history.state, '', url); }
    catch { /* Standalone file previews may not permit history writes. */ }
  };
  private choose = (id: DemoId) => {
    this.setState((state) => ({ selected: toggleSelection(state.selected, id), preview: false, message: '' }), this.syncUrl);
  };
  private copyLink = async () => {
    this.syncUrl();
    try {
      await navigator.clipboard.writeText(window.location.href);
      this.setState({ message: 'Selection link copied.' });
    } catch { this.setState({ message: 'Clipboard unavailable. Copy the URL from your address bar.' }); }
  };

  render() {
    const { explore = false } = this.props;
    const { selected, preview, message } = this.state;
    const visible = explore && !preview ? DEMOS : DEMOS.filter((demo) => (explore ? selected : DEFAULT_SELECTION).includes(demo.id));
    return (
      <div className="sx-gallery" data-explorations={explore ? 'review' : 'home'}>
        {explore ? (
          <div className="sx-picker" aria-label="Choose four demo concepts">
            <div className="sx-picker-copy">
              <strong>{preview ? 'Your four, together.' : 'Six different surfaces. Choose your four.'}</strong>
              <span role="status" aria-live="polite" aria-atomic="true">{message || `${selected.length} of 4 selected. ${selected.length === 4 ? 'Deselect one to swap it.' : 'Choose up to four.'}`}</span>
            </div>
            <div className="sx-picker-actions">
              <button type="button" onClick={() => this.setState({ preview: !preview, message: '' }, this.syncUrl)} disabled={!preview && selected.length !== 4}>{preview ? 'Show all 6' : 'Preview selected 4'}</button>
              <button type="button" onClick={this.copyLink}>Copy selection link</button>
            </div>
          </div>
        ) : null}
        <div className="sx-grid">
          {visible.map((demo) => {
            const id = `${explore ? 'explore' : 'home'}-${demo.id}`;
            return (
              <article className="sx-card" key={demo.id} aria-labelledby={`${id}-title`} data-demo={demo.id} data-surface={demo.surface}>
                {explore ? (
                  <div className="sx-choice">
                    <span className="sx-eyebrow">{demo.number} / {demo.label}</span>
                    <button type="button" className="sx-select" aria-pressed={selected.includes(demo.id)} aria-label={`${selected.includes(demo.id) ? 'Deselect' : 'Select'} ${demo.number}: ${demo.title}`} disabled={!selected.includes(demo.id) && selected.length === 4} onClick={() => this.choose(demo.id)}>
                      <span aria-hidden="true">{selected.includes(demo.id) ? '✓' : '+'}</span>{selected.includes(demo.id) ? 'Selected' : 'Select'}
                    </button>
                  </div>
                ) : null}
                <header className="sx-card-head">
                  <h3 id={`${id}-title`}>{demo.title}</h3>
                  <p>{demo.lead}</p>
                  <a href={demo.href}>{demo.cta} <span aria-hidden="true">→</span></a>
                </header>
                <div className="sx-card-body">
                  {demo.id === 'spreadsheet' ? <SpreadsheetDemo id={id} /> : null}
                  {demo.id === 'chat' ? <ChatDemo id={id} /> : null}
                  {demo.id === 'editor' ? <EditorDemo id={id} /> : null}
                  {demo.id === 'browser' ? <BrowserDemo id={id} /> : null}
                  {demo.id === 'document' ? <DocumentDemo id={id} /> : null}
                  {demo.id === 'terminal' ? <TerminalDemo id={id} /> : null}
                </div>
              </article>
            );
          })}
        </div>
        <p className="sx-footnote">Interactive illustrations, not recordings or live runs. Native app scenes assume a Host that passes the live readiness probe. macOS and Windows are candidate Hosts; native Linux Host execution is not supported in {RELEASE}. App scenes are not app-specific integrations.</p>
      </div>
    );
  }
}

type IconName = 'sheet' | 'chat' | 'code' | 'browser' | 'file' | 'terminal' | 'arrow' | 'check' | 'lock' | 'folder';
function Icon({ name }: { name: IconName }) {
  const paths: Record<IconName, string> = {
    sheet: 'M4 3h12v14H4zM4 7h12M4 11h12M8 7v10',
    chat: 'M3 3h14v10H8l-4 4v-4H3zM6 7h8M6 10h5',
    code: 'm7 6-4 4 4 4m6-8 4 4-4 4M11 4 9 16',
    browser: 'M3 3h14v14H3zM3 7h14M6 5h.1M9 5h.1',
    file: 'M5 2h7l4 4v12H5zM12 2v5h4M8 11h5M8 14h5',
    terminal: 'm4 5 5 5-5 5m7 0h5',
    arrow: 'M4 10h12m-5-5 5 5-5 5',
    check: 'm4 10 4 4 8-8',
    lock: 'M5 9h10v8H5zM7 9V6a3 3 0 0 1 6 0v3',
    folder: 'M2 5h6l2 2h8v10H2z',
  };
  return <svg viewBox="0 0 20 20" width="18" height="18" fill="none" stroke="currentColor" strokeWidth="1.35" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true" focusable="false"><path d={paths[name]} /></svg>;
}
function Frame({ title, icon, tag, className = '', children }: { title: string; icon: IconName; tag: string; className?: string; children: React.ReactNode }) {
  return <div className={`sx-app ${className}`}><div className="sx-app-bar"><span className="sx-app-title"><Icon name={icon} />{title}</span><span className="sx-app-tag">{tag}</span></div>{children}</div>;
}
function Caption({ children }: { children: React.ReactNode }) { return <p className="sx-caption">{children}</p>; }
function ExampleControl({ label, children }: { label: string; children: React.ReactNode }) {
  return <div className="sx-example-control"><span>{label}</span>{children}</div>;
}
function ToolDetail({ name, input, result }: { name: string; input: object; result: object }) {
  return <details className="sx-tool-detail"><summary><Icon name="code" />{name}<span>Inspect tool call</span></summary><div><p>Example arguments</p><pre>{JSON.stringify(input, null, 2)}</pre><p>Selected result fields (not a full response)</p><pre>{JSON.stringify(result, null, 2)}</pre></div></details>;
}

/** Native desktop vignette. Sample numbers mirror the existing Calc stage. */
class SpreadsheetDemo extends React.Component<IdProps, { charted: boolean }> {
  state = { charted: true };
  render() {
    const { charted } = this.state;
    return (
      <Frame title="Q3 Sales.xlsx" icon="sheet" tag="Host spreadsheet" className="sx-sheet-app">
        <div className="sx-sheet-menu" aria-hidden="true"><span>File</span><span>Edit</span><span>Insert</span><span>Format</span><span>Data</span></div>
        <div className="sx-formula"><span>B5</span><span aria-hidden="true">ƒx</span><code>=SUM(B2:B4)</code></div>
        <div className="sx-sheet-work">
          <table className="sx-sheet-table"><caption className="sx-visually-hidden">Illustrative Q3 monthly revenue and profit, also plotted below.</caption><thead><tr><th scope="col">Month</th><th scope="col">Revenue</th><th scope="col">Profit</th></tr></thead><tbody>{MONTHS.map((row) => <tr key={row.month}><th scope="row">{row.month}</th><td>{money(row.revenue)}</td><td>{money(row.profit)}</td></tr>)}<tr className="sx-total"><th scope="row">Q3 total</th><td>{money(MONTHS.reduce((sum, row) => sum + row.revenue, 0))}</td><td>{money(MONTHS.reduce((sum, row) => sum + row.profit, 0))}</td></tr></tbody></table>
          <div className={`sx-chart ${charted ? '' : 'sx-chart-empty'}`} id={`${this.props.id}-result`}>
            {charted ? <><div className="sx-chart-title"><strong>Revenue &amp; profit</strong><span>Q3 / monthly</span></div><div className="sx-bars" aria-hidden="true">{MONTHS.map((row) => <div className="sx-bar-pair" key={row.month}><div className="sx-bar-columns"><i style={{ height: `${row.revenue / 15000 * 100}%` }} /><i style={{ height: `${row.profit / 15000 * 100}%` }} /></div><span>{row.month}</span></div>)}</div><div className="sx-chart-key"><span><i />Revenue</span><span><i />Profit</span></div></> : <div><Icon name="sheet" /><strong>The data is here.</strong><span>The next task is to add its chart.</span></div>}
          </div>
        </div>
        <div className="sx-sheet-tabs" aria-hidden="true"><span>Monthly summary</span><span>Orders</span><span>+</span></div>
        <ExampleControl label={charted ? 'Example result · chart added' : 'Before · source data unchanged'}><button type="button" aria-controls={`${this.props.id}-result`} onClick={() => this.setState({ charted: !charted })}>{charted ? 'Show before' : 'Show result'} <span aria-hidden="true">↗</span></button></ExampleControl>
        <Caption>Illustrative desktop task, not a spreadsheet add-in or a verified run.</Caption>
      </Frame>
    );
  }
}

/** Claude Desktop is an actual installer target. This is not its exact UI. */
class ChatDemo extends React.Component<IdProps, { followUp: boolean }> {
  state = { followUp: false };
  render() {
    const { followUp } = this.state;
    return (
      <Frame title="Claude Desktop" icon="chat" tag="MCP illustration" className="sx-chat-app">
        <div className="sx-chat-topic"><span>Checking on the browser task</span><span className="sx-read-only">Read-only tools</span></div>
        <div className="sx-chat-conversation">
          <div className="sx-user-message">{followUp ? 'Can you start a follow-up Turn too?' : 'I closed my terminal. Is the Session still running?'}</div>
          <div className="sx-assistant-message"><span className="sx-avatar" aria-hidden="true">C</span><div>
            {!followUp ? <><p>The Host reports that your Session is still running.</p><div className="sx-session-card"><div><span className="sx-status-dot" />Running on your Host</div><dl><div><dt>Host</dt><dd>{HOST}</dd></div><div><dt>Session</dt><dd><abbr title={SESSION}>rs_0193…be02</abbr></dd></div></dl></div><p className="sx-message-muted">The state lives on the Host, not in the terminal you closed.</p></> : <><p>Not with this server’s current tool list.</p><p className="sx-message-muted">It advertises eight read-only tools. A follow-up needs <code>steer</code>, which is only advertised with mutation tools enabled.</p><div className="sx-tool-inventory">{READ_TOOLS.map((tool) => <code key={tool}>{tool}</code>)}</div><p>No mutation call was made.</p></>}
          </div></div>
          {!followUp ? <ToolDetail name="status · Satelle" input={MCP_EXAMPLE.statusInput} result={MCP_EXAMPLE.chatFields} /> : null}
        </div>
        <div className="sx-chat-composer"><span>Suggested follow-up</span><button type="button" onClick={() => this.setState({ followUp: !followUp })}>{followUp ? 'Ask about Session status' : 'Ask about starting another Turn'}<Icon name="arrow" /></button><div><Icon name="code" /><span>Satelle · local stdio MCP</span></div></div>
        <Caption>Illustrated client conversation. Tool names and argument keys match Satelle.</Caption>
      </Frame>
    );
  }
}

/** Cursor is an actual installer target; editor furniture is illustrative. */
class EditorDemo extends React.Component<IdProps, { mutations: boolean; started: boolean }> {
  state = { mutations: false, started: false };
  render() {
    const { mutations, started } = this.state;
    return (
      <Frame title="Workspace / Cursor" icon="code" tag="MCP illustration" className="sx-editor-app">
        <div className="sx-editor-layout">
          <aside className="sx-editor-rail" aria-hidden="true"><Icon name="file" /><Icon name="folder" /><Icon name="code" /></aside>
          <div className="sx-code-pane"><div className="sx-code-tab">mcp.json</div><div className="sx-code-content" aria-label="Illustrative Cursor MCP configuration"><code>{'{\n  "mcpServers": {\n    "satelle": {\n      "command": "satelle",\n      "args": [\n        "mcp",\n        "serve"' + (mutations ? ',\n        "--enable-mutations"' : '') + '\n      ]\n    }\n  }\n}'}</code></div><div className="sx-code-note">Configuration example<br />Not a file being edited by Satelle</div></div>
          <div className="sx-editor-agent"><div className="sx-code-tab">Agent <span>{mutations ? '15' : '8'} tools</span></div><div className="sx-editor-thread"><div className="sx-editor-prompt">Check the Session. Then open settings in a new Turn.</div><div className="sx-editor-tool"><Icon name="check" /><span><code>status</code><small>Previous Turn: stopped</small></span></div>{started ? <><div className="sx-editor-tool"><Icon name="check" /><span><code>steer</code><small>New Turn: starting</small></span></div><p>Follow-up admitted on the Host. This is not a completion result.</p></> : <p>{mutations ? 'steer is now advertised. Preview a detached follow-up.' : 'I can read the Session. steer is not in this server’s tool list.'}</p>}<button type="button" className="sx-editor-send" disabled={!mutations || started} onClick={() => this.setState({ started: true })}>{started ? 'Follow-up admitted' : 'Preview follow-up'}<Icon name="arrow" /></button></div></div>
        </div>
        <div className="sx-editor-mode"><label><input type="checkbox" checked={mutations} onChange={(event) => this.setState({ mutations: event.target.checked, started: false })} />Example with mutation tools enabled</label><span>{mutations ? '15 tools' : '8 tools'}</span></div>
        {started ? <ToolDetail name="steer · Satelle" input={MCP_EXAMPLE.steerInput} result={MCP_EXAMPLE.steerFields} /> : null}
        <Caption>Local demo switch only. Enabling tools grants no Host or OS permission.</Caption>
      </Frame>
    );
  }
}

/** The README's browser / follow-up prompt, visualized on a native Host. */
class BrowserDemo extends React.Component<IdProps, { settings: boolean }> {
  state = { settings: false };
  render() {
    const { settings } = this.state;
    return (
      <div className="sx-app sx-browser-app">
        <div className="sx-browser-tabs"><Icon name="browser" /><span>{settings ? 'Settings' : 'New tab'}</span><span aria-hidden="true">+</span><small>Host browser</small></div>
        <div className="sx-address"><span aria-hidden="true">← &nbsp; → &nbsp; ↻</span><div><Icon name="lock" /><span>{settings ? 'Browser settings' : 'Search or enter an address'}</span></div></div>
        <div className="sx-browser-page" id={`${this.props.id}-result`}>
          {settings ? <div className="sx-settings"><aside><strong>Settings</strong><span className="sx-active">Appearance</span><span>On startup</span><span>Downloads</span></aside><div><h4>Make it your browser.</h4><p>The next Turn opened settings.</p><div className="sx-setting-row"><span>Appearance</span><strong>System default</strong></div><div className="sx-setting-row"><span>Page zoom</span><strong>100%</strong></div><div className="sx-setting-row"><span>Home button</span><strong>Off</strong></div><small>Settings are illustrative and read-only.</small></div></div> : <div className="sx-new-tab"><div className="sx-browser-orbit" aria-hidden="true"><Icon name="browser" /></div><h4>Your browser. On your Host.</h4><div className="sx-search-illustration">Search the web or enter an address<span aria-hidden="true">↵</span></div><p>A visible desktop, not a headless browser API.</p></div>}
        </div>
        <div className="sx-turn-strip"><span className="sx-turn-number">{settings ? '02' : '01'}</span><div><strong>{settings ? 'Open settings' : 'Open the browser'}</strong><span>{HOST} · same Session</span></div><button type="button" aria-controls={`${this.props.id}-result`} onClick={() => this.setState({ settings: !settings })}>{settings ? 'Back to first Turn' : 'Show follow-up'}<Icon name="arrow" /></button></div>
        <Caption>Illustrative task on a ready native Host. Browser chrome is not interactive.</Caption>
      </div>
    );
  }
}

class DocumentDemo extends React.Component<IdProps, { formatted: boolean }> {
  state = { formatted: true };
  render() {
    const { formatted } = this.state;
    return (
      <Frame title="Project brief.odt" icon="file" tag="Host word processor" className="sx-document-app">
        <div className="sx-document-toolbar" aria-hidden="true"><span>{formatted ? 'Heading 1' : 'Body text'}</span><span>Sans serif</span><b>B</b><i>I</i><span>≡</span></div>
        <div className="sx-document-desk"><aside className="sx-document-outline"><strong>Outline</strong><span className="sx-active">Project brief</span><span>Overview</span><span>Deliverables</span><span>Next steps</span></aside><div className={`sx-paper ${formatted ? 'sx-paper-formatted' : ''}`} id={`${this.props.id}-result`}><div className="sx-paper-kicker">NORTHSTAR / INTERNAL</div><h4>Project brief</h4><p className="sx-paper-deck">A small plan for the next release.</p><h5>Overview</h5><p>Bring the draft, the review notes, and the delivery plan into one document.</p><h5>Deliverables</h5><p>A reviewed brief. A clear owner for each task. A release checklist the team can follow.</p><h5>Next steps</h5><p>Review the scope with the team before work begins.</p><div className="sx-paper-footer">WORKING DOCUMENT<span>01</span></div></div></div>
        <ExampleControl label={formatted ? 'Example result · headings and spacing' : 'Before · unformatted draft'}><button type="button" aria-controls={`${this.props.id}-result`} onClick={() => this.setState({ formatted: !formatted })}>{formatted ? 'Show draft' : 'Show formatted'} <span aria-hidden="true">↗</span></button></ExampleControl>
        <Caption>Synthetic desktop formatting scenario, not an office plugin or a verified run.</Caption>
      </Frame>
    );
  }
}

/** The only terminal card. Print shapes remain the CLI's own. */
class TerminalDemo extends React.Component<IdProps, { reconnect: boolean }> {
  state = { reconnect: true };
  render() {
    const { reconnect } = this.state;
    return (
      <Frame title="operator@thinkpad" icon="terminal" tag="Linux Controller" className="sx-terminal-app">
        <div className="sx-terminal" id={`${this.props.id}-result`}><div className="sx-command"><span>$ </span><code>satelle run --host {HOST} --detach &quot;Prepare the workspace&quot;</code></div><pre>{CLI_OUTPUT.start.join('\n')}</pre>{reconnect ? <><div className="sx-terminal-divider">Later, from a fresh Controller process</div><div className="sx-command"><span>$ </span><code>satelle status {SESSION}</code></div><pre>{CLI_OUTPUT.reconnect.join('\n')}</pre></> : <div className="sx-terminal-prompt" aria-hidden="true">$ <span>▌</span></div>}</div>
        <ExampleControl label={reconnect ? 'Same Session. Different Controller.' : 'Detached admission reports starting.'}><button type="button" aria-controls={`${this.props.id}-result`} onClick={() => this.setState({ reconnect: !reconnect })}>{reconnect ? 'Show admission' : 'Show fresh Controller'} <span aria-hidden="true">↗</span></button></ExampleControl>
        <Caption>Example CLI transcript. The Linux Controller is not the native Windows Host.</Caption>
      </Frame>
    );
  }
}
