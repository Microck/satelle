'use client';

import * as React from 'react';
import {
  BOUNDARIES, DEFAULT_SELECTION, DEMOS, HOST, MCP_EXAMPLE, PLATFORMS, PROBE_OUTPUT,
  RELEASE, SESSION, TURN, parseSelection, toggleSelection,
  type BoundaryId, type DemoId, type PlatformId,
} from './exploration-data';
import './explorations.css';

type GalleryProps = { explore?: boolean };
type GalleryState = { selected: DemoId[]; preview: boolean; message: string };

/**
 * Shared real DOM demos for the homepage and the six-option review page.
 * All interaction is local UI state: no Host, MCP server, shell or network call.
 * Initial markup is complete on the server; no timers, autoplay or empty frames.
 */
export default class DemoGallery extends React.Component<GalleryProps, GalleryState> {
  state: GalleryState = { selected: [...DEFAULT_SELECTION], preview: false, message: '' };

  componentDidMount() {
    if (!this.props.explore) return;
    const params = new URLSearchParams(window.location.search);
    const selected = parseSelection(params.get('demos'));
    this.setState({ selected, preview: params.get('view') === 'selection' && selected.length === 4 });
  }

  private syncUrl = () => {
    if (!this.props.explore) return;
    const url = new URL(window.location.href);
    url.searchParams.set('demos', this.state.selected.join(','));
    if (this.state.preview) url.searchParams.set('view', 'selection');
    else url.searchParams.delete('view');
    // Preserve Next's history state. No navigation, storage or server mutation.
    try { window.history.replaceState(window.history.state, '', url); } catch { /* file previews may disallow history writes */ }
  };

  private choose = (id: DemoId) => {
    this.setState((state) => ({ selected: toggleSelection(state.selected, id), preview: false, message: '' }), this.syncUrl);
  };

  private copyLink = async () => {
    this.syncUrl();
    try {
      await navigator.clipboard.writeText(window.location.href);
      this.setState({ message: 'Selection link copied.' });
    } catch {
      this.setState({ message: 'Clipboard unavailable. Copy the selection URL from your address bar.' });
    }
  };

  render() {
    const { explore = false } = this.props;
    const { selected, preview, message } = this.state;
    const visible = explore && !preview ? DEMOS : DEMOS.filter((demo) => (explore ? selected : DEFAULT_SELECTION).includes(demo.id));
    const prefix = explore ? 'explore' : 'home';
    return (
      <div className="sx-gallery" data-explorations={explore ? 'review' : 'home'}>
        {explore ? (
          <div className="sx-picker" aria-label="Choose four demo concepts">
            <div className="sx-picker-copy">
              <strong>{preview ? 'Your four, together.' : 'Choose the four for your homepage.'}</strong>
              <span role="status" aria-live="polite" aria-atomic="true">{message || `${selected.length} of 4 selected${selected.length === 4 ? '. Deselect a card to swap it.' : '.'}`}</span>
            </div>
            <div className="sx-picker-actions">
              <button type="button" onClick={() => this.setState({ preview: !preview, message: '' }, this.syncUrl)} disabled={!preview && selected.length !== 4}>
                {preview ? 'Show all 6' : 'Preview selected 4'}
              </button>
              <button type="button" onClick={this.copyLink}>Copy selection link</button>
            </div>
          </div>
        ) : null}
        <div className="sx-grid">
          {visible.map((demo) => {
            const id = `${prefix}-${demo.id}`;
            return (
              <article className="sx-card" key={demo.id} aria-labelledby={`${id}-title`} data-demo={demo.id}>
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
                  {demo.id === 'durability' ? <SessionDemo id={id} /> : null}
                  {demo.id === 'readiness' ? <ReadinessDemo id={id} /> : null}
                  {demo.id === 'transports' ? <TransportDemo id={id} /> : null}
                  {demo.id === 'agent' ? <AgentDemo id={id} /> : null}
                  {demo.id === 'boundaries' ? <BoundaryDemo id={id} /> : null}
                  {demo.id === 'platforms' ? <PlatformDemo id={id} /> : null}
                </div>
              </article>
            );
          })}
        </div>
        <p className="sx-footnote">Illustrative interactions, not live runs. Native macOS and Windows Hosts are candidates and must pass the live readiness probe. Native Linux Host execution is not supported in {RELEASE}.</p>
      </div>
    );
  }
}

type Choice = { id: string; label: string };
function Tabs({ id, label, choices, active, onChange }: { id: string; label: string; choices: readonly Choice[]; active: string; onChange: (id: string) => void }) {
  function keyDown(event: React.KeyboardEvent<HTMLButtonElement>, index: number) {
    let next: number;
    if (event.key === 'ArrowRight' || event.key === 'ArrowDown') next = (index + 1) % choices.length;
    else if (event.key === 'ArrowLeft' || event.key === 'ArrowUp') next = (index + choices.length - 1) % choices.length;
    else if (event.key === 'Home') next = 0;
    else if (event.key === 'End') next = choices.length - 1;
    else return;
    event.preventDefault();
    onChange(choices[next].id);
    event.currentTarget.parentElement?.querySelectorAll<HTMLButtonElement>('[role="tab"]')[next]?.focus();
  }
  return (
    <div className="sx-tabs" role="tablist" aria-label={label}>
      {choices.map((choice, index) => (
        <button key={choice.id} type="button" role="tab" id={`${id}-tab-${choice.id}`} aria-selected={active === choice.id} aria-controls={`${id}-panel`} tabIndex={active === choice.id ? 0 : -1} onClick={() => onChange(choice.id)} onKeyDown={(event) => keyDown(event, index)}>{choice.label}</button>
      ))}
    </div>
  );
}

function Window({ label, status, children }: { label: string; status?: string; children: React.ReactNode }) {
  return (
    <div className="sx-window">
      <div className="sx-window-bar">
        <span className="sx-lights" aria-hidden="true"><i /><i /><i /></span>
        <span className="sx-window-label">{label}</span>
        {status ? <span className="sx-window-status">{status}</span> : null}
      </div>
      {children}
    </div>
  );
}
function Command({ children }: { children: React.ReactNode }) {
  return <div className="sx-command"><span aria-hidden="true">$ </span><code>{children}</code></div>;
}
function Transcript({ lines }: { lines: readonly string[] }) {
  return <pre className="sx-output">{lines.join('\n')}</pre>;
}
function Notice({ children }: { children: React.ReactNode }) {
  return <p className="sx-notice">{children}</p>;
}

type IdProps = { id: string };
class SessionDemo extends React.Component<IdProps, { step: string }> {
  state = { step: 'reconnect' };
  render() {
    const { id } = this.props;
    const { step } = this.state;
    return (
      <Window label="operator@thinkpad · Linux" status="Controller">
        <Tabs id={id} label="Session example" choices={[{ id: 'start', label: '1. Start a Turn' }, { id: 'reconnect', label: '2. New Controller' }]} active={step} onChange={(value) => this.setState({ step: value })} />
        <div className="sx-pane sx-terminal" role="tabpanel" id={`${id}-panel`} aria-labelledby={`${id}-tab-${step}`} tabIndex={0}>
          <div className="sx-terminal-group">
            <Command>satelle run --host {HOST} --detach &quot;Prepare the workspace&quot;</Command>
            <Transcript lines={[`Session: ${SESSION}`, 'Status: starting']} />
          </div>
          {step === 'reconnect' ? (
            <div className="sx-terminal-group sx-reconnect">
              <div className="sx-editorial-label">Later, from a fresh Controller process</div>
              <Command>satelle status {SESSION}</Command>
              <Transcript lines={[`Session: ${SESSION}`, `Host: ${HOST}`, 'Status: running', 'Turns: 1', `Latest turn: ${TURN}`, 'Latest status: running']} />
            </div>
          ) : null}
        </div>
        <Notice>{step === 'reconnect' ? 'Same Session. Different Controller process. The Host kept the state.' : 'Detached admission reports starting. The Controller can exit without stopping the Turn.'}</Notice>
      </Window>
    );
  }
}

class ReadinessDemo extends React.Component<IdProps, { ready: boolean }> {
  state = { ready: false };
  render() {
    const { id } = this.props;
    const ending = this.state.ready ? 'ready' : 'blocked';
    return (
      <Window label="satelle doctor" status={ending}>
        <Tabs id={id} label="Readiness example" choices={[{ id: 'blocked', label: 'Blocked' }, { id: 'ready', label: 'After manual approval' }]} active={ending} onChange={(value) => this.setState({ ready: value === 'ready' })} />
        <div className="sx-pane sx-terminal" role="tabpanel" id={`${id}-panel`} aria-labelledby={`${id}-tab-${ending}`} tabIndex={0}>
          <Command>satelle doctor --host {HOST} --scope computer-use --refresh</Command>
          <Transcript lines={PROBE_OUTPUT[ending]} />
        </div>
        <Notice>{this.state.ready ? 'Example after a person resolves the blocker and reruns the probe. This switch grants no permission.' : 'A person must resolve the permission or app-approval blocker on the Host. Satelle cannot grant it.'}</Notice>
      </Window>
    );
  }
}

const TRANSPORTS = {
  local: { label: 'Local', wire: 'local call', host: 'local-demo', rows: [['transport', 'local'], ['Host', 'This machine'], ['Network credentials', 'No address, api_token, or ca_bundle']], note: 'The Controller and Host are on the same machine. No network transport is involved.' },
  direct: { label: 'Direct TLS', wire: 'HTTPS / WSS', host: HOST, rows: [['address', 'HTTPS or WSS endpoint'], ['expected_host_id', 'Operator-pinned Host identity'], ['api_token', 'Bearer token from an owner-only file'], ['ca_bundle', 'Explicit CA bundle']], note: 'All four are required. The Operator provisions the token and CA bundle; Satelle does not create them automatically.' },
  ssh: { label: 'SSH tunnel', wire: 'SSH tunnel', host: HOST, rows: [['transport', 'ssh'], ['Tunnel', 'Authenticated SSH connection'], ['api_token', 'Satelle API authentication still required'], ['expected_host_id', 'Host identity verification still required']], note: 'SSH authenticates the tunnel. It replaces neither Satelle API authentication nor Host identity verification.' },
} as const;
type TransportId = keyof typeof TRANSPORTS;
class TransportDemo extends React.Component<IdProps, { transport: TransportId }> {
  state: { transport: TransportId } = { transport: 'direct' };
  render() {
    const { id } = this.props;
    const { transport } = this.state;
    const current = TRANSPORTS[transport];
    return (
      <Window label="Controller → Host" status="binding requirements">
        <Tabs id={id} label="Controller transport" choices={Object.entries(TRANSPORTS).map(([key, value]) => ({ id: key, label: value.label }))} active={transport} onChange={(value) => this.setState({ transport: value as TransportId })} />
        <div className="sx-pane" role="tabpanel" id={`${id}-panel`} aria-labelledby={`${id}-tab-${transport}`} tabIndex={0}>
          <div className="sx-connection" aria-label={`Controller to ${current.host} over ${current.wire}`}>
            <span><strong>Controller</strong><small>your terminal</small></span>
            <span className="sx-wire"><span>{current.wire}</span><i aria-hidden="true">→</i></span>
            <span><strong>Host</strong><small>{current.host}</small></span>
          </div>
          <dl className="sx-fields">{current.rows.map(([key, value]) => <div key={key}><dt>{key}</dt><dd>{value}</dd></div>)}</dl>
          <div className="sx-example-command"><Command>satelle run --host {current.host} &quot;Open the browser&quot;</Command></div>
        </div>
        <Notice>{current.note}</Notice>
      </Window>
    );
  }
}

class AgentDemo extends React.Component<IdProps, { mutations: boolean }> {
  state = { mutations: false };
  render() {
    const { id } = this.props;
    const { mutations } = this.state;
    const mode = mutations ? 'mutations' : 'read-only';
    return (
      <Window label="satelle mcp serve" status={`${mutations ? MCP_EXAMPLE.mutationToolCount : MCP_EXAMPLE.readOnlyToolCount} tools`}>
        <Tabs id={id} label="MCP server example" choices={[{ id: 'read-only', label: 'Read-only' }, { id: 'mutations', label: 'Mutation tools enabled' }]} active={mode} onChange={(value) => this.setState({ mutations: value === 'mutations' })} />
        <div className="sx-pane sx-agent" role="tabpanel" id={`${id}-panel`} aria-labelledby={`${id}-tab-${mode}`} tabIndex={0}>
          <p className="sx-agent-ask"><span aria-hidden="true">›</span> Check my Session, then start a follow-up Turn.</p>
          <details className="sx-tool">
            <summary><code>status</code><span>stopped · 2 Turns</span></summary>
            <div className="sx-tool-detail"><pre>{JSON.stringify(MCP_EXAMPLE.statusInput, null, 2)}</pre><p>Selected fields from the result:</p><pre>{JSON.stringify(MCP_EXAMPLE.statusFields, null, 2)}</pre></div>
          </details>
          {mutations ? (
            <details className="sx-tool" key="steer">
              <summary><code>steer</code><span>starting · 3 Turns</span></summary>
              <div className="sx-tool-detail"><pre>{JSON.stringify(MCP_EXAMPLE.steerInput, null, 2)}</pre><p>Selected fields from the result:</p><pre>{JSON.stringify(MCP_EXAMPLE.steerFields, null, 2)}</pre></div>
            </details>
          ) : (
            <div className="sx-agent-response"><strong>steer is not in the tool list.</strong><p>This server advertises eight read-only tools. No mutation call was made.</p></div>
          )}
          <div className="sx-example-command"><Command>satelle mcp serve{mutations ? ' --enable-mutations' : ''}</Command></div>
          <p className="sx-small">Expand a tool to inspect its arguments and selected result fields. Turn counts summarize the returned arrays.</p>
        </div>
        <Notice>{mutations ? 'Example server restarted with --enable-mutations. The flag advertises tools; it grants no additional Host capability or native permission.' : 'Read-only is the default. Changing this example does not install or restart a real MCP server.'}</Notice>
      </Window>
    );
  }
}

class BoundaryDemo extends React.Component<IdProps, { boundary: BoundaryId }> {
  state: { boundary: BoundaryId } = { boundary: 'session' };
  render() {
    const { id } = this.props;
    const { boundary } = this.state;
    return (
      <Window label="Controller / Host" status="ownership diagram">
        <Tabs id={id} label="Inspect a boundary" choices={Object.entries(BOUNDARIES).map(([key, value]) => ({ id: key, label: value.label }))} active={boundary} onChange={(value) => this.setState({ boundary: value as BoundaryId })} />
        <div className="sx-pane" role="tabpanel" id={`${id}-panel`} aria-labelledby={`${id}-tab-${boundary}`} tabIndex={0}>
          <div className="sx-ownership">
            <section><span className="sx-eyebrow">Requests work</span><h4>Controller</h4><p>Your terminal or MCP client.</p><ul><li>Intent and commands</li><li>Status and log requests</li></ul></section>
            <div className="sx-ownership-wire" aria-hidden="true">⇄</div>
            <section><span className="sx-eyebrow">Owns execution</span><h4>Host</h4><p>The machine you control.</p><ul><li data-highlight={boundary === 'session'}>Session and Turn state</li><li data-highlight={boundary === 'session'}>Operational logs</li><li data-highlight={boundary === 'desktop'}>Desktop Binding</li><li data-highlight={boundary === 'credentials'}>Provider-secret resolution</li></ul></section>
          </div>
          <p className="sx-boundary-note">{BOUNDARIES[boundary].text}</p>
        </div>
        <Notice>The diagram shows ownership, not a separate settings dashboard or a promise that all data stays on one machine.</Notice>
      </Window>
    );
  }
}

class PlatformDemo extends React.Component<IdProps, { platform: PlatformId }> {
  state: { platform: PlatformId } = { platform: 'linux' };
  render() {
    const { id } = this.props;
    const { platform } = this.state;
    const current = PLATFORMS.find((item) => item.id === platform)!;
    return (
      <Window label={`Satelle ${RELEASE}`} status="support matrix">
        <div className="sx-pane sx-platform-pane">
          <table className="sx-support">
            <caption className="sx-sr">Controller and native Computer Use Host support in Satelle {RELEASE}</caption>
            <thead><tr><th scope="col">Capability</th>{PLATFORMS.map((item) => <th scope="col" key={item.id} data-active={platform === item.id}><button type="button" aria-pressed={platform === item.id} aria-controls={`${id}-explanation`} onClick={() => this.setState({ platform: item.id })}>{item.name}</button></th>)}</tr></thead>
            <tbody>
              <tr><th scope="row">Controller CLI</th>{PLATFORMS.map((item) => <td key={item.id} data-active={platform === item.id}><span className="sx-verdict-mark" aria-hidden="true">✓</span><span className="sx-verdict-text">{item.controller}</span></td>)}</tr>
              <tr><th scope="row">Native Computer Use Host</th>{PLATFORMS.map((item) => <td key={item.id} data-active={platform === item.id}><span className="sx-verdict-mark" aria-hidden="true">{item.host === 'Candidate' ? '△' : '×'}</span><span className="sx-verdict-text">{item.host}</span></td>)}</tr>
            </tbody>
          </table>
          <p className="sx-support-legend" aria-hidden="true">✓ Implemented · △ Candidate · × Not supported</p>
          <p className="sx-platform-note" id={`${id}-explanation`} role="status" aria-live="polite"><strong>{current.name}.</strong> {current.note}</p>
          <details className="sx-limitations"><summary>What is not implemented</summary><ul><li>Local setup mutation after planning.</li><li>Direct transport setup or automatic direct-token provisioning.</li><li>Persistent Host service installation and Host stop/restart control.</li><li>Storage migration.</li><li>Native Linux Computer Use Host execution.</li></ul></details>
        </div>
        <Notice>Choose a platform to inspect its limits. Candidate means the target machine must pass the live probe, not that support is guaranteed.</Notice>
      </Window>
    );
  }
}
