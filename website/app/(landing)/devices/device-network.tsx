'use client';

import * as React from 'react';
import { DEVICES, PLAYBACK_RATE, TIMING, devicePoint, layout, networkFrame, pointOnSignal, signalPath, smooth, type DeviceShape, type NetworkFrame } from './network-model';
import './device-network.css';

type State = { elapsed: number; compact: boolean; running: boolean; reduced: boolean };

/** A single clock drives orbit, incoming signals, work and cooldown. The
 * central laptop becomes idle, not powered off; its Session stays on the Host.
 * Click/Space pauses. R replays. Reduced motion is static until explicit Play. */
export default class DeviceNetwork extends React.Component<Record<string, never>, State> {
  state: State = { elapsed: 0, compact: false, running: false, reduced: false };
  private root: HTMLDivElement | null = null;
  private intersection?: IntersectionObserver;
  private resize?: ResizeObserver;
  private media?: MediaQueryList;
  private raf = 0;
  private clock = 0;
  private previous: number | null = null;
  private painted = 0;
  private visible = false;
  private mounted = false;
  private paused = false;
  private reduced = false;
  private playUntil = 0;

  componentDidMount() {
    this.mounted = true;
    this.media = window.matchMedia('(prefers-reduced-motion: reduce)');
    this.media.addEventListener('change', this.preference);
    document.addEventListener('visibilitychange', this.sync);
    this.preference();
    this.measure();
    if (this.root && typeof ResizeObserver !== 'undefined') {
      this.resize = new ResizeObserver(this.measure);
      this.resize.observe(this.root);
    }
    if (this.root && typeof IntersectionObserver !== 'undefined') {
      this.intersection = new IntersectionObserver(([entry]) => {
        this.visible = entry.isIntersecting && entry.intersectionRatio >= 0.1;
        this.sync();
      }, { threshold: [0, 0.1] });
      this.intersection.observe(this.root);
    } else { this.visible = true; this.sync(); }
  }
  componentWillUnmount() {
    this.mounted = false;
    cancelAnimationFrame(this.raf);
    this.intersection?.disconnect();
    this.resize?.disconnect();
    this.media?.removeEventListener('change', this.preference);
    document.removeEventListener('visibilitychange', this.sync);
  }
  private measure = () => {
    const width = this.root?.getBoundingClientRect().width;
    if (width && this.mounted) this.setState({ compact: width < 640 });
  };
  private preference = () => {
    this.reduced = this.media?.matches ?? false;
    this.clock = 0; this.previous = null; this.playUntil = 0;
    this.setState({ reduced: this.reduced, elapsed: 0 }, this.sync);
  };
  private allowed = () => this.mounted && this.visible && !document.hidden && !this.paused
    && (!this.reduced || this.clock < this.playUntil);
  private sync = () => {
    if (!this.mounted) return;
    const running = this.allowed();
    if (running && !this.raf) this.raf = requestAnimationFrame(this.tick);
    if (!running) { cancelAnimationFrame(this.raf); this.raf = 0; this.previous = null; }
    if (this.state.running !== running) this.setState({ running });
  };
  private tick = (now: number) => {
    this.raf = 0;
    if (!this.allowed()) { this.sync(); return; }
    this.clock += this.previous === null ? 0 : Math.min(100, Math.max(0, now - this.previous)) * PLAYBACK_RATE;
    this.previous = now;
    if (this.reduced) this.clock = Math.min(this.clock, this.playUntil);
    if (now - this.painted >= 30 || this.clock === this.playUntil) {
      this.painted = now;
      this.setState({ elapsed: this.clock });
    }
    this.sync();
  };
  private toggle = () => {
    if (this.reduced && this.clock >= this.playUntil) {
      this.playUntil = (Math.floor(this.clock / TIMING.cycle) + 1) * TIMING.cycle;
      this.paused = false;
    } else this.paused = !this.paused;
    this.sync();
  };
  private replay = () => {
    this.clock = 0; this.previous = null; this.paused = false;
    this.playUntil = this.reduced ? TIMING.cycle : 0;
    this.setState({ elapsed: 0 }, this.sync);
  };
  private keyDown = (event: React.KeyboardEvent<HTMLDivElement>) => {
    if (event.repeat || event.altKey || event.ctrlKey || event.metaKey) return;
    if (event.key === ' ' || event.key === 'Enter') { event.preventDefault(); this.toggle(); }
    else if (event.key.toLowerCase() === 'r') { event.preventDefault(); this.replay(); }
  };
  render() {
    const { elapsed, compact, running, reduced } = this.state;
    const frame = networkFrame(elapsed), box = layout(compact);
    const sourcePath = signalPath(frame.sender, elapsed, compact);
    const path = frame.acknowledging ? reverseSignal(sourcePath) : sourcePath;
    const activeProgress = frame.acknowledging ? frame.ackSignal : frame.signal;
    const pulse = pointOnSignal(path, activeProgress);
    const signalOpacity = frame.sending ? frame.signalFade : frame.acknowledging ? frame.ackFade : 0;
    return <div className="dn-block" ref={node => { this.root = node; }}
      role="button" tabIndex={0} aria-label={`${running ? 'Pause' : 'Play'} device network animation`}
      aria-describedby="device-network-description" aria-keyshortcuts="Space Enter R"
      onClick={this.toggle} onKeyDown={this.keyDown}
      data-device-network="" data-playing={running} data-reduced={reduced} data-compact={compact}
      data-elapsed={Math.round(elapsed)} data-cycle={frame.cycle} data-phase={frame.phase} data-sender={DEVICES[frame.sender].id} data-ack-sender={DEVICES[frame.sender].id} data-ack-progress={frame.ackSignal.toFixed(4)} data-ack-effect={frame.ackEffect.toFixed(4)}
      title="Click or press Space to pause/play. Press R to replay.">
      <span className="dn-sr" id="device-network-description">Illustration: different Controller computers send one task at a time to a configured Host. The laptop turns red, works, and returns to idle while keeping its Session. macOS, Windows and Linux Controllers are supported. Native Hosts require live readiness; this is not universal device support. Click, Space or Enter toggles playback. R restarts.</span>
      <div className="dn-corner" aria-hidden="true"><span className="dn-corner-dot" />CONTROLLER → HOST</div>
      <svg className="dn-canvas" viewBox={`0 0 ${box.width} ${box.height}`} aria-hidden="true" focusable="false">
        <ellipse className="dn-orbit" cx={box.cx} cy={box.cy} rx={box.rx} ry={box.ry} />
        <ellipse className="dn-orbit dn-orbit-inner" cx={box.cx} cy={box.cy} rx={box.rx - 36} ry={box.ry - 23} />
        {DEVICES.map((device, i) => <path key={device.id} className="dn-route" d={signalPath(i, elapsed, compact).d} />)}
        <path className="dn-active-route" d={path.d} opacity={signalOpacity * 0.46} />
        <g className="dn-signal" data-signal="" data-visible={frame.sending || frame.acknowledging} data-direction={frame.acknowledging ? "return" : "outgoing"} opacity={signalOpacity}>
          <path className="dn-signal-trace" d={path.d} pathLength={1} strokeDasharray=".2 .8" strokeDashoffset={1 - activeProgress} />
          <circle className="dn-signal-halo" cx={pulse.x} cy={pulse.y} r={compact ? 11 : 9} />
          <circle className="dn-signal-dot" cx={pulse.x} cy={pulse.y} r={compact ? 4.2 : 3.6} />
        </g>
        {DEVICES.map((device, i) => {
          const point = devicePoint(i, elapsed, compact);
          return <g key={device.id} data-network-device={device.id} transform={`translate(${point.x} ${point.y}) rotate(${point.tilt}) scale(${box.deviceScale})`}>
            <Device shape={device.shape} selected={i === frame.sender && frame.sending} acknowledged={i === frame.sender && frame.ackEffect > 0} />
          </g>;
        })}
        <g transform={`translate(${box.cx} ${box.cy}) scale(${box.hostScale})`}>
          <Host frame={frame} />
        </g>
      </svg>
      <div className="dn-host-caption" aria-hidden="true"><strong>Your Host</strong><span data-active={frame.heat > 0}>{frame.phase === 'working' ? 'Working' : frame.phase === 'receiving' ? 'Receiving' : frame.phase === 'complete' ? 'Task complete' : frame.phase === 'acknowledging' ? 'Confirming' : frame.phase === 'cooling' ? 'Cooling down' : 'Ready for the next task'}</span></div>
      <span className="dn-sr" role="status" aria-live={running ? 'off' : 'polite'}>{frame.phase === 'working' ? 'The Host is working.' : frame.phase === 'acknowledging' ? 'The Host is confirming completion.' : 'The Host is waiting.'}</span>
    </div>;
  }
}

function reverseSignal(path: ReturnType<typeof signalPath>) {
  return { ...path, a: path.b, b: path.a, d: 'M ' + path.b.x + ' ' + path.b.y + ' Q ' + path.control.x + ' ' + path.control.y + ' ' + path.a.x + ' ' + path.a.y };
}

/** Desktop-class silhouettes only: these do not advertise a mobile app,
 * phone Host, arbitrary server desktop, or automatic discovery. */
function Device({ shape, selected, acknowledged }: { shape: DeviceShape; selected: boolean; acknowledged: boolean }) {
  return <g className="dn-device" data-selected={selected} data-acknowledged={acknowledged}>
    {acknowledged && <ellipse className="dn-ack-ring" cx="0" cy="0" rx="52" ry="45" />}
    {shape === 'laptop' || shape === 'notebook' ? <>
      <rect x="-35" y="-32" width="70" height="46" rx="4" />
      <rect className="dn-device-screen" x="-29" y="-26" width="58" height="34" rx="1.5" />
      <path d="m-35 14-12 16q0 4 5 4h84q5 0 5-4L35 14Z" />
      <path className="dn-detail" d="M-29 20h58M-9 25H9M-14 34h28" />
      {shape === 'notebook' && <path className="dn-detail" d="m-12-13 6 5-6 5M0-3h12" />}
    </> : null}
    {shape === 'desktop' ? <>
      <rect x="-40" y="-37" width="80" height="54" rx="4" />
      <rect className="dn-device-screen" x="-34" y="-31" width="68" height="39" rx="1" />
      <path d="M-7 17v15l-17 5h48l-17-5V17" />
      <path className="dn-detail" d="M-30-21h22M-30-15h38M-30-9h30" />
    </> : null}
    {shape === 'rack' ? <>
      <rect x="-27" y="-43" width="54" height="86" rx="5" />
      {[-32,-12,8].map(y => <g key={y}><rect className="dn-device-screen" x="-20" y={y} width="40" height="15" rx="2" /><path className="dn-detail" d={`M-12 ${y+5}h17m-17 5H5`} /><circle className="dn-led" cx="13" cy={y+7.5} r="1.5" /></g>)}
      <path className="dn-detail" d="M-13 34h26" />
    </> : null}
    {shape === 'mini' ? <>
      <path d="m-36-19 39-11 33 13v44L-4 39l-32-14Z" />
      <path className="dn-detail" d="m-36-19 32 14 40-12M-4-5v44M-25 5l12 5m-12-1 12 5" />
      <circle className="dn-led" cx="22" cy="17" r="2" />
      <path className="dn-detail" d="M7 23l8-3" />
    </> : null}
    {shape === 'workstation' ? <>
      <rect x="-45" y="-29" width="60" height="43" rx="3" />
      <rect className="dn-device-screen" x="-40" y="-24" width="50" height="30" rx="1" />
      <path d="M-19 14v15m-11 3h25" />
      <rect x="23" y="-38" width="27" height="70" rx="3" />
      <path className="dn-detail" d="M29-27h15m-15 5h15m-15 6h15m-15 6h15" />
      <circle className="dn-led" cx="36.5" cy="19" r="2.5" />
    </> : null}
  </g>;
}

function Host({ frame }: { frame: NetworkFrame }) {
  const p = frame.progress;
  const complete = frame.progress >= 1;
  const echo = frame.phase === 'receiving' ? (frame.local - TIMING.arrive) / (TIMING.work - TIMING.arrive) : 1;
  return <g className="dn-host" data-network-host="" data-heat={frame.heat.toFixed(4)} data-working={frame.working} data-progress={p.toFixed(4)}>
    <ellipse className="dn-host-ground" cx="0" cy="89" rx="163" ry="15" />
    <ellipse className="dn-receive-ring" cx="0" cy="-16" rx={123 + echo * 24} ry={81 + echo * 16} opacity={(1 - echo) * 0.4} />
    <rect className="dn-host-case" x="-119" y="-91" width="238" height="155" rx="9" />
    <rect className="dn-host-screen" x="-109" y="-80" width="218" height="132" rx="3" />
    <rect className="dn-host-tint" x="-119" y="-91" width="238" height="155" rx="9" opacity={frame.heat} />
    <circle className="dn-camera" cx="0" cy="-85.5" r="1.5" />
    <path className="dn-host-base" d="m-119 64-34 24q0 8 11 8h284q11 0 11-8l-34-24Z" />
    <path className="dn-host-base-active" d="m-119 64-34 24q0 8 11 8h284q11 0 11-8l-34-24Z" opacity={frame.heat} />
    <path className="dn-host-keyboard" d="m-90 69-11 10h202L90 69ZM-25 82l-5 7h60l-5-7Z" />
    <path className="dn-host-detail" d="M-153 88h306M-39 96h78" />
    {/* A small native-window illustration communicates work, not terminal text. */}
    <g className="dn-screen-idle" opacity={frame.heat > 0 ? 0 : 1}>
      <rect x="-30" y="-38" width="60" height="43" rx="5" />
      <path d="M-13-21h26m-18 8h18M-9 14H9" />
      <circle cx="-18" cy="-30" r="1" /><circle cx="-12" cy="-30" r="1" />
    </g>
    <g className="dn-screen-work" opacity={frame.heat}>
      <rect className="dn-app-window" x="-88" y="-63" width="176" height="99" rx="4" />
      <path className="dn-app-rule" d="M-88-44H88M-46-44v80" />
      <circle className="dn-app-dot" cx="-77" cy="-54" r="2" /><circle className="dn-app-dot" cx="-69" cy="-54" r="2" /><circle className="dn-app-dot" cx="-61" cy="-54" r="2" />
      <path className="dn-app-rule" d="M-76-29h19m-19 10h13m-13 10h17M-32-28H68M-32-9H54M-32 10H63" />
      {[0,1,2].map(i => <g key={i}>
        <rect className="dn-work-row" x="-32" y={-30+i*19} width={(i === 0 ? 99 : i === 1 ? 84 : 93) * smooth((p - i * 0.22) / 0.32)} height="4" rx="2" />
        {p > 0.32 + i * 0.22 && <path className="dn-work-tick" d={`m73 ${-29+i*19} 3 3 6-7`} />}
      </g>)}
      <rect className="dn-progress-track" x="-76" y="25" width="152" height="3" rx="1.5" />
      <rect className="dn-progress-fill" x="-76" y="25" width={152*p} height="3" rx="1.5" />
      {frame.working && <path className="dn-work-cursor" d="m0 0 0 12 3-3 3 6 2-1-3-6 5 0Z" transform={`translate(${40 + Math.sin(p*Math.PI*2)*26} ${-18 + p*28})`} />}
      {complete && <g className="dn-complete-check"><circle cx="0" cy="-14" r="20" /><path d="m-9-14 6 6 13-15" /></g>}
    </g>
  </g>;
}
