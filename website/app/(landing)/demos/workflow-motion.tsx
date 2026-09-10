'use client';
import * as React from 'react';
import * as data from './exploration-data';

type Props = { id: data.DemoId; children: (frame: data.Frame, moving: boolean) => React.ReactNode };
type State = { elapsed: number; running: boolean; reduced: boolean; optedIn: boolean; cycle: number };

/** A chrome-free player. The scene itself is an accessible playback surface:
 * click/Space/Enter toggles, R replays. Reduced motion requires explicit opt-in.
 * Every animation receives the same 1.25x clock, including the final hold. */
export class WorkflowPlayer extends React.Component<Props, State> {
  state: State = { elapsed: data.duration(data.TIMELINES[this.props.id]), running: false, reduced: false, optedIn: false, cycle: 0 };
  private root: HTMLDivElement | null = null;
  private observer?: IntersectionObserver;
  private media?: MediaQueryList;
  private raf = 0;
  private clock = this.state.elapsed;
  private previous: number | null = null;
  private painted = 0;
  private inView = false;
  private paused = false;
  private mounted = false;
  private reduced = false;
  private optedIn = false;
  private cycle = 0;

  componentDidMount() {
    this.mounted = true;
    this.media = window.matchMedia('(prefers-reduced-motion: reduce)');
    this.media.addEventListener('change', this.preference);
    document.addEventListener('visibilitychange', this.sync);
    this.preference();
    if ('IntersectionObserver' in window && this.root) {
      this.observer = new IntersectionObserver(([entry]) => {
        this.inView = entry.isIntersecting && entry.intersectionRatio >= 0.1;
        this.sync();
      }, { threshold: [0, 0.1] });
      this.observer.observe(this.root);
    } else { this.inView = true; this.sync(); }
  }
  componentWillUnmount() {
    this.mounted = false;
    cancelAnimationFrame(this.raf);
    this.observer?.disconnect();
    this.media?.removeEventListener('change', this.preference);
    document.removeEventListener('visibilitychange', this.sync);
  }
  private preference = () => {
    this.reduced = this.media?.matches ?? false;
    this.optedIn = false;
    this.clock = this.reduced ? data.duration(data.TIMELINES[this.props.id]) : 0;
    this.previous = null;
    this.cycle = 0;
    this.setState({ reduced: this.reduced, optedIn: false, elapsed: this.clock, cycle: 0 }, this.sync);
  };
  private allowed = () => this.mounted && !this.paused && this.inView && !document.hidden
    && (!this.reduced || (this.optedIn && this.clock < data.duration(data.TIMELINES[this.props.id])));
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
    const total = data.duration(data.TIMELINES[this.props.id]);
    this.clock += this.previous === null ? 0 : data.playbackDelta(now - this.previous);
    this.previous = now;
    if (!this.reduced && this.clock >= total + data.LOOP_HOLD) { this.clock = 0; this.cycle++; }
    if (this.reduced) this.clock = Math.min(total, this.clock);
    if (now - this.painted >= 30 || this.clock === total || this.clock === 0) {
      this.painted = now;
      this.setState({ elapsed: this.clock, cycle: this.cycle });
    }
    this.sync();
  };
  private replay = () => {
    this.clock = 0;
    this.previous = null;
    this.paused = false;
    this.optedIn = true;
    this.setState({ elapsed: 0, optedIn: true }, this.sync);
  };
  private toggle = () => {
    if (this.reduced && (!this.optedIn || this.clock >= data.duration(data.TIMELINES[this.props.id]))) {
      this.replay(); return;
    }
    this.paused = !this.paused;
    this.sync();
  };
  private keyDown = (event: React.KeyboardEvent<HTMLDivElement>) => {
    if (event.altKey || event.ctrlKey || event.metaKey || event.repeat) return;
    if (event.key === ' ' || event.key === 'Enter') { event.preventDefault(); this.toggle(); }
    else if (event.key.toLowerCase() === 'r') { event.preventDefault(); this.replay(); }
  };
  render() {
    const { id } = this.props;
    const { running, reduced, optedIn } = this.state;
    const frame = data.sample(data.TIMELINES[id], this.state.elapsed);
    const action = running ? 'Pause' : 'Play';
    return <div className="sw-player" ref={node => { this.root = node; }}
      role="button" tabIndex={0} aria-label={`${action} ${id} animation`}
      aria-keyshortcuts="Space Enter R" aria-describedby={`${id}-playback-help`}
      title="Click or press Space to pause/play. Press R to replay."
      onClick={this.toggle} onKeyDown={this.keyDown}
      data-playing={running} data-step={frame.step} data-elapsed={Math.round(frame.elapsed)}
      data-cycle={this.state.cycle} data-complete={frame.done} data-reduced={reduced}
      data-motion-opt-in={optedIn} data-playback-rate={data.PLAYBACK_RATE}>
      <div className="sw-scene" aria-hidden="true">{this.props.children(frame, running)}</div>
      <span className="sw-a11y-status" id={`${id}-playback-help`}>
        Animated illustration. Click, Space or Enter toggles playback. R restarts it.
        {reduced && !optedIn ? ' Reduced motion is enabled; playback starts only by choice.' : ''}
      </span>
      <span className="sw-a11y-status" role="status" aria-live={running ? 'off' : 'polite'} aria-atomic="true">{frame.label}</span>
    </div>;
  }
}

/** Kept for the legacy, unmounted scene modules. Active landing scenes use the
 * measured, sequence-aware GestureCursor in workflow-gesture.tsx. */
type Point = { x: number; y: number };
type CursorProps = { target?: string; progress: number; click: boolean; visible: boolean; layout: number };
export class DemoCursor extends React.Component<CursorProps, { from: Point; to: Point }> {
  state = { from: { x: 24, y: 80 }, to: { x: 24, y: 80 } };
  private node: HTMLSpanElement | null = null;
  private observer?: ResizeObserver;
  private measure = () => {
    const root = this.node?.parentElement;
    if (!root || !this.props.target) return;
    const target = Array.from(root.querySelectorAll<HTMLElement>(`[data-cursor="${this.props.target}"]`))
      .find(node => { const r = node.getBoundingClientRect(); return r.width > 0 && r.height > 0; });
    if (!target) return;
    const a = root.getBoundingClientRect(), b = target.getBoundingClientRect();
    const to = { x: Math.max(0, Math.min(a.width - 22, b.left - a.left + b.width / 2)), y: Math.max(0, Math.min(a.height - 28, b.top - a.top + b.height / 2)) };
    if (Math.abs(to.x - this.state.to.x) + Math.abs(to.y - this.state.to.y) > 0.5) this.setState(state => ({ from: state.to, to }));
  };
  componentDidMount() {
    this.measure();
    if (this.node?.parentElement && typeof ResizeObserver !== 'undefined') {
      this.observer = new ResizeObserver(this.measure); this.observer.observe(this.node.parentElement);
    }
  }
  componentDidUpdate(previous: CursorProps) { if (previous.target !== this.props.target || previous.layout !== this.props.layout) this.measure(); }
  componentWillUnmount() { this.observer?.disconnect(); }
  render() {
    const { from, to } = this.state, q = data.ease(this.props.progress);
    return <span className="sw-cursor" ref={node => { this.node = node; }} aria-hidden="true" style={{ visibility: this.props.visible && this.props.target ? 'visible' : 'hidden', transform: `translate(${from.x + (to.x - from.x) * q}px, ${from.y + (to.y - from.y) * q}px)` }}>
      <i style={{ opacity: this.props.click ? 0.65 : 0, transform: `scale(${this.props.click ? 1 : 0.45})` }} />
      <svg width="22" height="28" viewBox="0 0 22 28"><path d="M2 2v21l5-5 4 8 4-2-4-8h8Z" fill="var(--sa-12)" stroke="var(--sa-0)" strokeWidth="1.7" /></svg>
    </span>;
  }
}
