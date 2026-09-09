'use client';
import * as React from 'react';
import { duration, sample, TIMELINES, LOOP_HOLD, type DemoId, type Frame } from './exploration-data';

type Props = { id: DemoId; children: (frame: Frame, moving: boolean) => React.ReactNode };
type State = { elapsed: number; running: boolean; reduced: boolean; optedIn: boolean; cycle: number };

/** Reduced motion used to remove Play entirely, and Replay only changed stills.
 * Explicit Play now opts into ONE animation. Normal autoplay loops on screen;
 * the clock is suspended offscreen/hidden, and manual Pause always persists. */
export class WorkflowPlayer extends React.Component<Props, State> {
  state: State = { elapsed: duration(TIMELINES[this.props.id]), running: false, reduced: false, optedIn: false, cycle: 0 };
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
    this.clock = this.reduced ? duration(TIMELINES[this.props.id]) : 0;
    this.previous = null;
    this.cycle = 0;
    this.setState({ reduced: this.reduced, optedIn: false, elapsed: this.clock, cycle: 0 }, this.sync);
  };
  private allowed = () => this.mounted && !this.paused && this.inView && !document.hidden
    && (!this.reduced || (this.optedIn && this.clock < duration(TIMELINES[this.props.id])));
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
    const total = duration(TIMELINES[this.props.id]);
    this.clock += this.previous === null ? 0 : Math.min(100, now - this.previous);
    this.previous = now;
    if (!this.reduced && this.clock >= total + LOOP_HOLD) { this.clock = 0; this.cycle++; }
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
    if (this.reduced && (!this.optedIn || this.clock >= duration(TIMELINES[this.props.id]))) { this.replay(); return; }
    this.paused = !this.paused;
    this.sync();
  };
  render() {
    const { id } = this.props;
    const { running, reduced, optedIn } = this.state;
    const frame = sample(TIMELINES[id], this.state.elapsed);
    return <div className="sw-player" ref={(node) => { this.root = node; }}
      data-playing={running} data-step={frame.step} data-elapsed={Math.round(frame.elapsed)}
      data-cycle={this.state.cycle} data-complete={frame.done} data-reduced={reduced} data-motion-opt-in={optedIn}>
      <div className="sw-scene" aria-hidden="true">{this.props.children(frame, running)}</div>
      <div className="sw-playback">
        <span className="sw-playback-label" role="status" aria-live={running ? 'off' : 'polite'} aria-atomic="true"><i aria-hidden="true" data-running={running} />{reduced && !optedIn ? 'Animation paused for reduced motion' : frame.label}</span>
        <div className="sw-playback-actions">
          <button type="button" onClick={this.toggle} aria-label={`${running ? 'Pause' : 'Play'} ${id} animation`}>{running ? 'Pause' : 'Play animation'}</button>
          <button type="button" onClick={this.replay} aria-label={`Replay ${id} demo`}>Replay <span aria-hidden="true">↻</span></button>
        </div>
      </div>
    </div>;
  }
}

type Point = { x: number; y: number };
type CursorProps = { target?: string; progress: number; click: boolean; visible: boolean; layout: number };
export class DemoCursor extends React.Component<CursorProps, { from: Point; to: Point }> {
  state = { from: { x: 24, y: 80 }, to: { x: 24, y: 80 } };
  private node: HTMLSpanElement | null = null;
  private observer?: ResizeObserver;
  componentDidMount() {
    this.measure();
    if (this.node?.parentElement && typeof ResizeObserver !== 'undefined') {
      this.observer = new ResizeObserver(this.measure);
      this.observer.observe(this.node.parentElement);
    }
  }
  componentDidUpdate(previous: CursorProps) {
    if (previous.target !== this.props.target || previous.layout !== this.props.layout) this.measure();
  }
  componentWillUnmount() { this.observer?.disconnect(); }
  private measure = () => {
    const root = this.node?.parentElement;
    if (!root || !this.props.target) return;
    const target = Array.from(root.querySelectorAll<HTMLElement>(`[data-cursor="${this.props.target}"]`))
      .find((node) => { const r = node.getBoundingClientRect(); return r.width > 0 && r.height > 0; });
    if (!target) return;
    const a = root.getBoundingClientRect(), b = target.getBoundingClientRect();
    const to = { x: Math.max(0, Math.min(a.width - 22, b.left - a.left + b.width / 2)), y: Math.max(0, Math.min(a.height - 28, b.top - a.top + b.height / 2)) };
    if (Math.abs(to.x - this.state.to.x) + Math.abs(to.y - this.state.to.y) > 0.5) this.setState((state) => ({ from: state.to, to }));
  };
  render() {
    const { from, to } = this.state;
    const p = this.props.progress, q = p * p * (3 - 2 * p);
    return <span className="sw-cursor" ref={(node) => { this.node = node; }} aria-hidden="true" style={{ visibility: this.props.visible && this.props.target ? 'visible' : 'hidden', transform: `translate(${from.x + (to.x - from.x) * q}px, ${from.y + (to.y - from.y) * q}px)` }}>
      <i style={{ opacity: this.props.click ? 0.65 : 0, transform: `scale(${this.props.click ? 1 : 0.45})` }} />
      <svg width="22" height="28" viewBox="0 0 22 28"><path d="M2 2v21l5-5 4 8 4-2-4-8h8Z" fill="var(--sa-12)" stroke="var(--sa-0)" strokeWidth="1.7" /></svg>
    </span>;
  }
}
