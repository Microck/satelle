'use client';

import * as React from 'react';
import { duration, sample, stepStart, TIMELINES, type DemoId, type Frame } from './exploration-data';

type Props = { id: DemoId; children: (frame: Frame, moving: boolean) => React.ReactNode };
type State = { elapsed: number; running: boolean; reduced: boolean };

/** Finite, view-triggered playback. A hidden page or offscreen card suspends the
 * clock, not just its paint. SSR and reduced motion show the complete scene. */
export class WorkflowPlayer extends React.Component<Props, State> {
  state: State = { elapsed: duration(TIMELINES[this.props.id]), running: false, reduced: false };
  private root: HTMLDivElement | null = null;
  private observer?: IntersectionObserver;
  private media?: MediaQueryList;
  private raf = 0;
  private elapsed = this.state.elapsed;
  private previous = 0;
  private painted = 0;
  private inView = false;
  private paused = false;
  private mounted = false;

  componentDidMount() {
    this.mounted = true;
    this.media = window.matchMedia('(prefers-reduced-motion: reduce)');
    this.media.addEventListener('change', this.preference);
    document.addEventListener('visibilitychange', this.sync);
    this.preference();
    if ('IntersectionObserver' in window && this.root) {
      this.observer = new IntersectionObserver(([entry]) => {
        this.inView = entry.isIntersecting && entry.intersectionRatio >= 0.15;
        this.sync();
      }, { threshold: 0.15 });
      this.observer.observe(this.root);
    } else {
      this.inView = true;
      this.sync();
    }
  }
  componentWillUnmount() {
    this.mounted = false;
    cancelAnimationFrame(this.raf);
    this.observer?.disconnect();
    this.media?.removeEventListener('change', this.preference);
    document.removeEventListener('visibilitychange', this.sync);
  }
  private preference = () => {
    const reduced = this.media?.matches ?? false;
    this.elapsed = reduced ? duration(TIMELINES[this.props.id]) : 0;
    this.previous = 0;
    this.paused = false;
    this.setState({ reduced, elapsed: this.elapsed }, this.sync);
  };
  private sync = () => {
    if (!this.mounted) return;
    const running = !this.state.reduced && !this.paused && this.inView && !document.hidden && this.elapsed < duration(TIMELINES[this.props.id]);
    if (running && !this.raf) this.raf = requestAnimationFrame(this.tick);
    if (!running) {
      cancelAnimationFrame(this.raf);
      this.raf = 0;
      this.previous = 0;
    }
    if (this.state.running !== running) this.setState({ running });
  };
  private tick = (now: number) => {
    this.raf = 0;
    if (!this.mounted) return;
    const total = duration(TIMELINES[this.props.id]);
    this.elapsed = Math.min(total, this.elapsed + (this.previous ? now - this.previous : 0));
    this.previous = now;
    if (now - this.painted >= 30 || this.elapsed === total) {
      this.painted = now;
      this.setState({ elapsed: this.elapsed });
    }
    this.sync();
  };
  private replay = () => {
    this.elapsed = this.state.reduced ? duration(TIMELINES[this.props.id]) : 0;
    this.previous = 0;
    this.paused = false;
    this.setState({ elapsed: this.elapsed }, this.sync);
  };
  private toggle = () => {
    if (this.elapsed === duration(TIMELINES[this.props.id])) return this.replay();
    this.paused = !this.paused;
    this.sync();
  };
  private seek = (index: number) => {
    const beats = TIMELINES[this.props.id];
    this.paused = true;
    this.elapsed = stepStart(beats, index) + beats[index].ms - 1;
    this.setState({ elapsed: this.elapsed }, this.sync);
  };
  render() {
    const { id } = this.props;
    const { running, reduced } = this.state;
    const beats = TIMELINES[id];
    const frame = sample(beats, this.state.elapsed);
    return (
      <div className="sw-player" ref={(node) => { this.root = node; }} data-playing={running} data-step={frame.step} data-complete={frame.done} data-reduced={reduced}>
        <div className="sw-scene">{this.props.children(frame, running)}</div>
        <div className="sw-playback">
          <div className="sw-playback-label" role="status" aria-live="polite" aria-atomic="true">
            <span className="sw-state-dot" data-running={running} aria-hidden="true" />
            <span>{frame.label}</span>
          </div>
          <div className="sw-playback-actions">
            {!reduced && <button type="button" onClick={this.toggle} aria-label={`${running ? 'Pause' : 'Play'} ${id} animation`}>{running ? 'Pause' : frame.done ? 'Play again' : 'Play'}</button>}
            <button type="button" onClick={this.replay} aria-label={`Replay ${id} demo`}>Replay <span aria-hidden="true">↻</span></button>
          </div>
        </div>
        <div className="sw-steps" role="group" aria-label={`${id} animation steps`}>
          {beats.map((beat, i) => <button type="button" key={beat.label} aria-label={`Show ${id} step ${i + 1}: ${beat.label}`} aria-current={i === frame.step ? 'step' : undefined} data-reached={i <= frame.step} onClick={() => this.seek(i)}><span style={{ width: `${i < frame.step ? 100 : i === frame.step ? Math.min(100, frame.local / beat.ms * 100) : 0}%` }} /></button>)}
        </div>
        {reduced && <p className="sw-reduced-note">Reduced motion: still frames. Use the steps to explore.</p>}
      </div>
    );
  }
}

type Point = { x: number; y: number };
type CursorProps = { target?: string; progress: number; click: boolean; visible: boolean };
/** Coordinates come from actual targets, so narrow layouts keep pointer fidelity.
 * Interpolation uses the demo clock rather than CSS transitions: Pause freezes it. */
export class DemoCursor extends React.Component<CursorProps, { from: Point; to: Point }> {
  state = { from: { x: 24, y: 90 }, to: { x: 24, y: 90 } };
  private node: HTMLSpanElement | null = null;
  private observer?: ResizeObserver;
  componentDidMount() {
    this.measure();
    const surface = this.node?.parentElement;
    if (surface && typeof ResizeObserver !== 'undefined') {
      this.observer = new ResizeObserver(this.measure);
      this.observer.observe(surface);
    }
  }
  componentDidUpdate(previous: CursorProps) {
    if (previous.target !== this.props.target) this.measure();
  }
  componentWillUnmount() { this.observer?.disconnect(); }
  private measure = () => {
    const root = this.node?.parentElement;
    if (!root || !this.props.target) return;
    const target = root.querySelector<HTMLElement>(`[data-cursor="${this.props.target}"]`);
    if (!target) return;
    const a = root.getBoundingClientRect();
    const b = target.getBoundingClientRect();
    const clamp = (point: Point) => ({ x: Math.max(0, Math.min(a.width - 24, point.x)), y: Math.max(0, Math.min(a.height - 29, point.y)) });
    const to = clamp({ x: b.left - a.left + b.width / 2, y: b.top - a.top + b.height / 2 });
    this.setState((state) => ({ from: clamp(state.to), to }));
  };
  render() {
    const { from, to } = this.state;
    const p = this.props.progress;
    const eased = p * p * (3 - 2 * p);
    return <span className="sw-cursor" ref={(node) => { this.node = node; }} aria-hidden="true" style={{ display: this.props.visible && this.props.target ? undefined : 'none', transform: `translate(${from.x + (to.x - from.x) * eased}px, ${from.y + (to.y - from.y) * eased}px)`, opacity: this.props.visible && this.props.target ? 1 : 0 }}>
      {this.props.click && <i key={this.props.target} />}
      <svg width="22" height="27" viewBox="0 0 22 27"><path d="M2 2v20l5-5 4 8 4-2-4-8h8Z" fill="var(--sa-12)" stroke="var(--sa-0)" strokeWidth="1.5" /></svg>
    </span>;
  }
}
