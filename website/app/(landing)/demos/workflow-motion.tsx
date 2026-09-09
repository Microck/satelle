'use client';

import * as React from 'react';
import { duration, sample, stepStart, TIMELINES, type DemoId, type Frame } from './exploration-data';

type PlayerProps = { id: DemoId; children: (frame: Frame, moving: boolean) => React.ReactNode };
type PlayerState = { elapsed: number; running: boolean; reduced: boolean };

/** Finite viewport-triggered playback. One clock drives typing, pointer movement,
 * window handoff, scrolling, and upload progress. No offscreen/hidden-tab work. */
export class WorkflowPlayer extends React.Component<PlayerProps, PlayerState> {
  state: PlayerState = { elapsed: duration(TIMELINES[this.props.id]), running: false, reduced: false };
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
    const running = !this.state.reduced && !this.paused && this.inView && !document.hidden
      && this.elapsed < duration(TIMELINES[this.props.id]);
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
    // Reduced motion restarts a sequence of stills, never automatic motion.
    this.elapsed = this.state.reduced ? TIMELINES[this.props.id][0].ms - 1 : 0;
    this.previous = 0;
    this.paused = false;
    this.setState({ elapsed: this.elapsed }, this.sync);
  };

  private toggle = () => { this.paused = !this.paused; this.sync(); };

  private nextStill = () => {
    const beats = TIMELINES[this.props.id];
    const next = (sample(beats, this.elapsed).step + 1) % beats.length;
    this.elapsed = stepStart(beats, next) + beats[next].ms - 1;
    this.setState({ elapsed: this.elapsed });
  };

  render() {
    const { id } = this.props;
    const { running, reduced } = this.state;
    const frame = sample(TIMELINES[id], this.state.elapsed);
    return (
      <div className="sw-player" ref={(node) => { this.root = node; }}
        data-playing={running} data-step={frame.step} data-complete={frame.done} data-reduced={reduced}>
        {/* App chrome is illustrative, not focusable or a live service. The status
            below describes the sequence without impersonating application controls. */}
        <div className="sw-scene" aria-hidden="true">{this.props.children(frame, running)}</div>
        <div className="sw-playback">
          <span className="sw-playback-label" role="status" aria-live="polite" aria-atomic="true">
            <i data-running={running} aria-hidden="true" />{frame.label}
          </span>
          <div className="sw-playback-actions">
            {!reduced && !frame.done && <button type="button" onClick={this.toggle}
              aria-label={`${running ? 'Pause' : 'Play'} ${id} animation`}>{running ? 'Pause' : 'Play'}</button>}
            {reduced && <button type="button" onClick={this.nextStill}
              aria-label={`Show next ${id} still frame`}>Next frame <span aria-hidden="true">›</span></button>}
            <button type="button" onClick={this.replay} aria-label={`Replay ${id} demo`}>Replay <span aria-hidden="true">↻</span></button>
          </div>
        </div>
      </div>
    );
  }
}

type Point = { x: number; y: number };
type CursorProps = { target?: string; progress: number; click: boolean; visible: boolean; layout: number };

/** Measure actual visible DOM targets, including after responsive layout changes.
 * Coordinates and click feedback are driven by the same pausable scene clock. */
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
      .find((node) => { const rect = node.getBoundingClientRect(); return rect.width > 0 && rect.height > 0; });
    if (!target) return;
    const a = root.getBoundingClientRect();
    const b = target.getBoundingClientRect();
    const to = {
      x: Math.max(0, Math.min(a.width - 22, b.left - a.left + b.width / 2)),
      y: Math.max(0, Math.min(a.height - 28, b.top - a.top + b.height / 2)),
    };
    if (Math.abs(to.x - this.state.to.x) + Math.abs(to.y - this.state.to.y) > 0.5)
      this.setState((state) => ({ from: state.to, to }));
  };

  render() {
    const { from, to } = this.state;
    const p = this.props.progress;
    const q = p * p * (3 - 2 * p);
    return <span className="sw-cursor" ref={(node) => { this.node = node; }} aria-hidden="true"
      style={{ visibility: this.props.visible && this.props.target ? 'visible' : 'hidden',
        transform: `translate(${from.x + (to.x - from.x) * q}px, ${from.y + (to.y - from.y) * q}px)` }}>
      <i style={{ opacity: this.props.click ? 0.65 : 0, transform: `scale(${this.props.click ? 1 : 0.45})` }} />
      <svg width="22" height="28" viewBox="0 0 22 28"><path d="M2 2v21l5-5 4 8 4-2-4-8h8Z"
        fill="var(--sa-12)" stroke="var(--sa-0)" strokeWidth="1.7" /></svg>
    </span>;
  }
}
