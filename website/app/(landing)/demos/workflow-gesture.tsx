'use client';
import * as React from 'react';
import { COMMIT_DELAY, DRAG_DURATION, POINTER_TRAVEL, ease, type SceneProps } from './exploration-data';

type Point = { x: number; y: number };
type Geometry = { from: Point; hit: Point; end: Point; measured: boolean; step: number };
const origin = { x: 18, y: 18 };
/** Targets are sampled BEFORE the click changes the UI and held for that beat.
 * Drag endpoints are separate fixed markers, so the pointer and window/slider
 * share exactly the same interpolation. No chasing a moving/disappearing node. */
export class GestureCursor extends React.Component<SceneProps, Geometry> {
  state: Geometry = { from: origin, hit: origin, end: origin, measured: false, step: -1 };
  private node: HTMLSpanElement | null = null;
  private observer?: ResizeObserver;
  private last: Point = origin;
  componentDidMount() {
    this.measure(true);
    if (this.node?.parentElement && typeof ResizeObserver !== 'undefined') {
      this.observer = new ResizeObserver(() => this.measure(false));
      this.observer.observe(this.node.parentElement);
    }
  }
  componentWillUnmount() { this.observer?.disconnect(); }
  componentDidUpdate(previous: SceneProps) {
    if (previous.frame.elapsed > this.props.frame.elapsed) this.last = origin;
    if (previous.frame.step !== this.props.frame.step || previous.frame.elapsed > this.props.frame.elapsed) this.measure(previous.frame.elapsed > this.props.frame.elapsed);
  }
  private measure = (reset: boolean) => {
    const root = this.node?.parentElement;
    const { target, dragTo } = this.props.frame;
    if (!root || !target) return;
    const rect = root.getBoundingClientRect();
    const locate = (id: string): Point | null => {
      const candidates = Array.from(root.querySelectorAll<HTMLElement>(`[data-cursor="${id}"]`));
      const el = candidates.find(node => { const r = node.getBoundingClientRect(); return r.width > 0 && r.height > 0; });
      if (!el) return null;
      const r = el.getBoundingClientRect();
      return { x: r.left - rect.left + r.width / 2, y: r.top - rect.top + r.height / 2 };
    };
    const hit = locate(target);
    if (!hit) return;
    this.setState({ from: reset ? origin : this.last, hit, end: dragTo ? locate(dragTo) ?? hit : hit, measured: true, step: this.props.frame.step });
  };
  render() {
    const { frame } = this.props;
    const { from, hit, end } = this.state;
    const travel = ease(Math.min(1, frame.local / POINTER_TRAVEL));
    const drag = ease(Math.min(1, Math.max(0, (frame.local - COMMIT_DELAY) / DRAG_DURATION)));
    const point = frame.step !== this.state.step ? this.last : frame.dragTo && frame.local >= COMMIT_DELAY
      ? { x: hit.x + (end.x - hit.x) * drag, y: hit.y + (end.y - hit.y) * drag }
      : { x: from.x + (hit.x - from.x) * travel, y: from.y + (hit.y - from.y) * travel };
    if (this.state.measured && frame.target && frame.step === this.state.step) this.last = point;
    const pressed = frame.dragTo ? frame.local >= COMMIT_DELAY && frame.local < COMMIT_DELAY + DRAG_DURATION : frame.local >= POINTER_TRAVEL && frame.local < COMMIT_DELAY + 110;
    return <span className="rf-cursor" ref={node => { this.node = node; }} data-pressed={pressed} data-target={frame.target ?? ''} data-dragging={Boolean(frame.dragTo && pressed)} style={{ visibility: frame.target && !frame.done && this.state.measured ? 'visible' : 'hidden', transform: `translate(${point.x}px, ${point.y}px)` }}>
      <i /><svg width="19" height="25" viewBox="0 0 22 28"><path d="M2 2v21l5-5 4 8 4-2-4-8h8Z" fill="var(--sa-12)" stroke="var(--sa-1)" strokeWidth="1.7" /></svg>
    </span>;
  }
}
