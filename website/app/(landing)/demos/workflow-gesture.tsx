'use client';
import * as React from 'react';
import * as data from './exploration-data';

type Point = { x: number; y: number };
type Geometry = { from: Point; hit: Point; end: Point; measured: boolean; step: number; target?: string };
const origin = { x: 18, y: 18 };

/** Capture before a click mutates the app. Keep the released pointer visible
 * between adjacent actions, including the render that measures the next target.
 * Missing targets clear geometry before paint; post-click modal removal does not. */
export class GestureCursor extends React.Component<data.SceneProps, Geometry> {
  state: Geometry = { from: origin, hit: origin, end: origin, measured: false, step: -1 };
  private node: HTMLSpanElement | null = null;
  private observer?: ResizeObserver;
  private last = origin;
  componentDidMount() {
    this.measure(true);
    if (this.node?.parentElement && typeof ResizeObserver !== 'undefined') {
      this.observer = new ResizeObserver(() => this.measure(false));
      this.observer.observe(this.node.parentElement);
    }
  }
  componentWillUnmount() { this.observer?.disconnect(); }
  componentDidUpdate(previous: data.SceneProps) {
    const reset = previous.frame.elapsed > this.props.frame.elapsed;
    if (reset) this.last = origin;
    if (previous.frame.step !== this.props.frame.step || reset) this.measure(reset);
    else if (!this.state.measured && this.props.frame.local < data.POINTER_PRESS) this.measure(false);
  }
  private measure = (reset: boolean) => {
    const root = this.node?.parentElement, { frame } = this.props;
    if (!root || !frame.target) {
      if (this.state.measured) this.setState({ measured: false, step: frame.step, target: undefined });
      return;
    }
    // UI actions can remove their clicked node. Retain its captured position
    // throughout this beat, rather than hiding or chasing the closing dialog.
    if (!reset && this.state.step === frame.step && frame.local >= data.COMMIT_DELAY) return;
    const rect = root.getBoundingClientRect();
    const locate = (id: string, endpoint = false): Point | null => {
      const el = Array.from(root.querySelectorAll<HTMLElement>(`[data-cursor="${id}"]`)).find(node => {
        const r = node.getBoundingClientRect();
        if (!r.width || !r.height || r.left < rect.left - 1 || r.right > rect.right + 1 || r.top < rect.top - 1 || r.bottom > rect.bottom + 1) return false;
        if (endpoint) return true; // Intentional invisible drag destination.
        for (let p: HTMLElement | null = node; p && p !== root; p = p.parentElement) {
          const style = getComputedStyle(p);
          if (style.visibility === 'hidden' || style.display === 'none' || Number(style.opacity) === 0) return false;
        }
        return true;
      });
      if (!el) return null;
      const r = el.getBoundingClientRect();
      return { x: r.left - rect.left + r.width / 2, y: r.top - rect.top + r.height / 2 };
    };
    const hit = locate(frame.target), end = frame.dragTo ? locate(frame.dragTo, true) : hit;
    if (!hit || !end) {
      if (this.state.measured || this.state.step !== frame.step) this.setState({ measured: false, step: frame.step, target: frame.target });
      return;
    }
    const from = reset ? origin : this.last;
    this.setState({ from: { x: Math.max(0, Math.min(rect.width - 20, from.x)), y: Math.max(0, Math.min(rect.height - 25, from.y)) }, hit, end, measured: true, step: frame.step, target: frame.target });
  };
  render() {
    const { frame } = this.props, { from, hit, end } = this.state;
    const current = frame.step === this.state.step;
    const bridge = this.state.measured && this.state.step === frame.step - 1
      && this.state.target === frame.previousTarget && Boolean(frame.target);
    const travel = data.ease(Math.min(1, frame.local / data.POINTER_TRAVEL));
    const drag = data.ease(Math.min(1, Math.max(0, (frame.local - data.COMMIT_DELAY) / data.DRAG_DURATION)));
    const point = !current ? this.last : frame.dragTo && frame.local >= data.COMMIT_DELAY
      ? { x: hit.x + (end.x - hit.x) * drag, y: hit.y + (end.y - hit.y) * drag }
      : { x: from.x + (hit.x - from.x) * travel, y: from.y + (hit.y - from.y) * travel };
    if (this.state.measured && frame.target && current) this.last = point;
    const timing = data.gesturePhase(frame);
    const visible = timing.visible && this.state.measured && (current || bridge);
    const pressed = visible && current && timing.pressed;
    return <span className="rf-cursor" ref={node => { this.node = node; }} aria-hidden="true"
      data-visible={visible} data-pressed={pressed} data-target={frame.target ?? ''}
      data-dragging={pressed && timing.dragging}
      style={{ visibility: visible ? 'visible' : 'hidden', transform: `translate(${point.x}px, ${point.y}px)` }}>
      <i /><svg width="19" height="25" viewBox="0 0 22 28"><path d="M2 2v21l5-5 4 8 4-2-4-8h8Z" fill="var(--sa-12)" stroke="var(--sa-1)" strokeWidth="1.7" /></svg>
    </span>;
  }
}
