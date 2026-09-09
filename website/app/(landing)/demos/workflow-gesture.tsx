'use client';
import * as React from 'react';
import * as data from './exploration-data';

type Point = { x: number; y: number };
type Geometry = { from: Point; hit: Point; end: Point; measured: boolean; step: number };

const origin = { x: 18, y: 18 };
/** Sample the clickable target before the action removes it. Never chase the
 * disappearing window/dialog. A cursor exists only during a measured gesture;
 * no cursor or pressed ring is left over during typing, chat, or result holds. */
export class GestureCursor extends React.Component<data.SceneProps, Geometry> {
    private observer?: ResizeObserver;
    state: Geometry = { from: origin, hit: origin, end: origin, measured: false, step: -1 };
    private node: HTMLSpanElement | null = null;
    last = origin;
    private measure = (reset: boolean) => {
        const root = this.node?.parentElement;
        const { frame } = this.props;
        if (!root || !frame.target) {
            if (this.state.measured)
                this.setState({ measured: false, step: frame.step });
            return;
        }
        // After committing, retain the original target even if a modal was removed.
        if (!reset && this.state.step === frame.step && frame.local >= data.COMMIT_DELAY)
            return;
        const rect = root.getBoundingClientRect();
        const locate = (id: string, endpoint = false): Point | null => {
            const candidates = Array.from(root.querySelectorAll<HTMLElement>(`[data-cursor="${id}"]`));
            const el = candidates.find(node => {
                const r = node.getBoundingClientRect();
                if (!r.width || !r.height || r.left < rect.left - 1 || r.right > rect.right + 1 || r.top < rect.top - 1 || r.bottom > rect.bottom + 1)
                    return false;
                if (endpoint)
                    return true; // Drag destinations are intentionally invisible markers.
                for (let p: HTMLElement | null = node; p && p !== root; p = p.parentElement) {
                    const style = getComputedStyle(p);
                    if (style.visibility === 'hidden' || style.display === 'none' || Number(style.opacity) === 0)
                        return false;
                }
                return true;
            });
            if (!el)
                return null;
            const r = el.getBoundingClientRect();
            return { x: r.left - rect.left + r.width / 2, y: r.top - rect.top + r.height / 2 };
        };
        const hit = locate(frame.target);
        const end = frame.dragTo ? locate(frame.dragTo, true) : hit;
        if (!hit || !end) {
            if (this.state.measured || this.state.step !== frame.step)
                this.setState({ measured: false, step: frame.step });
            return;
        }
        const from = reset ? origin : this.last;
        this.setState({ from: { x: Math.max(0, Math.min(rect.width - 20, from.x)), y: Math.max(0, Math.min(rect.height - 25, from.y)) }, hit, end, measured: true, step: frame.step });
    };
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
        if (reset)
            this.last = origin;
        if (previous.frame.step !== this.props.frame.step || reset)
            this.measure(reset);
        // Font/layout settlement can make a target available after the first render.
        else if (!this.state.measured && this.props.frame.local < data.POINTER_PRESS)
            this.measure(false);
    }
    render() {
        const { frame } = this.props;
        const { from, hit, end } = this.state;
        const travel = data.ease(Math.min(1, frame.local / data.POINTER_TRAVEL));
        const drag = data.ease(Math.min(1, Math.max(0, (frame.local - data.COMMIT_DELAY) / data.DRAG_DURATION)));
        const point = frame.step !== this.state.step ? this.last : frame.dragTo && frame.local >= data.COMMIT_DELAY
            ? { x: hit.x + (end.x - hit.x) * drag, y: hit.y + (end.y - hit.y) * drag }
            : { x: from.x + (hit.x - from.x) * travel, y: from.y + (hit.y - from.y) * travel };
        if (this.state.measured && frame.target && frame.step === this.state.step)
            this.last = point;
        const timing = data.gesturePhase(frame);
        const visible = timing.visible && this.state.measured && frame.step === this.state.step;
        const pressed = visible && timing.pressed;
        return <span className="rf-cursor" ref={node => { this.node = node; }} aria-hidden="true" data-visible={visible} data-pressed={pressed} data-target={frame.target ?? ''} data-dragging={visible && timing.dragging} style={{ visibility: visible ? 'visible' : 'hidden', transform: `translate(${point.x}px, ${point.y}px)` }}>
        <i />
        <svg width="19" height="25" viewBox="0 0 22 28">
        <path d="M2 2v21l5-5 4 8 4-2-4-8h8Z" fill="var(--sa-12)" stroke="var(--sa-1)" strokeWidth="1.7"/>
        </svg>
        </span>;
    }
}
