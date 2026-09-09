'use client';
import * as React from 'react';
import * as data from './exploration-data';

type Props = { id: data.DemoId; children: (frame: data.Frame, moving: boolean) => React.ReactNode };
type State = { elapsed: number; running: boolean; reduced: boolean; optedIn: boolean; cycle: number };
type Point = { x: number; y: number };
type CursorProps = { target?: string; progress: number; click: boolean; visible: boolean; layout: number };

/** One shared clock; Pause survives scrolling. Explicit reduced-motion Play
 * opts into one run. The interface has no footer: controls live in a small
 * hover/focus overlay, with a screen-reader-only status description. */
export class WorkflowPlayer extends React.Component<Props, State> {
    private observer?: IntersectionObserver;
    private media?: MediaQueryList;
    state: State = { elapsed: data.duration(data.TIMELINES[this.props.id]), running: false, reduced: false, optedIn: false, cycle: 0 };
    private root: HTMLDivElement | null = null;
    raf = 0;
    clock = this.state.elapsed;
    previous: number | null = null;
    painted = 0;
    inView = false;
    paused = false;
    mounted = false;
    reduced = false;
    optedIn = false;
    cycle = 0;
    preference = () => {
        this.reduced = this.media?.matches ?? false;
        this.optedIn = false;
        this.clock = this.reduced ? data.duration(data.TIMELINES[this.props.id]) : 0;
        this.previous = null;
        this.cycle = 0;
        this.setState({ reduced: this.reduced, optedIn: false, elapsed: this.clock, cycle: 0 }, this.sync);
    };
    allowed = () => this.mounted && !this.paused && this.inView && !document.hidden
        && (!this.reduced || (this.optedIn && this.clock < data.duration(data.TIMELINES[this.props.id])));
    sync = () => {
        if (!this.mounted)
            return;
        const running = this.allowed();
        if (running && !this.raf)
            this.raf = requestAnimationFrame(this.tick);
        if (!running) {
            cancelAnimationFrame(this.raf);
            this.raf = 0;
            this.previous = null;
        }
        if (this.state.running !== running)
            this.setState({ running });
    };
    private tick = (now: number) => {
        this.raf = 0;
        if (!this.allowed()) {
            this.sync();
            return;
        }
        const total = data.duration(data.TIMELINES[this.props.id]);
        this.clock += this.previous === null ? 0 : Math.min(100, now - this.previous);
        this.previous = now;
        if (!this.reduced && this.clock >= total + data.LOOP_HOLD) {
            this.clock = 0;
            this.cycle++;
        }
        if (this.reduced)
            this.clock = Math.min(total, this.clock);
        if (now - this.painted >= 30 || this.clock === total || this.clock === 0) {
            this.painted = now;
            this.setState({ elapsed: this.clock, cycle: this.cycle });
        }
        this.sync();
    };
    replay = () => {
        this.clock = 0;
        this.previous = null;
        this.paused = false;
        this.optedIn = true;
        this.setState({ elapsed: 0, optedIn: true }, this.sync);
    };
    toggle = () => {
        if (this.reduced && (!this.optedIn || this.clock >= data.duration(data.TIMELINES[this.props.id]))) {
            this.replay();
            return;
        }
        this.paused = !this.paused;
        this.sync();
    };
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
        }
        else {
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
    render() {
        const { id } = this.props;
        const { running, reduced, optedIn } = this.state;
        const frame = data.sample(data.TIMELINES[id], this.state.elapsed);
        return <div className="sw-player" ref={(node) => { this.root = node; }} data-playing={running} data-step={frame.step} data-elapsed={Math.round(frame.elapsed)} data-cycle={this.state.cycle} data-complete={frame.done} data-reduced={reduced} data-motion-opt-in={optedIn}>
        <div className="sw-scene" aria-hidden="true">{this.props.children(frame, running)}</div>
        <span className="sw-a11y-status" role="status" aria-live={running ? 'off' : 'polite'} aria-atomic="true">{reduced && !optedIn ? 'Animation paused for reduced motion. Use Play to watch it.' : frame.label}</span>
        <div className="sw-controls" role="group" aria-label={`${id} animation controls`}>
        <button type="button" onClick={this.toggle} aria-label={`${running ? 'Pause' : 'Play'} ${id} animation`} title={running ? 'Pause animation' : 'Play animation'}>
        <svg width="16" height="16" viewBox="0 0 20 20" aria-hidden="true" focusable="false" fill="currentColor">{running ? <path d="M5 4h3v12H5zm7 0h3v12h-3z"/> : <path d="m6 3 11 7-11 7z"/>}</svg>
        </button>
        <button type="button" onClick={this.replay} aria-label={`Replay ${id} demo`} title="Replay animation">
        <svg width="16" height="16" viewBox="0 0 20 20" aria-hidden="true" focusable="false" fill="none" stroke="currentColor" strokeWidth="1.6" strokeLinecap="round" strokeLinejoin="round">
        <path d="M4 7a7 7 0 1 1-1 6M4 2v5h5"/>
        </svg>
        </button>
        </div>
        </div>;
    }
}
export class DemoCursor extends React.Component<CursorProps, { from: Point; to: Point }> {
    private observer?: ResizeObserver;
    state = { from: { x: 24, y: 80 }, to: { x: 24, y: 80 } };
    private node: HTMLSpanElement | null = null;
    measure = () => {
        const root = this.node?.parentElement;
        if (!root || !this.props.target)
            return;
        const target = Array.from(root.querySelectorAll<HTMLElement>(`[data-cursor="${this.props.target}"]`))
            .find((node) => { const r = node.getBoundingClientRect(); return r.width > 0 && r.height > 0; });
        if (!target)
            return;
        const a = root.getBoundingClientRect(), b = target.getBoundingClientRect();
        const to = { x: Math.max(0, Math.min(a.width - 22, b.left - a.left + b.width / 2)), y: Math.max(0, Math.min(a.height - 28, b.top - a.top + b.height / 2)) };
        if (Math.abs(to.x - this.state.to.x) + Math.abs(to.y - this.state.to.y) > 0.5)
            this.setState((state) => ({ from: state.to, to }));
    };
    componentDidMount() {
        this.measure();
        if (this.node?.parentElement && typeof ResizeObserver !== 'undefined') {
            this.observer = new ResizeObserver(this.measure);
            this.observer.observe(this.node.parentElement);
        }
    }
    componentDidUpdate(previous: CursorProps) {
        if (previous.target !== this.props.target || previous.layout !== this.props.layout)
            this.measure();
    }
    componentWillUnmount() { this.observer?.disconnect(); }
    render() {
        const { from, to } = this.state;
        const p = this.props.progress, q = p * p * (3 - 2 * p);
        return <span className="sw-cursor" ref={(node) => { this.node = node; }} aria-hidden="true" style={{ visibility: this.props.visible && this.props.target ? 'visible' : 'hidden', transform: `translate(${from.x + (to.x - from.x) * q}px, ${from.y + (to.y - from.y) * q}px)` }}>
        <i style={{ opacity: this.props.click ? 0.65 : 0, transform: `scale(${this.props.click ? 1 : 0.45})` }}/>
        <svg width="22" height="28" viewBox="0 0 22 28">
        <path d="M2 2v21l5-5 4 8 4-2-4-8h8Z" fill="var(--sa-12)" stroke="var(--sa-0)" strokeWidth="1.7"/>
        </svg>
        </span>;
    }
}
