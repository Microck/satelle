'use client';

import { useCallback, useEffect, useId, useRef, useState } from 'react';

export type Offset = { x: number; y: number };

const KEY_STEP = 8;
const KEY_STEP_COARSE = 40;

/**
 * Drag and keyboard translation for a demo window.
 *
 * Position is a plain offset from the element's laid-out place, so the surrounding
 * layout keeps working at every width and a reset is just `{x: 0, y: 0}`. The
 * offset is applied with `translate3d` and no transition: a transition on a
 * dragged element makes it feel like it is trailing the hand.
 *
 * Returns props for the title bar (the grip) and the style for the window.
 */
/**
 * The box a window may be dragged within: the nearest marked demo area, or the
 * passed element if the demo is not inside one.
 *
 * The area is not the window stack. The Controller window deliberately rests
 * outside the stack, breaking past the Host window's left edge, so bounding a
 * drag by the stack would snap it inward the moment it was touched. The page
 * marks the surface the windows belong on and the drag honours that.
 */
function areaFor(el: HTMLElement, fallback: HTMLElement | null): HTMLElement | null {
  return el.closest<HTMLElement>('[data-demo-area]') ?? fallback;
}

/**
 * Holds the whole window inside the demo area. A window pushed past the edge
 * is clipped by the section's `overflow-x` and no pointer can get it back, and
 * a window hanging half outside the tinted stage just looks broken.
 */
function clampToBounds(
  next: Offset,
  el: HTMLElement | null,
  bounds: HTMLElement | null,
): Offset {
  if (!el) return next;
  const area = areaFor(el, bounds)?.getBoundingClientRect();
  if (!area) return next;
  const box = el.getBoundingClientRect();
  // Where the element sits with no offset at all.
  const restLeft = box.left - (el.dataset.offsetX ? Number(el.dataset.offsetX) : 0);
  const restTop = box.top - (el.dataset.offsetY ? Number(el.dataset.offsetY) : 0);
  // Every edge inside every edge, so the window is fully contained.
  const minX = area.left - restLeft;
  const minY = area.top - restTop;
  // A window wider or taller than the area cannot satisfy both edges. Pin it to
  // the near edge rather than letting the range invert and clamp to nonsense.
  const maxX = Math.max(minX, area.right - box.width - restLeft);
  const maxY = Math.max(minY, area.bottom - box.height - restTop);
  return {
    x: Math.min(Math.max(next.x, minX), maxX),
    y: Math.min(Math.max(next.y, minY), maxY),
  };
}

export function useMovable(enabled: boolean, boundsRef?: React.RefObject<HTMLElement | null>) {
  const [offset, setOffset] = useState<Offset>({ x: 0, y: 0 });
  const [dragging, setDragging] = useState(false);
  const windowRef = useRef<HTMLElement | null>(null);
  // Pointer origin and the offset at press time, so a drag is always relative
  // to where the press started rather than accumulating rounding drift.
  const origin = useRef<{ px: number; py: number; ox: number; oy: number } | null>(null);

  const onPointerDown = useCallback(
    (event: React.PointerEvent<HTMLElement>) => {
      if (!enabled || event.button !== 0) return;
      // Let the reader select text in the title bar with a modifier held.
      if (event.metaKey || event.ctrlKey) return;
      event.currentTarget.setPointerCapture(event.pointerId);
      origin.current = { px: event.clientX, py: event.clientY, ox: offset.x, oy: offset.y };
      setDragging(true);
    },
    [enabled, offset.x, offset.y],
  );

  const onPointerMove = useCallback(
    (event: React.PointerEvent<HTMLElement>) => {
      const start = origin.current;
      if (!start) return;
      setOffset(
        clampToBounds(
          { x: start.ox + (event.clientX - start.px), y: start.oy + (event.clientY - start.py) },
          windowRef.current,
          boundsRef?.current ?? null,
        ),
      );
    },
    [boundsRef],
  );

  const endDrag = useCallback((event: React.PointerEvent<HTMLElement>) => {
    if (!origin.current) return;
    origin.current = null;
    setDragging(false);
    if (event.currentTarget.hasPointerCapture(event.pointerId)) {
      event.currentTarget.releasePointerCapture(event.pointerId);
    }
  }, []);

  const onKeyDown = useCallback(
    (event: React.KeyboardEvent<HTMLElement>) => {
      if (!enabled) return;
      const step = event.shiftKey ? KEY_STEP_COARSE : KEY_STEP;
      const moves: Record<string, Offset> = {
        ArrowLeft: { x: -step, y: 0 },
        ArrowRight: { x: step, y: 0 },
        ArrowUp: { x: 0, y: -step },
        ArrowDown: { x: 0, y: step },
      };
      if (event.key === 'Home') {
        event.preventDefault();
        setOffset({ x: 0, y: 0 });
        return;
      }
      const move = moves[event.key];
      if (!move) return;
      event.preventDefault();
      setOffset((current) =>
        clampToBounds(
          { x: current.x + move.x, y: current.y + move.y },
          windowRef.current,
          boundsRef?.current ?? null,
        ),
      );
    },
    [enabled, boundsRef],
  );

  // A window dragged off-screen is unrecoverable with a pointer, so snap back
  // when the demo stops being movable (narrow layout) or on unmount.
  useEffect(() => {
    if (!enabled) setOffset({ x: 0, y: 0 });
  }, [enabled]);

  const moved = offset.x !== 0 || offset.y !== 0;

  return {
    offset,
    dragging,
    moved,
    reset: () => setOffset({ x: 0, y: 0 }),
    /**
     * Spread onto the element that should act as the title bar.
     *
     * Deliberately not `role="button"`: activation does nothing here, and a
     * button that ignores Enter and Space is worse than no role at all. This is
     * a focusable spatial handle, so it announces itself through
     * `aria-roledescription` and the caller supplies an `aria-label` naming the
     * window. Arrow keys, Shift plus arrow, and Home do the work.
     */
    gripProps: {
      onPointerDown,
      onPointerMove,
      onPointerUp: endDrag,
      onPointerCancel: endDrag,
      onKeyDown,
      tabIndex: enabled ? 0 : -1,
      'aria-roledescription': enabled ? 'movable window handle' : undefined,
      style: enabled ? { cursor: dragging ? 'grabbing' : 'grab' } : undefined,
    },
    /** Attach to the window element so the clamp can measure it. */
    windowRef,
    /** Spread onto the window element. */
    windowStyle: {
      transform: moved ? `translate3d(${offset.x}px, ${offset.y}px, 0)` : undefined,
      // A dragged window lifts. The colour comes from the theme rather than a
      // literal black, which reads as soot on the light ground.
      boxShadow: dragging
        ? '0 24px 48px -12px rgb(var(--sa-shadow) / calc(var(--sa-shadow-strength) + 0.08))'
        : undefined,
      zIndex: dragging ? 2 : undefined,
      position: 'relative' as const,
    },
    /** Data attributes the clamp reads to find the element's resting place. */
    windowData: { 'data-offset-x': offset.x, 'data-offset-y': offset.y },
  };
}

/**
 * True when the viewport is at least `minWidth` (a CSS length). Demos use it to
 * turn dragging off on narrow screens, where windows stack vertically instead.
 */
export function useViewportAtLeast(minWidth: string): boolean {
  const [matches, setMatches] = useState(false);

  useEffect(() => {
    const query = window.matchMedia(`(min-width: ${minWidth})`);
    setMatches(query.matches);
    const onChange = (event: MediaQueryListEvent) => setMatches(event.matches);
    query.addEventListener('change', onChange);
    return () => query.removeEventListener('change', onChange);
  }, [minWidth]);

  return matches;
}

/**
 * Stable id pair for wiring a demo's caption to its region with
 * `aria-describedby`, so a screen reader hears what is interactive before it
 * reaches the controls.
 */
export function useCaptionIds() {
  const base = useId();
  return { captionId: `${base}-caption`, regionId: `${base}-region` };
}
