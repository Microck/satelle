'use client';

import { useEffect, useState } from 'react';

/**
 * Tracks `prefers-reduced-motion`. Demos use it to skip animated transitions
 * and to stop the terminal caret, never to remove functionality: a reduced
 * motion reader steps through exactly the same states, just instantly.
 *
 * This is a genuine subscription to a browser API outside React's render flow,
 * which is what effects are for. It starts as `false` so the server render and
 * the first client render agree.
 */
export function useReducedMotion(): boolean {
  const [reduced, setReduced] = useState(false);

  useEffect(() => {
    const query = window.matchMedia('(prefers-reduced-motion: reduce)');
    setReduced(query.matches);
    const onChange = (event: MediaQueryListEvent) => setReduced(event.matches);
    query.addEventListener('change', onChange);
    return () => query.removeEventListener('change', onChange);
  }, []);

  return reduced;
}

/**
 * True once the component has mounted on the client. Demos use it to render a
 * settled static first frame on the server, then enable interaction. Keeps the
 * no-JavaScript rendering legible instead of empty.
 */
export function useMounted(): boolean {
  const [mounted, setMounted] = useState(false);
  useEffect(() => setMounted(true), []);
  return mounted;
}
