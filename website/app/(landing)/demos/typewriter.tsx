'use client';

import { useCallback, useEffect, useRef, useState } from 'react';

/**
 * One beat of a demo script. `text` is typed a character at a time; `hold` is a
 * pause in milliseconds after it lands, before the next beat starts.
 *
 * A beat with `instant: true` appears whole rather than character by character.
 * Use it for machine output: a command is typed by a person, but the Host's
 * reply arrives all at once, and typing it out would be a lie about what
 * happened.
 */
export type Beat = {
  text: string;
  hold?: number;
  instant?: boolean;
  /** Free-form tag the caller switches on when rendering the beat. */
  kind?: string;
};

export type TypedBeat = { text: string; done: boolean; kind?: string };

const CHAR_MS = 22;
const OUTPUT_MS = 90;

/**
 * Reveals a script the way the reference site's demos do: the window starts
 * nearly empty, and the content types itself in once the demo scrolls into view.
 *
 * The animation is finite and runs once. It is not a loop, and it is not
 * decoration: it is what makes a demo read as a session rather than as a
 * screenshot of one.
 *
 * Under `prefers-reduced-motion` the whole script is already present on the
 * first paint, so a reader who does not want motion loses nothing but the
 * reveal.
 */
export function useTypewriter(beats: Beat[], reduced: boolean) {
  const total = beats.length;
  // `beat` is how many beats have completed; `chars` is progress into the next.
  const [beat, setBeat] = useState(reduced ? total : 0);
  const [chars, setChars] = useState(0);
  const [started, setStarted] = useState(reduced);
  const hostRef = useRef<HTMLDivElement>(null);
  const timer = useRef<number | undefined>(undefined);

  // `useReducedMotion` returns false on the first render so the server and
  // client agree, and only reports the real preference after mount. The state
  // initializer above therefore cannot see it: without this, a reduced-motion
  // reader gets a window that never starts (the drive effect bails) and never
  // finishes. Each caller had been working around it with a remount key; the
  // guarantee belongs here, once.
  useEffect(() => {
    if (reduced && beat < total) {
      window.clearTimeout(timer.current);
      setBeat(total);
      setChars(0);
      setStarted(true);
    }
  }, [reduced, beat, total]);

  // Start when the demo first becomes visible. A demo that types itself out
  // above the fold while the reader is elsewhere on the page has already run by
  // the time they arrive.
  useEffect(() => {
    if (started || reduced) return;
    const el = hostRef.current;
    if (!el) return;
    if (typeof IntersectionObserver === 'undefined') {
      setStarted(true);
      return;
    }
    const observer = new IntersectionObserver(
      (entries) => {
        if (entries.some((entry) => entry.isIntersecting)) {
          setStarted(true);
          observer.disconnect();
        }
      },
      { rootMargin: '-10% 0px -10% 0px' },
    );
    observer.observe(el);
    return () => observer.disconnect();
  }, [started, reduced]);

  // Drive the script. One timeout at a time, cleared on every change, so there
  // is never more than one pending tick and unmounting stops it.
  useEffect(() => {
    if (!started || reduced || beat >= total) return;
    const current = beats[beat];
    const length = current.text.length;

    if (current.instant || chars >= length) {
      const ready = current.instant || chars >= length;
      const delay = ready ? (current.hold ?? (current.instant ? OUTPUT_MS : 240)) : 0;
      timer.current = window.setTimeout(() => {
        setBeat((n) => n + 1);
        setChars(0);
      }, delay);
    } else {
      timer.current = window.setTimeout(() => setChars((n) => n + 1), CHAR_MS);
    }
    return () => window.clearTimeout(timer.current);
  }, [started, reduced, beat, chars, total, beats]);

  const replay = useCallback(() => {
    window.clearTimeout(timer.current);
    setBeat(0);
    setChars(0);
    setStarted(true);
  }, []);

  const finish = useCallback(() => {
    window.clearTimeout(timer.current);
    setBeat(total);
    setChars(0);
  }, [total]);

  const typed: TypedBeat[] = beats.slice(0, beat).map((b) => ({
    text: b.text,
    done: true,
    kind: b.kind,
  }));
  if (beat < total && started) {
    const current = beats[beat];
    typed.push({
      text: current.instant ? current.text : current.text.slice(0, chars),
      done: false,
      kind: current.kind,
    });
  }

  return {
    /** Attach to the demo's root so the observer can find it. */
    hostRef,
    /** Beats revealed so far. The last one may be partial. */
    typed,
    /** True while the script is still running. */
    running: started && beat < total,
    /** True once every beat has landed. */
    done: beat >= total,
    replay,
    finish,
  };
}

/* ------------------------------------------------------------- retyping --- */

const DELETE_MS = 24;
const RETYPE_MS = 34;

/**
 * Animates a text value being replaced the way a person replaces it: the
 * divergent tail is deleted one character at a time, then the new tail is
 * typed. The common prefix is left alone, which is what an editor actually
 * does, and it is what makes a formula repair read as an edit rather than as a
 * swap.
 *
 * Deleting is faster than typing, because holding backspace is faster than
 * choosing characters.
 */
export function useRetype(value: string, animate: boolean, typeIn = false) {
  // `typeIn` is for text that appears rather than changes: a line the Turn has
  // just written should be written, not pasted. Safe against the server render
  // because content that types in only ever mounts after hydration.
  const [shown, setShown] = useState(typeIn && animate ? '' : value);
  const timer = useRef<number | undefined>(undefined);

  // A text edit playing out over time is synchronisation with the clock, which
  // is what an effect is for. One pending timeout at a time, cleared on every
  // change, so a value that changes mid-edit redirects rather than racing.
  useEffect(() => {
    if (!animate) {
      window.clearTimeout(timer.current);
      setShown(value);
      return;
    }
    if (shown === value) return;

    // How much of the head the two versions agree on. Everything after it has
    // to go before the new tail can be typed.
    let shared = 0;
    while (shared < shown.length && shared < value.length && shown[shared] === value[shared]) {
      shared += 1;
    }

    const deleting = shown.length > shared;
    timer.current = window.setTimeout(
      () => setShown((text) => (deleting ? text.slice(0, -1) : value.slice(0, text.length + 1))),
      deleting ? DELETE_MS : RETYPE_MS,
    );
    return () => window.clearTimeout(timer.current);
  }, [value, shown, animate]);

  return { shown, /** True while the edit is still playing out. */ editing: shown !== value };
}

/**
 * The text of a field that the Host is editing, plus a caret while the edit is
 * in flight. Drop it in place of the value and the field types itself.
 */
export function Retype({
  value,
  animate,
  typeIn,
}: {
  value: string;
  animate: boolean;
  /** Write the text out on first appearance instead of replacing existing text. */
  typeIn?: boolean;
}) {
  const { shown, editing } = useRetype(value, animate, typeIn);
  return (
    <>
      {shown}
      {editing ? <i className="sa-caret" data-blink="true" aria-hidden="true" /> : null}
    </>
  );
}
