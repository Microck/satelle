'use client';

import { useEffect, useState } from 'react';

type Choice = 'system' | 'light' | 'dark';

const CHOICES: { value: Choice; label: string }[] = [
  { value: 'system', label: 'System' },
  { value: 'light', label: 'Light' },
  { value: 'dark', label: 'Dark' },
];

export const THEME_KEY = 'satelle-theme';

/**
 * Runs before first paint, inlined into the document head, so an explicit choice
 * is on the root element before any pixels are drawn. Without it a reader who
 * picked dark on a light-default page gets a flash of the wrong theme.
 *
 * "system" deliberately stamps nothing: that is the state the CSS reads with
 * prefers-color-scheme, and an attribute would override the media query.
 */
export const THEME_BOOTSTRAP = `(function(){try{var t=localStorage.getItem('${THEME_KEY}');if(t==='light'||t==='dark'){document.documentElement.setAttribute('data-theme',t)}}catch(e){}})()`;

export function ThemeToggle() {
  const [choice, setChoice] = useState<Choice>('system');

  // Read the stored choice after mount. The server render cannot know it, and
  // the bootstrap script above has already applied it to the document, so this
  // only brings the control's own highlight into agreement.
  useEffect(() => {
    try {
      const stored = localStorage.getItem(THEME_KEY);
      if (stored === 'light' || stored === 'dark') setChoice(stored);
    } catch {
      // Storage can be unavailable in a private window. System is the default.
    }
  }, []);

  function pick(next: Choice) {
    setChoice(next);
    const root = document.documentElement;
    if (next === 'system') root.removeAttribute('data-theme');
    else root.setAttribute('data-theme', next);
    try {
      if (next === 'system') localStorage.removeItem(THEME_KEY);
      else localStorage.setItem(THEME_KEY, next);
    } catch {
      // The choice still applies for this page view.
    }
  }

  return (
    <div className="themer" role="group" aria-label="Color theme">
      {CHOICES.map((option) => (
        <button
          key={option.value}
          type="button"
          className="themer-btn"
          data-active={choice === option.value}
          aria-pressed={choice === option.value}
          onClick={() => pick(option.value)}
        >
          <Icon kind={option.value} />
          <span className="sa-sr">{option.label}</span>
        </button>
      ))}
    </div>
  );
}

function Icon({ kind }: { kind: Choice }) {
  const common = {
    width: '1em',
    height: '1em',
    viewBox: '0 0 16 16',
    fill: 'none',
    stroke: 'currentColor',
    strokeWidth: 1.4,
    strokeLinecap: 'round' as const,
    strokeLinejoin: 'round' as const,
    'aria-hidden': true,
    focusable: 'false' as const,
  };
  if (kind === 'system') {
    return (
      <svg {...common}>
        <rect x="2" y="3" width="12" height="8" rx="1" />
        <path d="M6 13.5h4" />
      </svg>
    );
  }
  if (kind === 'light') {
    return (
      <svg {...common}>
        <circle cx="8" cy="8" r="3" />
        <path d="M8 1.5v1.2M8 13.3v1.2M14.5 8h-1.2M2.7 8H1.5M12.6 3.4l-.85.85M4.25 11.75l-.85.85M12.6 12.6l-.85-.85M4.25 4.25l-.85-.85" />
      </svg>
    );
  }
  return (
    <svg {...common}>
      <path d="M13.2 9.6A5.6 5.6 0 0 1 6.4 2.8a5.6 5.6 0 1 0 6.8 6.8Z" />
    </svg>
  );
}
