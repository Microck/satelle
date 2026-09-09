import type { Metadata } from 'next';
import Link from 'next/link';
import DemoGallery from '../demos/explorations';
import { RELEASE } from '../demos/exploration-data';
import { Mark } from '../mark';
import { ThemeToggle } from '../theme-toggle';
import '../page.css';

export const metadata: Metadata = {
  title: 'Four animated workflows | Satelle',
  description: 'Website QA, desktop chat, a Claude Code dashboard handoff, and macOS wallpaper. Animated illustrations on operator-controlled Hosts.',
  robots: { index: false, follow: false },
};

export default function DemoExplorationsPage() {
  return (
    <div className="sx-review-page sx-review-shell">
      <a href="#main" className="sx-skip">Skip to workflow demos</a>
      <header className="sx-review-nav">
        <Link href="/" className="sx-review-brand"><Mark size={18} /> Satelle</Link>
        <nav className="sx-review-links" aria-label="Workflow demo navigation">
          <Link href="/">Back to the website</Link>
          <Link href="/docs">Documentation</Link>
        </nav>
      </header>
      <main id="main" className="sx-review-main">
        <header className="sx-review-intro">
          <p className="sx-eyebrow">Four workflows / {RELEASE}</p>
          <h1>Different tasks. Your computers.</h1>
          <p>Website QA, desktop chat, a dashboard handoff, and a new macOS wallpaper. Each scene plays once as it enters view. Pause, replay, or explore the steps.</p>
        </header>
        <DemoGallery explore />
        <footer className="sx-review-footer">
          <p>The same four workflows appear on the homepage. All scenes are illustrative.</p>
          <ThemeToggle />
        </footer>
      </main>
    </div>
  );
}
