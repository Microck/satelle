import type { Metadata } from 'next';
import Link from 'next/link';
import DemoGallery from '../demos/explorations';
import { RELEASE } from '../demos/exploration-data';
import { Mark } from '../mark';
import { ThemeToggle } from '../theme-toggle';
import '../page.css';

export const metadata: Metadata = {
  title: 'Demo explorations | Satelle',
  description: 'Six interactive, release-grounded website demo concepts. Choose four to compare.',
  robots: { index: false, follow: false },
};

export default function DemoExplorationsPage() {
  return (
    <div className="sx-review-page sx-review-shell">
      <a href="#main" className="sx-skip">Skip to demo explorations</a>
      <header className="sx-review-nav">
        <Link href="/" className="sx-review-brand"><Mark size={18} /> Satelle</Link>
        <nav className="sx-review-links" aria-label="Demo exploration navigation">
          <Link href="/">Back to the website</Link>
          <Link href="/docs">Documentation</Link>
        </nav>
      </header>
      <main id="main" className="sx-review-main">
        <header className="sx-review-intro">
          <p className="sx-eyebrow">Website explorations / {RELEASE}</p>
          <h1>Six demos. Pick your four.</h1>
          <p>Try the controls, compare the concepts, and preview your preferred set. These are illustrative website demos, not a connection to a live Host.</p>
        </header>
        <DemoGallery explore />
        <footer className="sx-review-footer">
          <p>The homepage uses 01–04. Your selection changes this preview only.</p>
          <ThemeToggle />
        </footer>
      </main>
    </div>
  );
}
