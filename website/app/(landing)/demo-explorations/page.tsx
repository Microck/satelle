import type { Metadata } from 'next';
import Link from 'next/link';
import DemoGallery from '../demos/explorations';
import { RELEASE } from '../demos/exploration-data';
import { Mark } from '../mark';
import { ThemeToggle } from '../theme-toggle';
import '../page.css';

export const metadata: Metadata = {
  title: 'Demo explorations | Satelle',
  description: 'Six different workflows: spreadsheet, chat, editor, browser, document, and CLI. Choose four.',
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
          <h1>Different work. Different windows.</h1>
          <p>A spreadsheet, a conversation, your editor, a browser, a document, and one terminal. Try the examples and choose four for the homepage.</p>
        </header>
        <DemoGallery explore />
        <footer className="sx-review-footer">
          <p>The homepage uses 01–04. This picker changes the preview only, not the published page.</p>
          <ThemeToggle />
        </footer>
      </main>
    </div>
  );
}
