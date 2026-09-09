import type { Metadata } from 'next';
import Link from 'next/link';
import DemoGallery from '../demos/explorations';
import { RELEASE } from '../demos/exploration-data';
import { Mark } from '../mark';
import { ThemeToggle } from '../theme-toggle';
import '../page.css';

export const metadata: Metadata = {
  title: 'Animated workflows | Satelle',
  description: 'GitHub QA, a ChatGPT desktop concept, Claude Code file delivery, and a Slack profile update.',
  robots: { index: false, follow: false },
};

export default function DemoExplorationsPage() {
  return (
    <div className="sx-review-shell">
      <a href="#main" className="sx-skip">Skip to the workflows</a>
      <header className="sx-review-nav">
        <Link href="/" className="sx-review-brand"><Mark size={18} /> Satelle</Link>
        <nav className="sx-review-links" aria-label="Workflow navigation">
          <Link href="/">Back to the website</Link>
          <Link href="/docs">Documentation</Link>
        </nav>
      </header>
      <main id="main" className="sx-review-main">
        <header className="sx-review-intro">
          <p className="sx-eyebrow">Website workflows / {RELEASE}</p>
          <h1>Real apps. One visual language.</h1>
          <p>Four scripted workflows in Satelle’s visual style. Each plays once on view.
            Pause or replay a scene. With reduced motion, use Next frame to view stills.</p>
        </header>
        <DemoGallery explore />
        <footer className="sx-review-footer">
          <p>These controls replay the illustrations. They do not operate a live Host.</p>
          <ThemeToggle />
        </footer>
      </main>
    </div>
  );
}
