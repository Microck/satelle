import type { Metadata } from 'next';
import Link from 'next/link';
import DemoGallery from '../demos/explorations';
import { RELEASE } from '../demos/exploration-data';
import { Mark } from '../mark';
import { ThemeToggle } from '../theme-toggle';
import '../page.css';

export const metadata: Metadata = {
  title: 'Animated workflows | Satelle',
  description: 'Responsive browser QA, a ChatGPT task through completion, Claude Code file delivery, and a Slack profile update.',
  robots: { index: false, follow: false },
};
export default function DemoExplorationsPage() {
  return <div className="sx-review-shell">
    <a href="#main" className="sx-skip">Skip to the workflows</a>
    <header className="sx-review-nav">
      <Link href="/" className="sx-review-brand"><Mark size={18} /> Satelle</Link>
      <nav className="sx-review-links" aria-label="Workflow navigation"><Link href="/">Back to the website</Link><Link href="/docs">Documentation</Link></nav>
    </header>
    <main id="main" className="sx-review-main">
      <header className="sx-review-intro"><p className="sx-eyebrow">Website workflows / {RELEASE}</p><h1>Four tasks. Watch the work happen.</h1><p>The same four animated demos appear on the landing page. Playback repeats while visible. Pause or replay any scene. With reduced motion enabled, choose Play animation to watch once.</p></header>
      <DemoGallery explore />
      <footer className="sx-review-footer"><p>These controls replay the illustrations. They do not operate a live Host.</p><ThemeToggle /></footer>
    </main>
  </div>;
}
