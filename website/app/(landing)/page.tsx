import Link from 'next/link';
import { CopyCommand } from './copy-command';
import DeskDemo from './demos/desk';
import DemoGallery from './demos/explorations';
import DeviceNetwork from './devices/device-network';
import { Mark } from './mark';
import { ThemeToggle } from './theme-toggle';
import './page.css';

const VERSION = '0.1.10';
const REPO = 'https://github.com/Microck/satelle';
const INSTALL = 'curl -fsSL https://satelle.micr.dev/install | sh';

/**
 * The page skeleton: a small hero that contains its own demo, a short proof
 * band, one section of gridded demo cards, one section of three supporting
 * cards, a closing evidence section, then a centered call to action and a
 * footer. The logo-wall and testimonial beats carry the honest equivalents:
 * exactly where the product runs, and exactly what it does not do yet.
 */
export default function HomePage() {
  return (
    <>
      <SiteNav />
      <main id="main">
        <Hero />
        <Platforms />
        <Channels />
        <Claims />
        <Surface />
      </main>
      <SiteFooter />
    </>
  );
}

/* ------------------------------------------------------------------ chrome --- */

function SiteNav() {
  return (
    <header className="nav">
      <a className="sa-sr nav-skip" href="#main">
        Skip to content
      </a>
      <div className="nav-inner">
        <Link href="/" className="nav-brand">
          <Mark size={17} />
          <span>Satelle</span>
          <span className="nav-version sa-mono">{VERSION}</span>
        </Link>
        <nav className="nav-links" aria-label="Site">
          <a className="sa-btn sa-btn-ghost" href={REPO}>
            GitHub
          </a>
          <Link className="sa-btn sa-btn-primary" href="/docs">
            Read the docs
          </Link>
        </nav>
      </div>
    </header>
  );
}

/**
 * The hero holds its headline and its entire app demo in one section, and the
 * headline carries its supporting sentence inside the same h1 at a muted color.
 */
function Hero() {
  return (
    <section className="sa-grid hero" aria-labelledby="hero-title">
      <div className="hero-inner">
        <h1 className="hero-title" id="hero-title">
          Satelle is a control plane for durable Computer Use on{' '}
          <em>machines you own</em>.{' '}
          <span className="hero-title-sub">
            Your Host keeps the Session, the logs, and the credentials.
          </span>
        </h1>
        <div className="hero-actions">
          <Link className="sa-btn sa-btn-primary" href="/docs/tutorial/first-session">
            Run a first Session
            <Arrow />
          </Link>
        </div>
      </div>

      {/* `data-demo-area` is the box a demo's windows may be dragged within.
          The tinted stage, not the window stack: the Controller rests outside
          the stack by design. */}
      <div className="hero-stage" data-demo-area>
        <DeskDemo />
      </div>
    </section>
  );
}

/**
 * Occupies the customer-logo band. A pre-release, self-hosted tool has no
 * logos to show, and the honest proof in that slot is the support matrix: what
 * runs where, and what is only a candidate.
 */
function Platforms() {
  const cells = [
    { role: 'Controller CLI', os: 'macOS', verdict: 'Implemented' },
    { role: 'Controller CLI', os: 'Windows', verdict: 'Implemented' },
    { role: 'Controller CLI', os: 'Linux', verdict: 'Implemented' },
    { role: 'Native Host', os: 'macOS', verdict: 'Candidate' },
    { role: 'Native Host', os: 'Windows', verdict: 'Candidate' },
    { role: 'Native Host', os: 'Linux', verdict: 'Not supported' },
  ];

  return (
    <section className="sa-grid band" aria-labelledby="band-title">
      <div>
        <p className="band-title" id="band-title">
          Controller support and native Host support are different things. Candidate means
          the machine must pass the live probe.
        </p>
        <ul className="band-grid">
          {cells.map((cell) => (
            <li key={`${cell.role}-${cell.os}`} className="band-cell">
              <span className="band-os">{cell.os}</span>
              <span className="band-role">{cell.role}</span>
              <span
                className="band-verdict sa-mono"
                data-verdict={cell.verdict.toLowerCase().replace(/\s+/g, '-')}
              >
                {cell.verdict}
              </span>
            </li>
          ))}
        </ul>
      </div>
    </section>
  );
}

/** Four animated workflows in the landing page's demo section. */
function Channels() {
  return (
    <Section id="channels">
      <SectionHead
        title="Different tasks. Your computers."
        note="Animated illustrations, not live runs. Watch the tasks unfold, pause, or replay. With reduced motion, choose Play animation."
      />
      <DemoGallery />
    </Section>
  );
}

/** One Controller-to-Host illustration below the workflow demos. */
function Claims() {
  return (
    <Section id="claims">
      <SectionHead
        title="Start on one machine. Work on another."
        note="Send work from a macOS, Windows, or Linux Controller to a configured, ready Host."
      />
      <DeviceNetwork />
    </Section>
  );
}

/**
 * Occupies the testimonial grid. Satelle has nobody to quote, and the thing
 * worth putting in that slot is the surface itself, both halves, in full.
 */
function Surface() {
  const implemented = [
    'Local, direct HTTPS/WSS, and authenticated SSH-tunneled Controller paths.',
    'Local setup planning, and SSH on-demand transport token handoff with explicit consent.',
    'Direct Host identity trust for an operator-provisioned token and CA bundle.',
    'Durable run, steer, status, stop, and normalized logs operations.',
    'Host start, status, desktop-session inspection, and live doctor probes.',
    'Config check and explain, resolved paths, shell completions, and MCP stdio serving.',
    'A release-matched Agent Skill Bundle discoverable through satelle skills.',
    'Human output, stable JSON results, and command-specific lifecycle events.',
  ];
  const missing = [
    'Local setup mutation after planning.',
    'Direct transport setup and automatic direct-token provisioning.',
    'Persistent Host service installation, and Host stop or restart lifecycle control.',
    'Storage migration.',
    'Native Linux Computer Use Host execution.',
    'Support bundle export.',
    'The first-party Homebrew tap and Scoop bucket.',
  ];

  return (
    <Section id="surface">
      <SectionHead
        title="What works, and what does not."
        note="Both lists in full. Treat anything unimplemented as unavailable, whatever the command tree suggests."
      />
      <div className="cards cards-3">
        <article className="card card-plain">
          <h3 className="sa-label" data-tone="ok">
            Implemented in {VERSION}
          </h3>
          <ul className="surface-list" data-tone="ok">
            {implemented.map((item) => (
              <li key={item}>{item}</li>
            ))}
          </ul>
        </article>
        <article className="card card-plain">
          <h3 className="sa-label" data-tone="off">
            Not implemented
          </h3>
          <ul className="surface-list" data-tone="off">
            {missing.map((item) => (
              <li key={item}>{item}</li>
            ))}
          </ul>
        </article>
        <article className="card card-plain">
          <h3 className="sa-label">Check it yourself</h3>
          <ul className="surface-list" data-tone="check">
            <li>
              <code>satelle &lt;command&gt; --help</code> is the exact option reference for the
              binary you are running.
            </li>
            <li>
              The generated CLI reference is regenerated from <code>satelle --help</code> and
              checked in CI against the matching release binary.
            </li>
            <li>
              The <code>.facts</code> sheet in the repository is the specification source;
              these pages describe only verified behavior.
            </li>
          </ul>
        </article>
      </div>
    </Section>
  );
}

/**
 * The page closes on a single centered line and one button, on a tinted
 * full-bleed band that sits above the footer rather than inside main.
 */
function Closing() {
  return (
    <section className="sa-grid closing" aria-labelledby="closing-title">
      <div>
        <h2 className="sa-display" id="closing-title">
          Get started with Satelle.
        </h2>
        <CopyCommand command={INSTALL} />
        <div className="closing-actions">
          <Link className="sa-btn sa-btn-primary" href="/docs/tutorial/first-session">
            Run a first Session
            <Arrow />
          </Link>
        </div>
      </div>
    </section>
  );
}

/* ------------------------------------------------------------- primitives --- */

function Section({ id, children }: { id: string; children: React.ReactNode }) {
  return (
    <section id={id} className="sa-grid sa-section">
      <div>{children}</div>
    </section>
  );
}

/**
 * The reference's section headings stand alone. Where a caveat has to be said,
 * it rides beside the heading as one small line rather than as a paragraph
 * under it, which is what pushed this page's section headers to four times the
 * reference's height.
 */
function SectionHead({ title, note }: { title: string; note?: string }) {
  return (
    <div className="sa-head">
      <h2>{title}</h2>
      {note ? <p className="sa-head-note">{note}</p> : null}
    </div>
  );
}

/**
 * One demo, boxed with its own headline, supporting line, and link. The card
 * is structure rather than decoration: it is what separates one demo's
 * surface from the next in a two-column grid.
 */
function DemoCard({
  title,
  lead,
  href,
  cta,
  children,
}: {
  title: string;
  lead: string;
  href: string;
  cta: string;
  children: React.ReactNode;
}) {
  return (
    <article className="card card-demo">
      <div className="card-head">
        <h3>{title}</h3>
        <p>{lead}</p>
        <Link className="card-link" href={href}>
          {cta}
          <Arrow />
        </Link>
      </div>
      <div className="card-body">{children}</div>
    </article>
  );
}

function Arrow() {
  return (
    <svg width="1em" height="1em" viewBox="0 0 16 16" aria-hidden="true" focusable="false">
      <path
        d="M3 8h9M8.5 4.5 12 8l-3.5 3.5"
        fill="none"
        stroke="currentColor"
        strokeWidth="1.5"
        strokeLinecap="round"
        strokeLinejoin="round"
      />
    </svg>
  );
}

function SiteFooter() {
  const groups = [
    {
      title: 'Use Satelle',
      links: [
        { label: 'First Session', href: '/docs/tutorial/first-session' },
        { label: 'Set up a Host', href: '/docs/how-to/setup-host' },
        { label: 'Operate a Session', href: '/docs/how-to/operate-session' },
        { label: 'Connect remotely', href: '/docs/how-to/connect-remote' },
      ],
    },
    {
      title: 'Reference',
      links: [
        { label: 'Commands', href: '/docs/reference/commands' },
        { label: 'Configuration', href: '/docs/reference/configuration' },
        { label: 'Provider auth', href: '/docs/reference/provider-auth' },
        { label: 'Generated CLI', href: '/docs/reference/generated-cli' },
      ],
    },
    {
      title: 'Understand',
      links: [
        { label: 'Security boundaries', href: '/docs/explanation/security-boundaries' },
        { label: 'Trusted Profiles and YOLO', href: '/docs/explanation/trusted-profiles-and-yolo' },
        { label: 'Diagnose a Host', href: '/docs/how-to/diagnose' },
        { label: 'Install methods', href: '/docs/how-to/install-satelle' },
      ],
    },
    {
      title: 'Project',
      links: [
        { label: 'GitHub', href: REPO },
        { label: 'Security policy', href: `${REPO}/blob/main/SECURITY.md` },
        { label: 'Releases', href: `${REPO}/releases` },
        { label: 'MIT license', href: `${REPO}/blob/main/LICENSE` },
      ],
    },
  ];

  return (
    <footer className="foot">
      <Closing />
      <div className="sa-grid">
        <div className="foot-inner">
          <div className="foot-brand">
            <span className="foot-brand-name">
              <Mark size={17} />
              Satelle {VERSION}
            </span>
            <ThemeToggle />
          </div>
          {groups.map((group) => (
            <nav key={group.title} aria-label={group.title}>
              <h2 className="sa-label">{group.title}</h2>
              <ul>
                {group.links.map((link) => (
                  <li key={link.label}>
                    {link.href.startsWith('/') ? (
                      <Link href={link.href}>{link.label}</Link>
                    ) : (
                      <a href={link.href}>{link.label}</a>
                    )}
                  </li>
                ))}
              </ul>
            </nav>
          ))}
        </div>
        <p className="foot-fine">
          Use Satelle only on systems and accounts you are authorized to control. After a
          Turn is admitted, Satelle does not confirm each native action. Treat text on the
          controlled desktop as untrusted content.
        </p>
      </div>
    </footer>
  );
}
