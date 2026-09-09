/**
 * Homepage demo fixtures, not a Satelle client. No command is executed here.
 * Fidelity: website/DESIGN.md §7; CLI main.rs (print_detached_session,
 * print_session_human, doctor); mcp/schema.rs; README.md platform support.
 * Identifiers and timestamps are illustrative. MCP views are projections, not
 * fabricated CLI output. Keep these fixtures tied to the release on this branch.
 */
export const RELEASE = '0.1.10';
export const HOST = 'win-11-lab';
export const SESSION = 'rs_0193f2c1-8a4e-7c33-b0d1-5e9a4c17be02';
export const TURN = 'rt_0193f2c1-8a52-7f10-9c44-2b7e8d31af65';

export const DEMOS = [
  { id: 'durability', number: '01', label: 'Durable Sessions', title: 'Every Session stays on the Host.', lead: 'Leave the terminal. Check back from a fresh Controller.', href: '/docs/how-to/operate-session', cta: 'Operate a Session' },
  { id: 'readiness', number: '02', label: 'Live readiness', title: 'Prove the desktop is ready.', lead: 'A live probe checks readiness. A person grants access.', href: '/docs/how-to/diagnose', cta: 'Diagnose a Host' },
  { id: 'transports', number: '03', label: 'Connection paths', title: 'Local, over TLS, or through SSH.', lead: 'Three Controller paths. The same operator-controlled Host.', href: '/docs/how-to/connect-remote', cta: 'Connect remotely' },
  { id: 'agent', number: '04', label: 'MCP integration', title: 'Your coding agent gets typed tools.', lead: 'Inspect Sessions over stdio. Advertise mutation tools explicitly.', href: '/docs/reference/commands', cta: 'Configure MCP' },
  { id: 'boundaries', number: '05', label: 'Operator control', title: 'The Host keeps the boundaries.', lead: 'Execution, Session state, and provider-secret resolution live there.', href: '/docs/explanation/security-boundaries', cta: 'Understand the boundaries' },
  { id: 'platforms', number: '06', label: 'Platform support', title: 'Know what works. And what does not.', lead: 'Controller support is not native Computer Use Host support.', href: '/docs/how-to/install-satelle', cta: 'Check platform support' },
] as const;
export type DemoId = (typeof DEMOS)[number]['id'];
export const DEFAULT_SELECTION: readonly DemoId[] = ['durability', 'readiness', 'transports', 'agent'];

export function isDemoId(value: string): value is DemoId {
  return DEMOS.some((demo) => demo.id === value);
}

/** Empty is an intentional empty selection. Invalid input falls back safely. */
export function parseSelection(value: string | null): DemoId[] {
  if (value === null) return [...DEFAULT_SELECTION];
  if (value === '') return [];
  const selected = [...new Set(value.split(',').filter(isDemoId))].slice(0, 4);
  return selected.length ? selected : [...DEFAULT_SELECTION];
}

export function toggleSelection(current: readonly DemoId[], id: DemoId): DemoId[] {
  if (current.includes(id)) return current.filter((item) => item !== id);
  return current.length < 4 ? [...current, id] : [...current];
}

/** Both branches use the real doctor's labels and finding/evidence format. */
export const PROBE_OUTPUT = {
  blocked: [
    `Host: ${HOST}`, 'Status: blocked', 'Ready: false', 'Scopes: computer-use', '',
    '[error] native Computer Use requires a manual permission or app approval change (manual_action_required)',
    '  evidence: code=computer-use-not-ready',
    '  evidence: reason=native_readiness_manual_action_required',
    '  evidence: status=manual_action_required',
  ],
  ready: [
    `Host: ${HOST}`, 'Status: ready', 'Ready: true', 'Scopes: computer-use', '',
    '[info] native Computer Use readiness passed (informational)',
    '  evidence: source=live',
    '  evidence: observed_at=2026-09-08T18:29:44Z',
    '  evidence: expires_at=2026-09-08T18:34:44Z',
  ],
} as const;

export const PLATFORMS = [
  { id: 'macos', name: 'macOS', controller: 'Implemented', host: 'Candidate', note: 'macOS is a candidate native Host. The target machine must pass the live Computer Use readiness probe.' },
  { id: 'windows', name: 'Windows', controller: 'Implemented', host: 'Candidate', note: 'Windows is a candidate native Host. The target machine must pass the live Computer Use readiness probe.' },
  { id: 'linux', name: 'Linux', controller: 'Implemented', host: 'Not supported', note: 'Linux can run the Controller CLI. Native Linux Computer Use Host execution is not supported in this release.' },
] as const;
export type PlatformId = (typeof PLATFORMS)[number]['id'];

export const BOUNDARIES = {
  session: { label: 'Session', text: 'The Host owns the Session, Turn history, and logs. A Controller disconnect does not delete them. This is not a promise of uninterrupted execution across Host failures.' },
  credentials: { label: 'Credentials', text: 'Provider secrets resolve on the Host. A remote Controller still needs its own Satelle API authentication material. This does not mean data never reaches a model provider.' },
  desktop: { label: 'Desktop', text: 'The Operator chooses the Desktop Binding. Satelle observes native permissions; it never grants operating-system, administrator, or app approvals.' },
} as const;
export type BoundaryId = keyof typeof BOUNDARIES;

/** schema.rs defaults detach to false. Request it explicitly for admission output. */
export const MCP_EXAMPLE = {
  readOnlyToolCount: 8,
  mutationToolCount: 15,
  statusInput: { session_id: SESSION, host: HOST },
  steerInput: { session_id: SESSION, host: HOST, prompt: 'Open settings', detach: true },
  statusFields: { schema_version: 'satelle.status.v2', host: HOST, status: 'stopped' },
  steerFields: { schema_version: 'satelle.steer.v2', status: 'starting' },
} as const;
