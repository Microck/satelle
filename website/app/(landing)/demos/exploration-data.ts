/** Scripted website illustrations, never a Satelle client or a measured run.
 * Sources and assumptions are recorded in website/DEMO-EXPLORATIONS.md. */
export const RELEASE = '0.1.10';
export const SESSION = 'rs_0193f2c1-8a4e-7c33-b0d1-5e9a4c17be02';
export const COMMIT_DELAY = 720; // The pointer arrives before the application changes.
export const POINTER_TRAVEL = 620;

export const PROMPTS = {
  qa: 'Test the checkout on shop.example. Do not place an order.',
  hosts: 'Which hosts are available?',
  chat: 'Use studio-mac to open example.com in the browser.',
  transfer: 'Use ops-pc. Open reports.example, download September.csv, then upload it to files.example / Finance.',
  wallpaper: 'On studio-mac, change the wallpaper to the mountain landscape.',
} as const;

export const DEMOS = [
  { id: 'qa', number: '01', title: 'Put your website through its paces.', lead: 'Walk through a checkout. Find what breaks in the browser.', cta: 'Run a website check', href: '/docs/tutorial/first-session', label: 'Website QA', surface: 'browser' },
  { id: 'chat', number: '02', title: 'Pick a computer. Ask for the task.', lead: 'Find your configured Hosts from desktop chat, then send work to one.', cta: 'Connect your chat client', href: '/docs/reference/commands', label: 'Desktop chat', surface: 'conversation' },
  { id: 'transfer', number: '03', title: 'One prompt. From dashboard to delivery.', lead: 'Ask Claude Code to use a computer, download a report, and upload it.', cta: 'Connect your coding agent', href: '/docs/reference/commands', label: 'Claude Code', surface: 'terminal-and-browser' },
  { id: 'wallpaper', number: '04', title: 'Make the desktop feel like yours.', lead: 'Ask for a new macOS wallpaper. Watch the change on the Host.', cta: 'Set up your Host', href: '/docs/how-to/setup-host', label: 'macOS desktop', surface: 'desktop' },
] as const;
export type DemoId = (typeof DEMOS)[number]['id'];
export type Beat = Readonly<{ label: string; ms: number; target?: string }>;

export const TIMELINES: Record<DemoId, readonly Beat[]> = {
  qa: [
    { label: 'Open the staging website', ms: 2200 },
    { label: 'Add an item to the cart', ms: 1500, target: 'qa-add' },
    { label: 'Open checkout', ms: 1500, target: 'qa-checkout' },
    { label: 'Enter an invalid email', ms: 1800, target: 'qa-email' },
    { label: 'Test form validation', ms: 1600, target: 'qa-continue' },
    { label: 'Review the finding', ms: 2000, target: 'qa-finding' },
  ],
  chat: [
    { label: 'Ask which Hosts are available', ms: 1800 },
    { label: 'Read configured Host contexts', ms: 1500 },
    { label: 'Show configured Hosts', ms: 2100 },
    { label: 'Ask for a task on studio-mac', ms: 2400 },
    { label: 'Send the task through MCP', ms: 1500 },
    { label: 'Show detached admission', ms: 2000 },
  ],
  transfer: [
    { label: 'Give Claude Code the task', ms: 3400 },
    { label: 'Send work to ops-pc', ms: 1600 },
    { label: 'Browse the reports dashboard', ms: 1600, target: 'reports' },
    { label: 'Download September.csv', ms: 1800, target: 'download' },
    { label: 'Open the Finance destination', ms: 1600, target: 'destination' },
    { label: 'Open the file picker', ms: 1500, target: 'choose-file' },
    { label: 'Select the downloaded file', ms: 1600, target: 'local-file' },
    { label: 'Upload to Finance', ms: 1900, target: 'upload' },
    { label: 'Confirm the example upload', ms: 1800 },
  ],
  wallpaper: [
    { label: 'Ask for a new wallpaper', ms: 2200 },
    { label: 'Open System Settings', ms: 1600, target: 'settings' },
    { label: 'Choose Wallpaper', ms: 1600, target: 'wallpaper' },
    { label: 'Select the mountain landscape', ms: 2000, target: 'mountains' },
    { label: 'Return to the desktop', ms: 1500, target: 'close-settings' },
    { label: 'Show the new wallpaper', ms: 2000 },
  ],
};

export const duration = (beats: readonly Beat[]) => beats.reduce((sum, beat) => sum + beat.ms, 0);
export const stepStart = (beats: readonly Beat[], index: number) => duration(beats.slice(0, index));
/** Pure clock projection used by both playback and tests. No wall-clock dates. */
export function sample(beats: readonly Beat[], elapsed: number) {
  const total = duration(beats);
  const safe = Number.isFinite(elapsed) ? Math.max(0, Math.min(elapsed, total)) : 0;
  let step = 0;
  let local = safe;
  while (step < beats.length - 1 && local >= beats[step].ms) local -= beats[step++].ms;
  return {
    step, local, total, elapsed: safe, done: safe === total,
    committed: Math.max(0, step - (local < COMMIT_DELAY ? 1 : 0)),
    pointer: Math.min(1, local / POINTER_TRAVEL),
    label: beats[step].label, target: beats[step].target,
  };
}
export type Frame = ReturnType<typeof sample>;
export function typed(text: string, frame: Frame, step: number, ms = 1600) {
  if (frame.step < step) return '';
  if (frame.step > step || frame.done) return text;
  return text.slice(0, Math.floor(text.length * Math.min(1, frame.local / ms)));
}

/** config_check(all=true) enumerates checked_contexts, not network discovery.
 * These are selected real result fields; native readiness is NOT checked here. */
export const HOST_CHECK = {
  input: { all: true },
  fields: {
    schema_version: 'satelle.config.check.v1', status: 'ok', mode: 'all',
    checked_contexts: [{ host: 'studio-mac', status: 'ok' }, { host: 'ops-pc', status: 'ok' }],
    not_checked: ['remote_host', 'provider_auth', 'native_computer_use'],
  },
} as const;
export const CHAT_RUN = {
  input: { host: 'studio-mac', prompt: PROMPTS.chat, detach: true },
  fields: { schema_version: 'satelle.run.v2', session_id: SESSION, status: 'starting' },
} as const;
export const TRANSFER_RUN = {
  input: { host: 'ops-pc', prompt: PROMPTS.transfer, detach: true },
  fields: { schema_version: 'satelle.run.v2', session_id: SESSION, status: 'starting' },
} as const;
