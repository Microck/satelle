/** Scripted page illustrations, never live browser/Host requests. */
export const RELEASE = '0.1.10';
export const SESSION = 'rs_0193f2c1-8a4e-7c33-b0d1-5e9a4c17be02';
export const COMMIT_DELAY = 760;
export const POINTER_TRAVEL = 620;
export const DRAG_DURATION = 1200;
export const LOOP_HOLD = 1800;
export const REPORT_FILE = 'Traffic acquisition.csv';
export const PHOTO_FILE = 'profile.png';
export const BRIEF_FILE = 'Documents/launch-brief.pdf';
/** Classic compact Clawd, using full-width terminal cells, not letter spacing.
 * The preformatted glyphs are also the source for the pixel-aligned rendering. */
export const CLAWD = ' ▐▛███▜▌\n▝▜█████▛▘\n  ▘▘ ▝▝';
export const SITES = {
  qa: 'localhost:3000/storefront',
  analytics: 'analytics.google.com/analytics/web/',
  drive: 'drive.google.com/drive/my-drive',
  slack: 'slack.com',
};
export const PROMPTS = {
  qa: 'QA my storefront at wide and narrow widths. Resize the browser and flag broken layouts.',
  hosts: 'What hosts are available?',
  chat: 'On studio-mac, turn Documents/launch-notes.odt into a one-page PDF.',
  transfer: 'Use ops-pc to export the Traffic acquisition report from Google Analytics. Upload the CSV to Reports in Google Drive.',
  slack: 'Change my Slack profile picture to Pictures/profile.png.',
};
export const CHATGPT_INTEGRATION = {
  status: 'concept',
  note: 'ChatGPT concept. A compatible remote MCP bridge is required; it is not included in Satelle.',
};
export const DEMOS = [
  { id: 'qa', number: '01', title: 'Catch the layout that breaks.', lead: 'Resize the browser. Make the responsive bug impossible to miss.', cta: 'Run a website check', href: '/docs/tutorial/first-session', label: 'Responsive QA', surface: 'resizable-browser' },
  { id: 'chat', number: '02', title: 'Start a task. Stay in the conversation.', lead: 'Choose a Host, check progress, and see the finished result.', cta: 'Review connection requirements', href: '/demo-explorations#chatgpt-requirements', label: 'ChatGPT concept', surface: 'conversation' },
  { id: 'transfer', number: '03', title: 'A prompt, then the computer takes over.', lead: 'Export from Google Analytics. Deliver to Google Drive.', cta: 'Connect your coding agent', href: '/docs/reference/commands', label: 'Claude Code', surface: 'terminal-and-browser' },
  { id: 'slack', number: '04', title: 'Your profile, updated for you.', lead: 'Choose the photo. Adjust the crop. Save the change.', cta: 'Operate a Session', href: '/docs/how-to/operate-session', label: 'Slack on macOS', surface: 'slack' },
] as const;
export type DemoId = (typeof DEMOS)[number]['id'];
export type Beat = Readonly<{ label: string; ms: number; target?: string; dragTo?: string }>;
export const TIMELINES: Record<DemoId, readonly Beat[]> = {
  qa: [
    { label: 'Start a responsive QA walkthrough', ms: 2500 },
    { label: 'Inspect the wide storefront', ms: 1700 },
    { label: 'Drag the browser narrower', ms: 2600, target: 'qa-resize', dragTo: 'qa-narrow' },
    { label: 'The purchase button is clipped', ms: 2400 },
    { label: 'Widen the browser to compare', ms: 2400, target: 'qa-resize', dragTo: 'qa-wide' },
    { label: 'Resize again to reproduce the issue', ms: 2400, target: 'qa-resize', dragTo: 'qa-narrow' },
    { label: 'Responsive issue reproduced', ms: 2700 },
  ],
  chat: [
    { label: 'Ask which Hosts are configured', ms: 1600 },
    { label: 'Show two configured Hosts', ms: 2200 },
    { label: 'Ask for a one-page PDF', ms: 2300 },
    { label: 'The Host starts the task', ms: 2400 },
    { label: 'Ask for progress while it runs', ms: 1700 },
    { label: 'Inspect status and recent logs', ms: 2900 },
    { label: 'Ask where the result will be saved', ms: 2000 },
    { label: 'The Host is exporting the PDF', ms: 2600 },
    { label: 'Check completion and show the saved file', ms: 3500 },
  ],
  transfer: [
    { label: 'Give Claude Code the task', ms: 3500 },
    { label: 'Satelle admits the task on ops-pc', ms: 1800 },
    { label: 'Click the terminal’s minimize control', ms: 2100, target: 'terminal-minimize' },
    { label: 'Open the report export menu', ms: 1600, target: 'ga-export' },
    { label: 'Download the CSV', ms: 1700, target: 'ga-csv' },
    { label: 'Switch to Google Drive', ms: 1600, target: 'drive-tab' },
    { label: 'Open Reports', ms: 1600, target: 'drive-folder' },
    { label: 'Open the New menu', ms: 1500, target: 'drive-new' },
    { label: 'Choose File upload', ms: 1500, target: 'drive-upload' },
    { label: 'Select the downloaded CSV', ms: 1700, target: 'transfer-file' },
    { label: 'Open the file to upload it', ms: 2000, target: 'transfer-open' },
    { label: 'Report delivered to Google Drive', ms: 2500 },
  ],
  slack: [
    { label: 'Ask for the profile-photo update', ms: 2200 },
    { label: 'Open your account menu', ms: 1500, target: 'slack-account' },
    { label: 'Choose Profile', ms: 1500, target: 'slack-profile' },
    { label: 'Edit your profile', ms: 1500, target: 'slack-edit' },
    { label: 'Choose Upload Photo', ms: 1500, target: 'slack-upload' },
    { label: 'Open Pictures', ms: 1500, target: 'slack-pictures' },
    { label: 'Select profile.png', ms: 1700, target: 'slack-file' },
    { label: 'Open the selected photo', ms: 1500, target: 'slack-open' },
    { label: 'Drag to adjust the crop', ms: 2400, target: 'slack-crop', dragTo: 'slack-crop-end' },
    { label: 'Save the crop', ms: 1500, target: 'slack-crop-save' },
    { label: 'Save Changes', ms: 1700, target: 'slack-save' },
    { label: 'Your Slack profile photo is updated', ms: 2500 },
  ],
};
export const duration = (beats: readonly Beat[]) => beats.reduce((sum, beat) => sum + beat.ms, 0);
export const stepStart = (beats: readonly Beat[], index: number) => duration(beats.slice(0, index));
export function sample(beats: readonly Beat[], elapsed: number) {
  if (!beats.length) throw new RangeError('A workflow needs at least one beat.');
  const total = duration(beats);
  const safe = Number.isFinite(elapsed) ? Math.max(0, Math.min(elapsed, total)) : 0;
  let step = 0;
  let local = safe;
  while (step < beats.length - 1 && local >= beats[step].ms) local -= beats[step++].ms;
  return { step, local, total, elapsed: safe, done: safe === total,
    committed: Math.max(0, step - (local < COMMIT_DELAY ? 1 : 0)),
    pointer: Math.min(1, local / POINTER_TRAVEL), label: beats[step].label,
    target: beats[step].target, dragTo: beats[step].dragTo };
}
export type Frame = ReturnType<typeof sample>;
export type SceneProps = { frame: Frame; moving: boolean };
export function typed(text: string, frame: Frame, step: number, ms = 1800) {
  if (frame.step < step) return '';
  if (frame.step > step || frame.done) return text;
  return text.slice(0, Math.floor(text.length * Math.min(1, frame.local / ms)));
}
export function phase(frame: Frame, step: number, ms = 900, delay = 0) {
  return frame.step < step ? 0 : frame.step > step || frame.done ? 1 : Math.max(0, Math.min(1, (frame.local - delay) / ms));
}
export const ease = (p: number) => p * p * (3 - 2 * p);
export function qaWidth(frame: Frame) {
  return 100 - 36 * ease(phase(frame, 2, DRAG_DURATION, COMMIT_DELAY))
    + 36 * ease(phase(frame, 4, DRAG_DURATION, COMMIT_DELAY))
    - 36 * ease(phase(frame, 5, DRAG_DURATION, COMMIT_DELAY));
}
/** Entire messages arrive at commit time. Only their geometry pops; no fading. */
export function messagePop(frame: Frame, step: number) {
  const t = phase(frame, step, 280, step === 0 ? 0 : COMMIT_DELAY);
  const back = 1 + 2.70158 * (t - 1) ** 3 + 1.70158 * (t - 1) ** 2;
  return { transform: `translateY(${6 * (1 - t)}px) scale(${0.96 + 0.04 * back})` };
}
export const CHAT_MESSAGES = [
  { step: 0, role: 'user', text: PROMPTS.hosts },
  { step: 1, role: 'assistant', tool: 'config_check', text: 'Configured: studio-mac and ops-pc. Live readiness is checked separately.' },
  { step: 2, role: 'user', text: PROMPTS.chat },
  { step: 3, role: 'assistant', tool: 'run · starting', text: 'Task started on studio-mac. I’ll format the notes, then export the PDF.' },
  { step: 4, role: 'user', text: 'How is it going?' },
  { step: 5, role: 'assistant', tool: 'status + logs · running', text: 'Still running. The notes are open and the one-page brief is being formatted.' },
  { step: 6, role: 'user', text: 'Where will the PDF be saved?' },
  { step: 7, role: 'assistant', tool: 'status · running', text: `On studio-mac at ${BRIEF_FILE}. The export is in progress; I’ll check again.` },
  { step: 8, role: 'assistant', tool: 'status · completed', text: 'Completed. The PDF is saved on studio-mac.', file: BRIEF_FILE },
] as const;
export const HOST_CHECK = {
  input: { all: true },
  fields: { schema_version: 'satelle.config.check.v1', status: 'ok', mode: 'all',
    checked_contexts: [{ host: 'studio-mac', status: 'ok' }, { host: 'ops-pc', status: 'ok' }],
    not_checked: ['remote_host', 'provider_auth', 'native_computer_use'] },
};
export const CHAT_RUN = { input: { host: 'studio-mac', prompt: PROMPTS.chat, detach: true }, fields: { schema_version: 'satelle.run.v2', session_id: SESSION, status: 'starting' } };
export const CHAT_STATUS = { input: { host: 'studio-mac', session_id: SESSION }, fields: { schema_version: 'satelle.status.v2', session_id: SESSION, status: 'completed' } };
export const TRANSFER_RUN = { input: { host: 'ops-pc', prompt: PROMPTS.transfer, detach: true }, fields: { schema_version: 'satelle.run.v2', session_id: SESSION, status: 'starting' } };
