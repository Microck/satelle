/** Scripted page illustrations, never live browser/Host requests. */
export const RELEASE = '0.1.10';
export const SESSION = 'rs_0193f2c1-8a4e-7c33-b0d1-5e9a4c17be02';
export const COMMIT_DELAY = 760;
export const POINTER_TRAVEL = 620;
export const LOOP_HOLD = 1800;
export const REPORT_FILE = 'Traffic acquisition.csv';
export const PHOTO_FILE = 'profile.png';
export const SITES = {
  qa: 'saucedemo.com/checkout-step-one.html',
  analytics: 'analytics.google.com/analytics/web/',
  drive: 'drive.google.com/drive/my-drive',
  slack: 'slack.com',
};
export const PROMPTS = {
  qa: 'Test the checkout. Check required fields, then review the order. Do not buy anything.',
  hosts: 'What hosts are available?',
  chat: 'Use studio-mac to update my Slack profile picture with Pictures/profile.png.',
  transfer: 'Use ops-pc to export last month’s Traffic acquisition report from Google Analytics as CSV. Upload the downloaded file to the Reports folder in Google Drive.',
  slack: 'On studio-mac, change my Slack profile picture to Pictures/profile.png.',
};
export const CHATGPT_INTEGRATION = {
  status: 'concept',
  note: 'ChatGPT concept. A compatible remote MCP bridge is required; it is not included in Satelle.',
};
export const DEMOS = [
  { id: 'qa', number: '01', title: 'Put your checkout through its paces.', lead: 'Fill the form. Check validation. Review the order before payment.', cta: 'Run a website check', href: '/docs/tutorial/first-session', label: 'Website QA', surface: 'checkout' },
  { id: 'chat', number: '02', title: 'Choose a computer. Ask for the task.', lead: 'Your configured Hosts, in one conversation.', cta: 'Review connection requirements', href: '/demo-explorations#chatgpt-requirements', label: 'ChatGPT concept', surface: 'conversation' },
  { id: 'transfer', number: '03', title: 'Start in Claude Code. Finish on the computer.', lead: 'Export from Google Analytics. Deliver to Google Drive. One request.', cta: 'Connect your coding agent', href: '/docs/reference/commands', label: 'Claude Code', surface: 'terminal-and-browser' },
  { id: 'slack', number: '04', title: 'Your profile, updated for you.', lead: 'Open Slack, choose your photo, adjust the crop, and save your profile.', cta: 'Operate a Session', href: '/docs/how-to/operate-session', label: 'Slack on macOS', surface: 'slack' },
] as const;
export type DemoId = (typeof DEMOS)[number]['id'];
export type Beat = Readonly<{ label: string; ms: number; target?: string }>;
export const TIMELINES: Record<DemoId, readonly Beat[]> = {
  qa: [
    { label: 'Open the checkout', ms: 2200 },
    { label: 'Enter the first name', ms: 1700, target: 'qa-first' },
    { label: 'Continue with a required field empty', ms: 1600, target: 'qa-continue' },
    { label: 'Check the required-field message', ms: 1600 },
    { label: 'Complete the missing details', ms: 2200, target: 'qa-last' },
    { label: 'Review the order', ms: 1700, target: 'qa-continue' },
    { label: 'Validation checked. No purchase made.', ms: 2600 },
  ],
  chat: [
    { label: 'Ask which Hosts are configured', ms: 1800 },
    { label: 'Read the Host configuration', ms: 1400 },
    { label: 'Show two configured Hosts', ms: 1900 },
    { label: 'Ask for a task on studio-mac', ms: 2500 },
    { label: 'Send the proposed task', ms: 1500 },
    { label: 'Task admitted. First Turn starting.', ms: 2500 },
  ],
  transfer: [
    { label: 'Give Claude Code the task', ms: 4200 },
    { label: 'Admit the task on ops-pc through Satelle', ms: 2000 },
    { label: 'Minimize the terminal and reveal the Host', ms: 1500 },
    { label: 'Open the Traffic acquisition report', ms: 1500, target: 'ga-report' },
    { label: 'Share this report', ms: 1300, target: 'ga-share' },
    { label: 'Choose Download File', ms: 1200, target: 'ga-download' },
    { label: 'Download CSV to the Host', ms: 1600, target: 'ga-csv' },
    { label: 'Switch to Google Drive', ms: 1400, target: 'drive-tab' },
    { label: 'Open the Reports folder', ms: 1400, target: 'drive-folder' },
    { label: 'Open the New menu', ms: 1200, target: 'drive-new' },
    { label: 'Choose File upload', ms: 1300, target: 'drive-upload' },
    { label: 'Select the downloaded CSV', ms: 1600, target: 'transfer-file' },
    { label: 'Open the file to upload it', ms: 2200, target: 'transfer-open' },
    { label: 'Report delivered to Google Drive', ms: 2000 },
  ],
  slack: [
    { label: 'Ask to update your Slack profile photo', ms: 2800 },
    { label: 'Open your Slack account menu', ms: 1400, target: 'slack-account' },
    { label: 'Choose Profile', ms: 1400, target: 'slack-profile' },
    { label: 'Edit your profile', ms: 1400, target: 'slack-edit' },
    { label: 'Upload Photo', ms: 1500, target: 'slack-upload' },
    { label: 'Open Pictures in the file picker', ms: 1400, target: 'slack-pictures' },
    { label: 'Select profile.png', ms: 1600, target: 'slack-file' },
    { label: 'Open the selected image', ms: 1500, target: 'slack-open' },
    { label: 'Adjust the profile-photo framing', ms: 1800, target: 'slack-crop' },
    { label: 'Save the crop', ms: 1500, target: 'slack-crop-save' },
    { label: 'Save Changes to your profile', ms: 1700, target: 'slack-save' },
    { label: 'Your Slack profile photo is updated', ms: 2200 },
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
    pointer: Math.min(1, local / POINTER_TRAVEL), label: beats[step].label, target: beats[step].target };
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
export const HOST_CHECK = {
  input: { all: true },
  fields: { schema_version: 'satelle.config.check.v1', status: 'ok', mode: 'all',
    checked_contexts: [{ host: 'studio-mac', status: 'ok' }, { host: 'ops-pc', status: 'ok' }],
    not_checked: ['remote_host', 'provider_auth', 'native_computer_use'] },
};
export const CHAT_RUN = {
  input: { host: 'studio-mac', prompt: PROMPTS.chat, detach: true },
  fields: { schema_version: 'satelle.run.v2', session_id: SESSION, status: 'starting' },
};
export const TRANSFER_RUN = {
  input: { host: 'ops-pc', prompt: PROMPTS.transfer, detach: true },
  fields: { schema_version: 'satelle.run.v2', session_id: SESSION, status: 'starting' },
};
