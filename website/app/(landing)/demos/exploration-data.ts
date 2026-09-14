/** Scripted page illustrations, never live browser/Host requests. */
export const RELEASE = "0.1.10";
export const SESSION = "rs_0193f2c1-8a4e-7c33-b0d1-5e9a4c17be02";
export const COMMIT_DELAY = 760;
export const POINTER_TRAVEL = 620;
export const POINTER_PRESS = 670;
export const POINTER_RELEASE = 100;
export const POINTER_LINGER = 130;
export const DRAG_DURATION = 1200;
export const MINIMIZE_DURATION = 320;
export const LOOP_HOLD = 1800;
export const REPORT_FILE = "Traffic acquisition.csv";
export const PHOTO_FILE = "profile.png";
export const BRIEF_FILE = "Documents/launch-brief.pdf";
export const CLAWD = " ▐▛███▜▌\n▝▜█████▛▘\n  ▘▘ ▝▝";
export const SITES = {"qa": "localhost:3000/storefront", "analytics": "analytics.google.com/analytics/web/", "drive": "drive.google.com/drive/my-drive", "slack": "slack.com"} as const;
export const PROMPTS = {"qa": "QA my storefront at wide and narrow widths. Resize the browser and flag broken layouts.", "hosts": "What hosts are available?", "chat": "On studio-mac, turn Documents/launch-notes.odt into a one-page PDF.", "transfer": "Use ops-pc to export the Traffic acquisition report from Google Analytics. Upload the CSV to Reports in Google Drive.", "slack": "Change my Slack profile picture to Pictures/profile.png."} as const;
export const CHATGPT_INTEGRATION = {"status": "concept", "note": "ChatGPT concept. A compatible remote MCP bridge is required; it is not included in Satelle."} as const;
export const DEMOS = [
  {"id": "qa", "number": "01", "title": "Test the experience, end to end.", "lead": "Check real interfaces on the computers you control.", "cta": "Run a website check", "href": "/docs/tutorial/first-session", "label": "Website QA", "surface": "resizable-browser"},
  {"id": "chat", "number": "02", "title": "Talk to your computers.", "lead": "Start tasks, follow progress, and see the result.", "cta": "Watch the task", "href": "#channels", "label": "ChatGPT concept", "surface": "conversation"},
  {"id": "transfer", "number": "03", "title": "Give your coding agent a computer.", "lead": "Go beyond the editor and get work done in your apps.", "cta": "Connect your coding agent", "href": "/docs/reference/commands", "label": "Coding agents", "surface": "terminal-and-browser"},
  {"id": "slack", "number": "04", "title": "Skip the repetitive clicks.", "lead": "Let your Host handle the everyday work in your apps.", "cta": "Operate a Session", "href": "/docs/how-to/operate-session", "label": "Desktop tasks", "surface": "slack"}
] as const;
export const PLAYBACK_RATE = 1.25;
export type DemoId = (typeof DEMOS)[number]['id'];
export type Beat = Readonly<{ label: string; ms: number; target?: string; dragTo?: string }>;
export const TIMELINES: Record<DemoId, readonly Beat[]> = {
  qa: [
    {"label": "Start a responsive QA walkthrough", "ms": 2500},
    {"label": "Inspect the wide storefront", "ms": 1700},
    {"label": "Drag the browser narrower", "ms": 2600, "target": "qa-resize", "dragTo": "qa-narrow"},
    {"label": "The purchase button is clipped", "ms": 2400},
    {"label": "Widen the browser to compare", "ms": 2400, "target": "qa-resize", "dragTo": "qa-wide"},
    {"label": "Resize again to reproduce the issue", "ms": 2400, "target": "qa-resize", "dragTo": "qa-narrow"},
    {"label": "Responsive issue reproduced", "ms": 2700}
  ],
  chat: [
    {"label": "Ask which Hosts are configured", "ms": 1600},
    {"label": "Show two configured Hosts", "ms": 2200},
    {"label": "Ask for a one-page PDF", "ms": 2300},
    {"label": "The Host starts the task", "ms": 2400},
    {"label": "Ask for progress while it runs", "ms": 1700},
    {"label": "Inspect status and recent logs", "ms": 2900},
    {"label": "Ask where the result will be saved", "ms": 2000},
    {"label": "The Host is exporting the PDF", "ms": 2600},
    {"label": "Check completion and show the saved file", "ms": 3500}
  ],
  transfer: [
    {"label": "Give Claude Code the task", "ms": 3500},
    {"label": "Satelle admits the task on ops-pc", "ms": 1800},
    {"label": "Click the terminal’s minimize control", "ms": 1400, "target": "terminal-minimize"},
    {"label": "Open the report export menu", "ms": 1600, "target": "ga-export"},
    {"label": "Download the CSV", "ms": 1700, "target": "ga-csv"},
    {"label": "Switch to Google Drive", "ms": 1600, "target": "drive-tab"},
    {"label": "Open Reports", "ms": 1600, "target": "drive-folder"},
    {"label": "Open the New menu", "ms": 1500, "target": "drive-new"},
    {"label": "Choose File upload", "ms": 1500, "target": "drive-upload"},
    {"label": "Select the downloaded CSV", "ms": 1700, "target": "transfer-file"},
    {"label": "Open the file to upload it", "ms": 2000, "target": "transfer-open"},
    {"label": "Report delivered to Google Drive", "ms": 2500}
  ],
  slack: [
    {"label": "Ask for the profile-photo update", "ms": 2200},
    {"label": "Open your account menu", "ms": 1500, "target": "slack-account"},
    {"label": "Choose Profile", "ms": 1500, "target": "slack-profile"},
    {"label": "Edit your profile", "ms": 1500, "target": "slack-edit"},
    {"label": "Choose Upload Photo", "ms": 1500, "target": "slack-upload"},
    {"label": "Open Pictures", "ms": 1500, "target": "slack-pictures"},
    {"label": "Select profile.png", "ms": 1700, "target": "slack-file"},
    {"label": "Open the selected photo", "ms": 1500, "target": "slack-open"},
    {"label": "Drag to adjust the crop", "ms": 2400, "target": "slack-crop", "dragTo": "slack-crop-end"},
    {"label": "Save the crop", "ms": 1500, "target": "slack-crop-save"},
    {"label": "Save Changes", "ms": 1700, "target": "slack-save"},
    {"label": "Your Slack profile photo is updated", "ms": 2500}
  ]
};
export const duration = (beats: readonly Beat[]) => beats.reduce((sum, beat) => sum + beat.ms, 0);
export const stepStart = (beats: readonly Beat[], index: number) => duration(beats.slice(0, index));
/** Wall time is scaled once. Cursor, application, chat and hold timings share it. */
export const playbackDelta = (ms: number) => Number.isFinite(ms) ? Math.max(0, Math.min(100, ms)) * PLAYBACK_RATE : 0;
export function sample(beats: readonly Beat[], elapsed: number) {
  if (!beats.length) throw new RangeError('A workflow needs at least one beat.');
  const total = duration(beats);
  const safe = Number.isFinite(elapsed) ? Math.max(0, Math.min(elapsed, total)) : 0;
  let step = 0, local = safe;
  while (step < beats.length - 1 && local >= beats[step].ms) local -= beats[step++].ms;
  return { step, local, total, elapsed: safe, done: safe === total,
    committed: Math.max(0, step - (local < COMMIT_DELAY ? 1 : 0)),
    pointer: Math.min(1, local / POINTER_TRAVEL), label: beats[step].label,
    target: beats[step].target, dragTo: beats[step].dragTo,
    previousTarget: beats[step - 1]?.target, nextTarget: beats[step + 1]?.target };
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
/** Keep the same cursor on screen between consecutive pointer actions. Only
 * an actual idle/typing/result beat ends the sequence. Release never hides it. */
export function gesturePhase(frame: Frame) {
  const releaseAt = COMMIT_DELAY + (frame.dragTo ? DRAG_DURATION : POINTER_RELEASE);
  const visible = Boolean(frame.target && !frame.done &&
    (frame.nextTarget || frame.local < releaseAt + POINTER_LINGER));
  const pressed = visible && frame.local >= POINTER_PRESS && frame.local < releaseAt;
  return { visible, pressed, dragging: pressed && Boolean(frame.dragTo) && frame.local >= COMMIT_DELAY, releaseAt };
}
export function terminalMinimize(frame: Frame) {
  const progress = phase(frame, 2, MINIMIZE_DURATION, COMMIT_DELAY);
  return 1 - (1 - progress) ** 3;
}
/** Whole messages, geometry-only popup. No opacity animation. */
export function messagePop(frame: Frame, step: number) {
  const t = phase(frame, step, 280, step === 0 ? 0 : COMMIT_DELAY);
  const back = 1 + 2.70158 * (t - 1) ** 3 + 1.70158 * (t - 1) ** 2;
  return { transform: `translateY(${6 * (1 - t)}px) scale(${0.96 + 0.04 * back})` };
}
export const CHAT_MESSAGES = [
  {"step": 0, "role": "user", "text": "What hosts are available?"},
  {"step": 1, "role": "assistant", "tool": "config_check", "text": "Configured: studio-mac and ops-pc. Live readiness is checked separately."},
  {"step": 2, "role": "user", "text": "On studio-mac, turn Documents/launch-notes.odt into a one-page PDF."},
  {"step": 3, "role": "assistant", "tool": "run · starting", "text": "Task started on studio-mac. I’ll format the notes, then export the PDF."},
  {"step": 4, "role": "user", "text": "How is it going?"},
  {"step": 5, "role": "assistant", "tool": "status + logs · running", "text": "Still running. The notes are open and the one-page brief is being formatted."},
  {"step": 6, "role": "user", "text": "Where will the PDF be saved?"},
  {"step": 7, "role": "assistant", "tool": "status · running", "text": "On studio-mac at Documents/launch-brief.pdf. The export is in progress; I’ll check again."},
  {"step": 8, "role": "assistant", "tool": "status · completed", "text": "Completed. The PDF is saved on studio-mac.", "file": "Documents/launch-brief.pdf"}
] as const;
export type McpActivity = Readonly<{ tools: readonly string[]; action: string; state: 'checked' | 'started' | 'running' | 'completed' }>;
export const MCP_ACTIVITIES: Record<number, McpActivity> = {"1": {"tools": ["config_check"], "action": "2 configured Hosts", "state": "checked"}, "3": {"tools": ["run"], "action": "Task admitted · studio-mac", "state": "started"}, "5": {"tools": ["status", "logs"], "action": "Checking the Session", "state": "running"}, "7": {"tools": ["status"], "action": "Export in progress", "state": "running"}, "8": {"tools": ["status"], "action": "Task completed", "state": "completed"}};
export const HOST_CHECK = {"input": {"all": true}, "fields": {"schema_version": "satelle.config.check.v1", "status": "ok", "mode": "all", "checked_contexts": [{"host": "studio-mac", "status": "ok"}, {"host": "ops-pc", "status": "ok"}], "not_checked": ["remote_host", "provider_auth", "native_computer_use"]}} as const;
export const CHAT_RUN = {"input": {"host": "studio-mac", "prompt": "On studio-mac, turn Documents/launch-notes.odt into a one-page PDF.", "detach": true}, "fields": {"schema_version": "satelle.run.v2", "session_id": "rs_0193f2c1-8a4e-7c33-b0d1-5e9a4c17be02", "status": "starting"}} as const;
export const CHAT_STATUS = {"input": {"host": "studio-mac", "session_id": "rs_0193f2c1-8a4e-7c33-b0d1-5e9a4c17be02"}, "fields": {"schema_version": "satelle.status.v2", "session_id": "rs_0193f2c1-8a4e-7c33-b0d1-5e9a4c17be02", "status": "completed"}} as const;
export const TRANSFER_RUN = {"input": {"host": "ops-pc", "prompt": "Use ops-pc to export the Traffic acquisition report from Google Analytics. Upload the CSV to Reports in Google Drive.", "detach": true}, "fields": {"schema_version": "satelle.run.v2", "session_id": "rs_0193f2c1-8a4e-7c33-b0d1-5e9a4c17be02", "status": "starting"}} as const;
