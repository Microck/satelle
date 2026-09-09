/** Illustrative website fixtures, not a Satelle client or measured task results.
 * Sources and boundaries: website/DEMO-EXPLORATIONS.md. */
export const RELEASE = '0.1.10';
export const HOST = 'win-11-lab';
export const SESSION = 'rs_0193f2c1-8a4e-7c33-b0d1-5e9a4c17be02';
export const TURN = 'rt_0193f2c1-8a52-7f10-9c44-2b7e8d31af65';

export const DEMOS = [
  { id: 'spreadsheet', number: '01', label: 'Spreadsheet', surface: 'spreadsheet', title: 'Work in the apps already on your Host.', lead: 'An illustrative Q3 report, built in a desktop spreadsheet.', href: '/docs/tutorial/first-session', cta: 'Explore Computer Use' },
  { id: 'chat', number: '02', label: 'Desktop chat', surface: 'conversation', title: 'Ask about your Session in Claude Desktop.', lead: 'Read Host-owned Session state through Satelle’s MCP tools.', href: '/docs/reference/commands', cta: 'Connect an MCP client' },
  { id: 'editor', number: '03', label: 'Coding agent', surface: 'editor', title: 'Keep your editor. Give your agent typed tools.', lead: 'Inspect a Session from Cursor. Enable mutation tools explicitly.', href: '/docs/reference/commands', cta: 'Configure MCP' },
  { id: 'browser', number: '04', label: 'Browser', surface: 'browser', title: 'A new Turn. The same desktop.', lead: 'Open the browser, then ask for a follow-up in the same Session.', href: '/docs/how-to/operate-session', cta: 'Operate a Session' },
  { id: 'document', number: '05', label: 'Document editor', surface: 'document', title: 'Format the document where it lives.', lead: 'An illustrative formatting task in a desktop word processor.', href: '/docs/tutorial/first-session', cta: 'Run a first Session' },
  { id: 'terminal', number: '06', label: 'CLI', surface: 'terminal', title: 'Close the terminal. Keep the Session.', lead: 'Start detached, then check back from a fresh Controller.', href: '/docs/how-to/operate-session', cta: 'Use the CLI' },
] as const;
export type DemoId = (typeof DEMOS)[number]['id'];
// Four different non-terminal interfaces on the homepage. CLI remains an option.
export const DEFAULT_SELECTION: readonly DemoId[] = ['spreadsheet', 'chat', 'editor', 'browser'];
export function isDemoId(value: string): value is DemoId {
  return DEMOS.some((demo) => demo.id === value);
}
export function parseSelection(value: string | null): DemoId[] {
  if (value === null) return [...DEFAULT_SELECTION];
  if (value === '') return [];
  const valid = [...new Set(value.split(',').filter(isDemoId))].slice(0, 4);
  return valid.length ? valid : [...DEFAULT_SELECTION];
}
export function toggleSelection(current: readonly DemoId[], id: DemoId): DemoId[] {
  if (current.includes(id)) return current.filter((item) => item !== id);
  return current.length < 4 ? [...current, id] : [...current];
}

/** The existing Calc showcase's monthly sample, not a measured Satelle run. */
export const MONTHS = [
  { month: 'Jul', revenue: 13701.8, profit: 5562.8 },
  { month: 'Aug', revenue: 11826.35, profit: 4835.35 },
  { month: 'Sep', revenue: 13915.95, profit: 5810.95 },
] as const;
export const money = (amount: number) => amount.toLocaleString('en-US', {
  minimumFractionDigits: 2, maximumFractionDigits: 2,
});
export const READ_TOOLS = [
  'config_check', 'config_explain', 'paths', 'status', 'logs', 'doctor', 'host_status', 'host_sessions',
] as const;
export const MCP_EXAMPLE = {
  readOnlyToolCount: READ_TOOLS.length,
  mutationToolCount: 15,
  statusInput: { session_id: SESSION, host: HOST },
  // No active Turn in the editor example before admitting its follow-up.
  statusFields: { schema_version: 'satelle.status.v2', host: HOST, status: 'stopped' },
  chatFields: { schema_version: 'satelle.status.v2', host: HOST, status: 'running' },
  // schema.rs defaults detach to false; admission output requires true here.
  steerInput: { session_id: SESSION, host: HOST, prompt: 'Open settings', detach: true },
  steerFields: { schema_version: 'satelle.steer.v2', status: 'starting' },
} as const;
export const CLI_OUTPUT = {
  start: [`Session: ${SESSION}`, 'Status: starting'],
  reconnect: [`Session: ${SESSION}`, `Host: ${HOST}`, 'Status: running', 'Turns: 1', `Latest turn: ${TURN}`, 'Latest status: running'],
} as const;
