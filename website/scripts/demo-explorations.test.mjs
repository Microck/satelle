import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { createRequire } from 'node:module';
import test from 'node:test';

// Test the actual fixtures. TypeScript is already a website devDependency.
const require = createRequire(import.meta.url);
const ts = require('typescript');
const location = '../app/(landing)/demos/';
const source = readFileSync(new URL(`${location}exploration-data.ts`, import.meta.url), 'utf8');
const component = readFileSync(new URL(`${location}explorations.tsx`, import.meta.url), 'utf8');
const { outputText, diagnostics } = ts.transpileModule(source, {
  reportDiagnostics: true,
  compilerOptions: { target: ts.ScriptTarget.ES2022, module: ts.ModuleKind.ES2022 },
});
assert.equal(diagnostics?.length ?? 0, 0);
const data = await import(`data:text/javascript;base64,${Buffer.from(outputText).toString('base64')}`);
const { DEFAULT_SELECTION, DEMOS, SESSION, TURN, CLI_OUTPUT, MCP_EXAMPLE, HOST, MONTHS, READ_TOOLS, parseSelection, toggleSelection } = data;

test('six scenarios have six different interface types', () => {
  assert.equal(DEMOS.length, 6);
  assert.equal(new Set(DEMOS.map(demo => demo.id)).size, 6);
  assert.equal(new Set(DEMOS.map(demo => demo.surface)).size, 6);
});
test('homepage defaults are four non-terminal scenarios', () => {
  assert.equal(DEFAULT_SELECTION.length, 4);
  assert.deepEqual(DEFAULT_SELECTION, ['spreadsheet', 'chat', 'editor', 'browser']);
  assert.ok(DEFAULT_SELECTION.every(id => DEMOS.some(demo => demo.id === id && demo.surface !== 'terminal')));
});
test('the CLI is the only terminal-marked body', () => {
  assert.equal(DEMOS.filter(demo => demo.surface === 'terminal').length, 1);
  assert.equal((component.match(/className="sx-terminal"/g) ?? []).length, 1);
  for (const name of ['SpreadsheetDemo', 'ChatDemo', 'EditorDemo', 'BrowserDemo', 'DocumentDemo', 'TerminalDemo']) {
    assert.match(component, new RegExp(`class ${name} extends React.Component`));
  }
});
test('missing, invalid, and old selections normalize to fresh defaults', () => {
  for (const value of [null, 'unknown,<script>', 'durability,readiness,transports,agent']) {
    assert.deepEqual(parseSelection(value), DEFAULT_SELECTION);
  }
  assert.notEqual(parseSelection(null), DEFAULT_SELECTION);
});
test('explicitly empty selection stays empty', () => assert.deepEqual(parseSelection(''), []));
test('URL parsing deduplicates, removes unknown IDs and caps at four', () => {
  assert.deepEqual(parseSelection('chat,chat,unknown,document,editor,browser,terminal'), ['chat', 'document', 'editor', 'browser']);
});
test('selection changes are immutable', () => {
  const original = Object.freeze([...DEFAULT_SELECTION]);
  const fewer = toggleSelection(original, 'editor');
  assert.equal(fewer.length, 3);
  assert.equal(original.length, 4);
  assert.deepEqual(toggleSelection(fewer, 'document'), ['spreadsheet', 'chat', 'browser', 'document']);
});
test('a fifth selection is not admitted', () => assert.deepEqual(toggleSelection(DEFAULT_SELECTION, 'terminal'), DEFAULT_SELECTION));
test('every scenario can be chosen independently', () => {
  for (const demo of DEMOS) assert.deepEqual(toggleSelection([], demo.id), [demo.id]);
});
test('Session and Turn IDs are well-formed UUIDv7 examples', () => {
  const uuid = '[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}';
  assert.match(SESSION, new RegExp(`^rs_${uuid}$`));
  assert.match(TURN, new RegExp(`^rt_${uuid}$`));
});
test('detached admission and later status retain real CLI field shapes', () => {
  assert.deepEqual(CLI_OUTPUT.start, [`Session: ${SESSION}`, 'Status: starting']);
  assert.deepEqual(CLI_OUTPUT.reconnect, [`Session: ${SESSION}`, `Host: ${HOST}`, 'Status: running', 'Turns: 1', `Latest turn: ${TURN}`, 'Latest status: running']);
});
test('MCP follow-up is explicitly detached and begins after a stopped Turn', () => {
  assert.equal(MCP_EXAMPLE.statusFields.status, 'stopped');
  assert.equal(MCP_EXAMPLE.steerInput.detach, true);
  assert.equal(MCP_EXAMPLE.steerInput.session_id, SESSION);
  assert.equal(MCP_EXAMPLE.steerInput.host, HOST);
  assert.equal(MCP_EXAMPLE.steerInput.prompt, 'Open settings');
  assert.equal(MCP_EXAMPLE.steerFields.status, 'starting');
});
test('MCP schema projections and tool inventory match the release', () => {
  assert.equal(MCP_EXAMPLE.readOnlyToolCount, 8);
  assert.equal(MCP_EXAMPLE.mutationToolCount, 15);
  assert.deepEqual(READ_TOOLS, ['config_check', 'config_explain', 'paths', 'status', 'logs', 'doctor', 'host_status', 'host_sessions']);
  assert.equal(MCP_EXAMPLE.chatFields.schema_version, 'satelle.status.v2');
  assert.equal(MCP_EXAMPLE.statusFields.schema_version, 'satelle.status.v2');
  assert.equal(MCP_EXAMPLE.steerFields.schema_version, 'satelle.steer.v2');
  assert.ok(!('turns' in MCP_EXAMPLE.statusFields));
});
test('the spreadsheet uses the existing synthetic monthly totals', () => {
  assert.equal(data.money(MONTHS.reduce((sum, row) => sum + row.revenue, 0)), '39,444.10');
  assert.equal(data.money(MONTHS.reduce((sum, row) => sum + row.profit, 0)), '16,209.10');
  assert.ok(MONTHS.every(row => row.revenue >= row.profit && row.profit > 0));
});
test('CTAs point to the documentation tree, not invented integrations', () => {
  for (const demo of DEMOS) assert.match(demo.href, /^\/docs\//);
  assert.ok(!/Connect (GitHub|Slack)/.test(source + component));
});
test('native scenarios retain the visible readiness and illustration boundary', () => {
  for (const text of ['not recordings or live runs', 'passes the live readiness probe', 'macOS and Windows are candidate Hosts', 'native Linux Host execution is not supported', 'not app-specific integrations']) assert.ok(component.includes(text));
});
test('only local demo state changes, not Host calls or timed animation', () => {
  assert.ok(!/\b(fetch|WebSocket|EventSource|setInterval|setTimeout)\s*\(/.test(component));
  assert.match(component, /Local demo switch only/);
  assert.match(component, /componentWillUnmount/);
});
test('the component syntax transpiles with the repository JSX mode', () => {
  const { diagnostics } = ts.transpileModule(component, { fileName: 'explorations.tsx', reportDiagnostics: true, compilerOptions: { target: ts.ScriptTarget.ES2022, jsx: ts.JsxEmit.Preserve } });
  assert.equal(diagnostics?.length ?? 0, 0);
});
