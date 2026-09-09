import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { createRequire } from 'node:module';
import test from 'node:test';

// TypeScript is already a website devDependency. Test the actual shared module,
// not a duplicate of the selection code. No browser or new package is needed.
const require = createRequire(import.meta.url);
const ts = require('typescript');
const source = readFileSync(new URL('../app/(landing)/demos/exploration-data.ts', import.meta.url), 'utf8');
const { outputText, diagnostics } = ts.transpileModule(source, {
  reportDiagnostics: true,
  compilerOptions: { target: ts.ScriptTarget.ES2022, module: ts.ModuleKind.ES2022 },
});
assert.equal(diagnostics?.length ?? 0, 0);
const data = await import(`data:text/javascript;base64,${Buffer.from(outputText).toString('base64')}`);
const { DEFAULT_SELECTION, DEMOS, PLATFORMS, PROBE_OUTPUT, SESSION, TURN, parseSelection, toggleSelection } = data;

test('six unique concepts and four valid homepage defaults', () => {
  assert.equal(DEMOS.length, 6);
  assert.equal(new Set(DEMOS.map((demo) => demo.id)).size, 6);
  assert.equal(DEFAULT_SELECTION.length, 4);
  for (const id of DEFAULT_SELECTION) assert.ok(DEMOS.some((demo) => demo.id === id));
});
test('missing and invalid URLs fall back to a fresh default selection', () => {
  assert.deepEqual(parseSelection(null), DEFAULT_SELECTION);
  assert.deepEqual(parseSelection('unknown,<script>'), DEFAULT_SELECTION);
  assert.notEqual(parseSelection(null), DEFAULT_SELECTION);
});
test('an explicitly empty selection survives a reload', () => assert.deepEqual(parseSelection(''), []));
test('URL parsing removes duplicates and unknown IDs and caps at four', () => {
  assert.deepEqual(parseSelection('agent,agent,unknown,platforms,boundaries,readiness,durability'), ['agent', 'platforms', 'boundaries', 'readiness']);
});
test('removing and adding is immutable', () => {
  const original = Object.freeze([...DEFAULT_SELECTION]);
  const fewer = toggleSelection(original, 'agent');
  assert.equal(fewer.length, 3);
  assert.equal(original.length, 4);
  assert.deepEqual(toggleSelection(fewer, 'platforms'), ['durability', 'readiness', 'transports', 'platforms']);
});
test('a fifth selection is not admitted', () => assert.deepEqual(toggleSelection(DEFAULT_SELECTION, 'boundaries'), DEFAULT_SELECTION));
test('all six concepts can be selected after clearing the default set', () => {
  for (const demo of DEMOS) assert.deepEqual(toggleSelection([], demo.id), [demo.id]);
});
test('Session and Turn identifiers are well-formed UUIDv7 examples', () => {
  const uuid = '[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}';
  assert.match(SESSION, new RegExp(`^rs_${uuid}$`));
  assert.match(TURN, new RegExp(`^rt_${uuid}$`));
});
test('readiness output uses real fields, not the speculative mockup fields', () => {
  for (const lines of Object.values(PROBE_OUTPUT)) {
    for (const label of ['Host:', 'Status:', 'Ready:', 'Scopes:']) assert.ok(lines.some((line) => line.startsWith(label)));
    assert.ok(!lines.some((line) => /^(Checks:|Reason:|Scope:)/.test(line)));
  }
  assert.ok(PROBE_OUTPUT.blocked.includes('Ready: false'));
  assert.ok(PROBE_OUTPUT.ready.includes('Ready: true'));
  assert.ok(PROBE_OUTPUT.blocked.some((line) => line.includes('manual_action_required')));
  assert.ok(PROBE_OUTPUT.ready.includes('  evidence: source=live'));
});
test('readiness timestamps show the existing five-minute example TTL', () => {
  const observed = PROBE_OUTPUT.ready.find((line) => line.includes('observed_at=')).split('=')[1];
  const expires = PROBE_OUTPUT.ready.find((line) => line.includes('expires_at=')).split('=')[1];
  assert.equal(Date.parse(expires) - Date.parse(observed), 300_000);
});
test('platform claims distinguish the Controller from the native Host', () => {
  assert.ok(PLATFORMS.every((platform) => platform.controller === 'Implemented'));
  assert.equal(PLATFORMS.find((platform) => platform.id === 'linux').host, 'Not supported');
  assert.ok(PLATFORMS.filter((platform) => platform.id !== 'linux').every((platform) => platform.host === 'Candidate'));
});
test('all concept CTAs stay within the documentation tree', () => {
  for (const demo of DEMOS) assert.match(demo.href, /^\/docs\//);
});

test('MCP mutation admission is explicitly detached and targets the example Host', () => {
  const { MCP_EXAMPLE, HOST } = data;
  assert.equal(MCP_EXAMPLE.steerInput.detach, true);
  assert.equal(MCP_EXAMPLE.steerInput.session_id, SESSION);
  assert.equal(MCP_EXAMPLE.steerInput.host, HOST);
  assert.equal(MCP_EXAMPLE.steerInput.prompt, 'Open settings');
  assert.equal(MCP_EXAMPLE.steerFields.status, 'starting');
});
test('MCP fields are projections, with the correct read-only and mutation counts', () => {
  const { MCP_EXAMPLE } = data;
  assert.equal(MCP_EXAMPLE.readOnlyToolCount, 8);
  assert.equal(MCP_EXAMPLE.mutationToolCount, 15);
  assert.equal(MCP_EXAMPLE.statusFields.schema_version, 'satelle.status.v2');
  assert.equal(MCP_EXAMPLE.steerFields.schema_version, 'satelle.steer.v2');
  assert.ok(!('turns' in MCP_EXAMPLE.statusFields));
});
