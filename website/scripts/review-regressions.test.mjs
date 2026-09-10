import assert from 'node:assert/strict';
import { mkdtempSync, mkdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { createRequire } from 'node:module';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { spawnSync } from 'node:child_process';
import test from 'node:test';

const require = createRequire(import.meta.url);
const ts = require('typescript');
const read = path => readFileSync(new URL(path, import.meta.url), 'utf8');

/** Compile an isolated, real source declaration without its unrelated UI imports. */
function compile(source, fileName = 'regression.ts') {
  const result = ts.transpileModule(source, {
    fileName,
    reportDiagnostics: true,
    compilerOptions: {
      target: ts.ScriptTarget.ES2022,
      module: ts.ModuleKind.CommonJS,
      jsx: ts.JsxEmit.React,
    },
  });
  assert.equal(result.diagnostics?.length ?? 0, 0);
  return result.outputText;
}

/** Locate a named function structurally, rather than matching emitted formatting. */
function namedFunction(source, name) {
  const node = source.statements.find(node => ts.isFunctionDeclaration(node) && node.name?.text === name);
  assert.ok(node, `Missing function ${name}`);
  return node;
}

/** Find action literals inside an effect without allowing comments to satisfy it. */
function dispatchesSettle(node) {
  if (ts.isCallExpression(node) && ts.isIdentifier(node.expression) && node.expression.text === 'dispatch') {
    const action = node.arguments[0];
    if (action && ts.isObjectLiteralExpression(action)) {
      return action.properties.some(property => ts.isPropertyAssignment(property) &&
        property.name.getText() === 'type' && ts.isStringLiteral(property.initializer) &&
        property.initializer.text === 'settle');
    }
  }
  return ts.forEachChild(node, dispatchesSettle) ?? false;
}

const desk = ts.createSourceFile('desk.tsx', read('../app/(landing)/demos/desk.tsx'), ts.ScriptTarget.Latest, true, ts.ScriptKind.TSX);
const deskBody = namedFunction(desk, 'DeskDemo').body;
const lastStep = desk.statements.find(node => ts.isVariableStatement(node) &&
  node.declarationList.declarations.some(declaration => declaration.name.getText(desk) === 'lastStepOf'));
assert.ok(lastStep);
const reducerSource = `${lastStep.getText(desk)}\n${namedFunction(desk, 'reduce').getText(desk)}`;
const effects = deskBody.statements.filter(node => ts.isExpressionStatement(node) &&
  ts.isCallExpression(node.expression) && node.expression.expression.getText(desk) === 'useEffect' &&
  dispatchesSettle(node));
assert.ok(effects.length > 0);
const runEffects = new Function('state', 'reduced', 'dispatch', 'lastStepOf', 'useEffect',
  compile(effects.map(node => node.getText(desk)).join('\n')));
const committedDeclaration = deskBody.statements.filter(ts.isVariableStatement)
  .flatMap(node => [...node.declarationList.declarations])
  .find(node => node.name.getText(desk) === 'committed');
assert.ok(committedDeclaration?.initializer);
const committed = new Function('state', 'reduced', `return (${committedDeclaration.initializer.getText(desk)});`);

// Intentionally unequal fixtures expose a hardcoded Excel bound.
const stages = ['excel', 'kicad', 'godot', 'filing'].map((id, index) => ({ id, steps: Array(3 + index * 2).fill({}) }));
const { reduce, lastStepOf } = new Function('STAGES', `${compile(reducerSource)}\nreturn { reduce, lastStepOf };`)(stages);

/** Exercise the real effect callbacks and dependency lists using batched dispatch. */
function hero(initialReduced = true) {
  let state = { stage: 'excel', step: 0, phase: 'acted', auto: true };
  let reduced = initialReduced;
  const previousDependencies = [];
  function flush() {
    for (let render = 0; render < 20; render++) {
      let index = 0;
      const callbacks = [];
      const actions = [];
      const useEffect = (callback, dependencies) => {
        const previous = previousDependencies[index];
        if (!previous || dependencies.some((value, i) => !Object.is(value, previous[i]))) callbacks.push(callback);
        previousDependencies[index++] = dependencies;
      };
      runEffects(state, reduced, action => actions.push(action), lastStepOf, useEffect);
      callbacks.forEach(callback => callback());
      if (!actions.length) return state;
      state = actions.reduce(reduce, state);
    }
    throw new Error('Reduced-motion effects did not settle');
  }
  flush();
  return {
    get state() { return state; },
    dispatch(action) { state = reduce(state, action); return flush(); },
    motion(value) { reduced = value; return flush(); },
  };
}

test('reduced motion initially opens on the finished Excel Turn', () => {
  assert.deepEqual(hero().state, { stage: 'excel', step: lastStepOf('excel'), phase: 'acted', auto: false });
});

for (const { id } of stages) {
  test(`reduced motion: ${id} opens on its own finished Turn`, () => {
    const demo = hero();
    if (id === 'excel') demo.dispatch({ type: 'pick', stage: 'kicad' });
    demo.dispatch({ type: 'pick', stage: id });
    assert.deepEqual(demo.state, { stage: id, step: lastStepOf(id), phase: 'acted', auto: false });
  });
  test(`reduced motion: ${id} navigation and replay commit without a cursor`, () => {
    const demo = hero();
    demo.dispatch({ type: 'pick', stage: id });
    for (const step of [0, 1, lastStepOf(id), 0]) {
      demo.dispatch({ type: 'goto', step });
      assert.equal(demo.state.step, step);
      assert.equal(demo.state.phase, 'acted');
      assert.equal(demo.state.auto, false);
    }
    demo.dispatch({ type: 'next' });
    assert.equal(demo.state.step, 1);
    assert.equal(demo.state.phase, 'acted');
    demo.dispatch({ type: 'replay' });
    assert.equal(demo.state.step, 0);
    assert.equal(demo.state.phase, 'acted');
    demo.dispatch({ type: 'goto', step: 999 });
    demo.dispatch({ type: 'next' });
    assert.equal(demo.state.step, lastStepOf(id));
    assert.equal(demo.state.phase, 'acted');
  });
}

test('enabling reduced motion settles the active task rather than Excel', () => {
  const demo = hero(false);
  demo.dispatch({ type: 'pick', stage: 'filing' });
  assert.equal(demo.state.phase, 'travel');
  demo.motion(true);
  assert.equal(demo.state.step, lastStepOf('filing'));
  assert.equal(demo.state.phase, 'acted');
});

test('normal motion still waits for pointer arrival', () => {
  const demo = hero(false);
  demo.dispatch({ type: 'next' });
  assert.equal(demo.state.phase, 'travel');
  assert.equal(committed(demo.state, false), 0);
  demo.dispatch({ type: 'arrive' });
  assert.equal(demo.state.phase, 'acted');
});

test('reduced motion displays the selected step even before effects flush', () => {
  assert.equal(committed({ step: 0, phase: 'travel' }, true), 0);
  assert.equal(committed({ step: 3, phase: 'travel' }, true), 3);
});

const sceneSource = ts.createSourceFile('landing-scenes.tsx', read('../app/(landing)/demos/landing-scenes.tsx'), ts.ScriptTarget.Latest, true, ts.ScriptKind.TSX);
const clawdSource = compile(namedFunction(sceneSource, 'Clawd').getText(sceneSource), 'clawd.tsx');
const React = { createElement: (type, props, ...children) => ({ type, props, children: children.flat(Infinity) }) };
for (const mascot of [' ▐▛███▜▌\n▝▜█████▛▘\n  ▘▘ ▝▝', '███████████\n▐▌']) {
  test(`Clawd viewBox contains every rendered quadrant (${mascot.split('\n')[0].length} columns in first row)`, () => {
    const Clawd = new Function('React', 'data', 'exports', `${clawdSource}\nreturn exports.Clawd;`)(React, { CLAWD: mascot }, {});
    const svg = Clawd();
    assert.equal(svg.type, 'svg');
    const [, , width, height] = svg.props.viewBox.split(' ').map(Number);
    assert.equal(width, Math.max(...mascot.split('\n').map(line => Array.from(line).length)) * 10);
    assert.equal(height, mascot.split('\n').length * 16);
    for (const rect of svg.children) {
      assert.equal(rect.type, 'rect');
      assert.ok(rect.props.x >= 0 && rect.props.x + Number(rect.props.width) <= width);
      assert.ok(rect.props.y >= 0 && rect.props.y + Number(rect.props.height) <= height);
    }
  });
}

const installer = read('../public/install');
const preflightStart = installer.indexOf('command -v gh');
const preflightEnd = installer.indexOf('validate_paths_output()', preflightStart);
assert.ok(preflightStart >= 0 && preflightEnd > preflightStart);
const preflight = installer.slice(preflightStart, preflightEnd);

for (const state of ['missing', 'unauthenticated', 'authenticated']) {
  test(`installer preflight handles ${state} gh without live API calls`, () => {
    const directory = mkdtempSync(join(tmpdir(), 'satelle-preflight-'));
    try {
      const log = join(directory, 'calls');
      writeFileSync(join(directory, 'jq'), '#!/bin/sh\nexit 0\n', { mode: 0o755 });
      if (state !== 'missing') {
        writeFileSync(join(directory, 'gh'), `#!/bin/sh\nprintf '%s\\n' "$*" >> "$GH_CALL_LOG"\n[ "$*" = 'auth status' ] || exit 99\nexit ${state === 'authenticated' ? 0 : 1}\n`, { mode: 0o755 });
      }
      const result = spawnSync('/bin/sh', ['-c', preflight], {
        encoding: 'utf8', env: { PATH: directory, GH_CALL_LOG: log }, timeout: 5000,
      });
      assert.ifError(result.error);
      assert.equal(result.status, state === 'authenticated' ? 0 : 1);
      if (state === 'missing') assert.match(result.stderr, /gh is required/);
      else {
        assert.equal(readFileSync(log, 'utf8'), 'auth status\n');
        if (state === 'unauthenticated') assert.match(result.stderr, /gh auth login.*GH_TOKEN/);
      }
    } finally {
      rmSync(directory, { recursive: true, force: true });
    }
  });
}

for (const equal of [true, false]) {
  test(`installer parity check ${equal ? 'accepts identical bytes' : 'rejects drift'}`, () => {
    const directory = mkdtempSync(join(tmpdir(), 'satelle-parity-'));
    try {
      for (const path of ['scripts', 'website/scripts', 'website/public']) mkdirSync(join(directory, path), { recursive: true });
      writeFileSync(join(directory, 'scripts/install.sh'), '#!/bin/sh\n');
      writeFileSync(join(directory, 'website/public/install'), equal ? '#!/bin/sh\n' : '#!/bin/sh\n# drift\n');
      const check = join(directory, 'website/scripts/check-installer.mjs');
      writeFileSync(check, read('./check-installer.mjs'));
      const result = spawnSync(process.execPath, [check], { encoding: 'utf8', timeout: 5000 });
      assert.ifError(result.error);
      assert.equal(result.status, equal ? 0 : 1);
      if (!equal) assert.match(result.stderr, /Installer copies differ/);
    } finally {
      rmSync(directory, { recursive: true, force: true });
    }
  });
}
