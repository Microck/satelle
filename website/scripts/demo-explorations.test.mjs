import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { createRequire } from 'node:module';
import test from 'node:test';

const require = createRequire(import.meta.url);
const ts = require('typescript');
const directory = new URL('../app/(landing)/demos/', import.meta.url);
function compile(file) {
  const source = readFileSync(new URL(file, directory), 'utf8');
  const { outputText, diagnostics } = ts.transpileModule(source, {
    reportDiagnostics: true,
    compilerOptions: { target: ts.ScriptTarget.ES2022, module: ts.ModuleKind.ES2022, jsx: ts.JsxEmit.React },
  });
  assert.equal(diagnostics?.length ?? 0, 0, `syntax: ${file}`);
  return outputText;
}
const data = await import(`data:text/javascript;base64,${Buffer.from(compile('exploration-data.ts')).toString('base64')}`);
const { DEMOS, TIMELINES, COMMIT_DELAY, POINTER_TRAVEL, duration, stepStart, sample, typed, HOST_CHECK, CHAT_RUN, TRANSFER_RUN, PROMPTS, SESSION } = data;
const scenes = readFileSync(new URL('workflow-scenes.tsx', directory), 'utf8');
const motion = readFileSync(new URL('workflow-motion.tsx', directory), 'utf8');
const gallery = readFileSync(new URL('explorations.tsx', directory), 'utf8');

test('exactly the four requested workflows, in order', () => {
  assert.deepEqual(DEMOS.map(d => d.id), ['qa', 'chat', 'transfer', 'wallpaper']);
  assert.equal(new Set(DEMOS.map(d => d.surface)).size, 4);
  assert.equal(DEMOS.filter(d => d.surface.includes('terminal')).length, 1);
});
test('every workflow has a finite multi-beat animation', () => {
  for (const demo of DEMOS) {
    const beats = TIMELINES[demo.id];
    assert.ok(beats.length >= 6);
    assert.ok(beats.every(b => Number.isFinite(b.ms) && b.ms > COMMIT_DELAY));
    assert.ok(duration(beats) < 25000);
  }
});
test('zero starts at the first frame', () => {
  for (const beats of Object.values(TIMELINES)) {
    const f = sample(beats, 0);
    assert.equal(f.step, 0); assert.equal(f.local, 0); assert.equal(f.done, false);
  }
});
test('final and excess time settle at a complete last frame, never loop', () => {
  for (const beats of Object.values(TIMELINES)) {
    for (const elapsed of [duration(beats), duration(beats) + 10000]) {
      const f = sample(beats, elapsed);
      assert.equal(f.step, beats.length - 1);
      assert.equal(f.done, true);
      assert.equal(f.committed, beats.length - 1);
    }
  }
});
test('invalid clock inputs are bounded', () => {
  for (const elapsed of [-1, NaN, Infinity, -Infinity]) assert.equal(sample(TIMELINES.qa, elapsed).elapsed, 0);
});
test('step boundaries project into the next beat', () => {
  for (const beats of Object.values(TIMELINES)) for (let i = 1; i < beats.length; i++) {
    const f = sample(beats, stepStart(beats, i));
    assert.equal(f.step, i); assert.equal(f.local, 0);
  }
});
test('the pointer arrives before an application action commits', () => {
  assert.ok(POINTER_TRAVEL < COMMIT_DELAY);
  for (const beats of Object.values(TIMELINES)) for (let i = 1; i < beats.length; i++) {
    const at = stepStart(beats, i);
    assert.equal(sample(beats, at + POINTER_TRAVEL).pointer, 1);
    assert.equal(sample(beats, at + COMMIT_DELAY - 1).committed, i - 1);
    assert.equal(sample(beats, at + COMMIT_DELAY).committed, i);
  }
});
test('manual stepping exposes the completed contents of each beat', () => {
  for (const beats of Object.values(TIMELINES)) beats.forEach((b, i) => {
    assert.equal(sample(beats, stepStart(beats, i) + b.ms - 1).committed, i);
  });
});
test('human text reveals progressively and remains complete afterward', () => {
  const text = 'hello world';
  assert.equal(typed(text, sample(TIMELINES.chat, 0), 0, 1000), '');
  assert.equal(typed(text, sample(TIMELINES.chat, 500), 0, 1000), 'hello');
  assert.equal(typed(text, sample(TIMELINES.chat, 1000), 0, 1000), text);
  assert.equal(typed(text, sample(TIMELINES.chat, 1000), 3), '');
  assert.equal(typed(text, sample(TIMELINES.chat, duration(TIMELINES.chat)), 3), text);
});
test('every cursor target has a corresponding rendered marker', () => {
  for (const beats of Object.values(TIMELINES)) for (const beat of beats) {
    if (beat.target) assert.ok(scenes.includes(`data-cursor="${beat.target}"`), beat.target);
  }
});
test('Host inventory is configuration, not a invented discovery endpoint', () => {
  assert.deepEqual(HOST_CHECK.input, { all: true });
  assert.equal(HOST_CHECK.fields.schema_version, 'satelle.config.check.v1');
  assert.deepEqual(HOST_CHECK.fields.checked_contexts.map(c => c.host), ['studio-mac', 'ops-pc']);
  assert.ok(HOST_CHECK.fields.not_checked.includes('native_computer_use'));
  assert.ok(HOST_CHECK.fields.not_checked.includes('remote_host'));
  assert.ok(!scenes.includes('list_hosts'));
});
test('desktop chat asks about Hosts before requesting a specific task', () => {
  assert.equal(PROMPTS.hosts, 'Which hosts are available?');
  assert.ok(PROMPTS.chat.includes('studio-mac'));
  assert.equal(CHAT_RUN.input.prompt, PROMPTS.chat);
});
test('mutation examples use real run arguments and detached admission', () => {
  for (const run of [CHAT_RUN, TRANSFER_RUN]) {
    assert.equal(run.input.detach, true);
    assert.deepEqual(Object.keys(run.input).sort(), ['detach', 'host', 'prompt']);
    assert.equal(run.fields.schema_version, 'satelle.run.v2');
    assert.equal(run.fields.status, 'starting');
  }
});
test('Session identifier is a well-formed UUIDv7 example', () => {
  assert.match(SESSION, /^rs_[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/);
});
test('transfer prompt names the computer, source, file, and destination', () => {
  for (const part of ['ops-pc', 'reports.example', 'September.csv', 'files.example / Finance']) assert.ok(PROMPTS.transfer.includes(part));
  assert.equal(TRANSFER_RUN.input.prompt, PROMPTS.transfer);
  assert.equal(TRANSFER_RUN.input.host, 'ops-pc');
});
test('file flow has explicit download, native selection, upload, and confirmation beats', () => {
  const labels = TIMELINES.transfer.map(b => b.label).join('\n');
  assert.match(labels, /Download September.csv[\s\S]*Open the file picker[\s\S]*Select the downloaded file[\s\S]*Upload to Finance[\s\S]*Confirm/);
});
test('QA is synthetic functional testing that stops before a purchase', () => {
  assert.ok(PROMPTS.qa.includes('Do not place an order'));
  assert.ok(scenes.includes('Test stops before placing an order.'));
  assert.ok(scenes.includes('EXAMPLE QA NOTES'));
});
test('wallpaper scenario uses native Settings and a visible desktop change', () => {
  assert.match(scenes, /System Settings/);
  assert.match(scenes, /sw-new-wallpaper/);
  assert.ok(PROMPTS.wallpaper.includes('studio-mac'));
  assert.match(TIMELINES.wallpaper[3].label, /mountain/);
});
test('clock suspends when offscreen or the document is hidden, and cleans up', () => {
  for (const token of ['IntersectionObserver', 'visibilitychange', '!document.hidden', 'cancelAnimationFrame', 'componentWillUnmount', 'removeEventListener']) assert.ok(motion.includes(token));
});
test('reduced motion starts at the final frame and has an explicit still-frame notice', () => {
  assert.ok(motion.includes('prefers-reduced-motion: reduce'));
  assert.ok(motion.includes('reduced ? duration(TIMELINES[this.props.id]) : 0'));
  assert.ok(motion.includes('Reduced motion: still frames.'));
});
test('both routes use all four and no longer show the obsolete six-option picker', () => {
  assert.ok(gallery.includes('DEMOS.map'));
  assert.ok(!gallery.includes('parseSelection'));
  assert.ok(!gallery.includes('Show all 6'));
});
test('all CTAs remain in the existing docs tree', () => {
  for (const d of DEMOS) assert.match(d.href, /^\/docs\//);
});
test('source files transpile without syntax errors', () => {
  for (const file of ['explorations.tsx', 'workflow-motion.tsx', 'workflow-scenes.tsx']) compile(file);
});
