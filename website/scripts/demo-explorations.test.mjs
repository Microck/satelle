import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { createRequire } from 'node:module';
import test from 'node:test';

const require = createRequire(import.meta.url);
const ts = require('typescript');
const directory = new URL('../app/(landing)/demos/', import.meta.url);
const read = (name) => readFileSync(new URL(name, directory), 'utf8');
const source = read('exploration-data.ts');
const compile = (source, fileName) => ts.transpileModule(source, {
  fileName, reportDiagnostics: true,
  compilerOptions: { target: ts.ScriptTarget.ES2022, module: ts.ModuleKind.ES2022, jsx: ts.JsxEmit.React },
});
const compiled = compile(source, 'exploration-data.ts');
assert.equal(compiled.diagnostics?.length ?? 0, 0);
const data = await import(`data:text/javascript;base64,${Buffer.from(compiled.outputText).toString('base64')}`);
const { DEMOS, TIMELINES, duration, sample, phase, typed, COMMIT_DELAY, POINTER_TRAVEL } = data;
const ui = read('workflow-ui.tsx');
const scenes = read('workflow-scenes.tsx');
const motion = read('workflow-motion.tsx');
const gallery = read('explorations.tsx');
const css = read('explorations.css');

// Syntax validation is not a full Next.js / React type-check. CI still owns that build.
for (const file of ['workflow-ui.tsx', 'workflow-scenes.tsx', 'workflow-motion.tsx', 'explorations.tsx']) {
  test(`${file} transpiles without syntax errors`, () => {
    assert.equal(compile(read(file), file).diagnostics?.length ?? 0, 0);
  });
}
test('the four requested workflows have a stable order and distinct surfaces', () => {
  assert.deepEqual(DEMOS.map(d => d.id), ['qa', 'chat', 'transfer', 'slack']);
  assert.equal(new Set(DEMOS.map(d => d.surface)).size, 4);
  assert.deepEqual(Object.keys(TIMELINES), DEMOS.map(d => d.id));
});
test('real service domains replace placeholder sites', () => {
  assert.match(data.SITES.qa, /^github\.com\/Microck\/satelle$/);
  assert.match(data.SITES.analytics, /^analytics\.google\.com\//);
  assert.match(data.SITES.drive, /^drive\.google\.com\//);
  assert.equal(data.SITES.slack, 'slack.com');
  assert.doesNotMatch(source + scenes, /(?:shop|reports|files)\.example|example\.com/);
});
test('every script is finite and every action allows pointer travel before commit', () => {
  assert.ok(POINTER_TRAVEL < COMMIT_DELAY);
  for (const beats of Object.values(TIMELINES)) {
    assert.ok(beats.length > 1);
    assert.ok(beats.every(b => Number.isFinite(b.ms) && b.ms > COMMIT_DELAY));
    assert.ok(duration(beats) < 60_000);
    assert.equal(sample(beats, duration(beats)).done, true);
    assert.equal(sample(beats, duration(beats) * 2).elapsed, duration(beats));
  }
});
test('clock projections clamp invalid times and reject empty scripts', () => {
  for (const t of [NaN, Infinity, -4]) assert.equal(sample(TIMELINES.qa, t).elapsed, 0);
  assert.throws(() => sample([], 0), RangeError);
});
test('cursor reaches each actionable target before its application change', () => {
  for (const beats of Object.values(TIMELINES)) for (let index = 1; index < beats.length; index++) {
    const start = data.stepStart(beats, index);
    const before = sample(beats, start + POINTER_TRAVEL);
    assert.equal(before.pointer, 1);
    assert.equal(before.committed, index - 1);
    assert.equal(sample(beats, start + COMMIT_DELAY).committed, index);
  }
});
test('human text types progressively then remains complete', () => {
  const text = data.PROMPTS.transfer;
  assert.equal(typed(text, sample(TIMELINES.transfer, 0), 0), '');
  assert.ok(typed(text, sample(TIMELINES.transfer, 900), 0).length < text.length);
  assert.equal(typed(text, sample(TIMELINES.transfer, 1800), 0), text);
  assert.equal(typed(text, sample(TIMELINES.transfer, 6000), 0), text);
});
test('window handoff and crop interpolation follow the finite clock', () => {
  assert.equal(phase(sample(TIMELINES.transfer, 0), 2), 0);
  assert.equal(phase(sample(TIMELINES.transfer, duration(TIMELINES.transfer)), 2), 1);
  assert.match(scenes, /phase\(frame, 2, 1100\)/);
  assert.match(scenes, /phase\(frame, 8, 1000, data.COMMIT_DELAY\)/);
});
test('no segmented step bars, step rail, or obsolete help text survive', () => {
  assert.doesNotMatch(motion + css, /sw-steps|animation steps|Use the steps to explore|Show .* step /);
  assert.match(motion, /Replay/);
  assert.match(motion, /Next frame/);
});
test('all application paint is inherited from the landing theme, not vendor hex colors', () => {
  assert.doesNotMatch(css, /#[0-9a-f]{3,8}\b/i);
  assert.doesNotMatch(ui + scenes + motion, /(?:fill|stroke)=["']#[0-9a-f]/i);
  assert.doesNotMatch(ui, /#[0-9a-f]{3,8}\b/i);
  assert.doesNotMatch(css, /filter\s*:\s*(?:grayscale|hue-rotate)/);
  assert.doesNotMatch(css, /var\(--(?:google|slack|gpt|claude)-/);
  assert.match(css, /background: var\(--sa-5\)/);
});
test('branding is represented by monochrome shapes, not raster assets', () => {
  assert.match(ui, /name === 'slack'/);
  assert.match(ui, /fill="currentColor"/);
  assert.doesNotMatch(ui + scenes, /<img\b|<iframe\b|https?:\/\/.*\.(?:png|svg|jpe?g)/);
});
test('Host rows mean configured contexts, not discovered or confirmed-ready machines', () => {
  assert.deepEqual(data.HOST_CHECK.input, { all: true });
  assert.equal(data.HOST_CHECK.fields.schema_version, 'satelle.config.check.v1');
  assert.deepEqual(data.HOST_CHECK.fields.not_checked, ['remote_host', 'provider_auth', 'native_computer_use']);
  assert.doesNotMatch(source + scenes, /hosts_list|discover_hosts|list_hosts/);
  assert.match(scenes, /Configured/);
});
test('ChatGPT is visibly a concept, with no nonexistent installer command', () => {
  assert.equal(data.CHATGPT_INTEGRATION.status, 'concept');
  assert.match(scenes, /Integration concept/);
  assert.match(gallery, /not an available Satelle integration/);
  assert.doesNotMatch(source + scenes + gallery, /mcp install.*chatgpt/);
});
test('ChatGPT task submission remains hypothetical and detached', () => {
  assert.equal(data.CHAT_RUN.input.detach, true);
  assert.equal(data.CHAT_RUN.input.host, 'studio-mac');
  assert.equal(data.CHAT_RUN.fields.status, 'starting');
  assert.match(data.PROMPTS.chat, /Slack profile picture/);
});
test('Claude Code uses the recognizable prompt and tool transcript, not a checklist app', () => {
  assert.match(scenes, /▐▛███▜▌/);
  assert.match(scenes, /satelle - run \(MCP\)/);
  assert.match(scenes, /esc to interrupt/);
  assert.match(scenes, /wf-terminal-layer/);
  assert.match(scenes, /wf-minimized-terminal/);
});
test('file export and upload share one Host and one filename', () => {
  assert.equal(data.TRANSFER_RUN.input.host, 'ops-pc');
  assert.equal(data.TRANSFER_RUN.input.detach, true);
  assert.match(data.PROMPTS.transfer, /Google Analytics/);
  assert.match(data.PROMPTS.transfer, /Google Drive/);
  assert.equal(data.REPORT_FILE, 'Traffic acquisition.csv');
  const targets = TIMELINES.transfer.map(b => b.target).filter(Boolean);
  assert.deepEqual(targets, ['ga-report','ga-share','ga-download','ga-csv','drive-tab','drive-folder','drive-new','drive-upload','transfer-file','transfer-open']);
});
test('Slack profile navigation includes picker, crop, and both save actions', () => {
  assert.equal(data.PHOTO_FILE, 'profile.png');
  const targets = TIMELINES.slack.map(b => b.target).filter(Boolean);
  assert.deepEqual(targets, ['slack-account','slack-profile','slack-edit','slack-upload','slack-pictures','slack-file','slack-open','slack-crop','slack-crop-save','slack-save']);
  assert.match(scenes, /Save Changes/);
  assert.doesNotMatch(source + scenes, /WallpaperScene|change the wallpaper|mountain landscape/);
});
test('example identifiers remain valid, without personal account details', () => {
  assert.match(data.SESSION, /^rs_[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/);
  assert.doesNotMatch(scenes, /Sara Parras|555 0123|checkout\.js:421/);
});
test('QA is read-only and does not invent a security finding on GitHub', () => {
  assert.match(data.PROMPTS.qa, /Do not submit anything/);
  assert.match(scenes, /Scripted example/);
  assert.doesNotMatch(scenes, /Critical|invalid email|security vulnerability/);
});
test('playback suspends offscreen, honors reduced motion, and cleans up', () => {
  for (const term of ['IntersectionObserver','document.hidden','prefers-reduced-motion','cancelAnimationFrame','disconnect()','removeEventListener']) assert.ok(motion.includes(term));
  assert.match(motion, /private paused = false/);
  assert.doesNotMatch(motion, /setInterval|setTimeout/);
});
test('illustrative scenes do not invoke the apps, a Host, or a shell', () => {
  assert.doesNotMatch(source + scenes + ui + motion, /\bfetch\s*\(|XMLHttpRequest|WebSocket\s*\(|child_process|execSync|window\.open/);
});
test('Claude Code retains the website monospace operator typography', () => {
  assert.match(css, /\.wf-claude-window\s*\{\s*font-family:\s*var\(--font-mono/);
});

