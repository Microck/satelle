import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { createRequire } from 'node:module';
import { createHash } from 'node:crypto';
import test from 'node:test';
const require = createRequire(import.meta.url);
const ts = require('typescript');
const dir = new URL('../app/(landing)/demos/', import.meta.url);
const read = name => readFileSync(new URL(name, dir), 'utf8');
const compile = name => ts.transpileModule(read(name), { fileName: name, reportDiagnostics: true, compilerOptions: { target: ts.ScriptTarget.ES2022, module: ts.ModuleKind.ES2022, jsx: ts.JsxEmit.React } });
const compiled = compile('exploration-data.ts');
assert.equal(compiled.diagnostics?.length ?? 0, 0);
const data = await import(`data:text/javascript;base64,${Buffer.from(compiled.outputText).toString('base64')}`);
const { DEMOS, TIMELINES, CHAT_MESSAGES, MCP_ACTIVITIES, duration, stepStart, sample, phase, messagePop, qaWidth, gesturePhase, terminalMinimize, COMMIT_DELAY, POINTER_TRAVEL, POINTER_PRESS, POINTER_RELEASE, POINTER_LINGER, DRAG_DURATION, MINIMIZE_DURATION } = data;
const scenes = read('landing-scenes.tsx'), gesture = read('workflow-gesture.tsx'), gallery = read('explorations.tsx'), player = read('workflow-motion.tsx'), polish = read('landing-polish.css');
const at = (id, step, local) => sample(TIMELINES[id], stepStart(TIMELINES[id], step) + local);
for (const name of ['exploration-data.ts', 'workflow-motion.tsx', 'workflow-gesture.tsx', 'landing-scenes.tsx', 'explorations.tsx']) {
  test(`${name}: TypeScript/JSX syntax`, () => assert.equal(compile(name).diagnostics?.length ?? 0, 0));
}
test('the landing gallery mounts exactly four shared scenes', () => {
  assert.deepEqual(DEMOS.map(d => d.id), ['qa', 'chat', 'transfer', 'slack']);
  for (const component of ['ResponsiveQaScene', 'SimpleChatScene', 'CompactTransferScene', 'CompactSlackScene']) assert.ok(gallery.includes(component));
  assert.ok(gallery.includes('DEMOS.map'));
});
test('headings describe reusable capabilities', () => {
  assert.deepEqual(DEMOS.map(d => d.title), ['Test the experience, end to end.', 'Talk to your computers.', 'Give your coding agent a computer.', 'Skip the repetitive clicks.']);
});
test('no playback footer or step bars are mounted', () => {
  assert.doesNotMatch(player, /className="sw-playback|className="sw-steps/);
  assert.match(player, /className="sw-controls"/);
});
test('captions and the grid footnote have moved out of the cards', () => {
  assert.doesNotMatch(gallery, /className="sw-notes|className="sx-footnote/);
  assert.doesNotMatch(scenes, /rf-fixture-caption/);
  assert.match(gallery, /About these illustrations and connection requirements/);
});
test('playback is still keyboard accessible and discoverable on touch', () => {
  assert.match(player, /aria-label=.*Pause.*Play/);
  assert.match(player, /Replay.*demo/);
  assert.match(polish, /focus-within/);
  assert.match(polish, /hover:none/);
  assert.match(player, /sw-a11y-status/);
});
test('QA remains a seeded local storefront', () => {
  assert.equal(data.SITES.qa, 'localhost:3000/storefront');
  assert.match(scenes, /seeded-responsive-storefront/);
  assert.doesNotMatch(scenes, /GitHub|checkout-step/);
});
test('QA drag narrows, restores, and reproduces the same viewport', () => {
  assert.equal(qaWidth(at('qa', 1, 1000)), 100);
  assert.equal(qaWidth(at('qa', 2, COMMIT_DELAY)), 100);
  assert.equal(qaWidth(at('qa', 3, 1000)), 64);
  assert.equal(qaWidth(at('qa', 4, COMMIT_DELAY + DRAG_DURATION)), 100);
  assert.equal(qaWidth(at('qa', 6, 1000)), 64);
  assert.ok(qaWidth(at('qa', 2, COMMIT_DELAY + DRAG_DURATION / 2)) > 64);
});
test('chat sends complete messages and never types fragments', () => {
  const chat = scenes.slice(scenes.indexOf('export function SimpleChatScene'), scenes.indexOf('export function Clawd'));
  assert.match(chat, /CHAT_MESSAGES.filter/);
  assert.match(chat, /message.text/);
  assert.doesNotMatch(chat, /typed\(|opacity|fade/i);
});
test('the chat task is distinct and continues through progress to completion', () => {
  assert.match(data.PROMPTS.chat, /launch-notes\.odt/);
  assert.doesNotMatch(data.PROMPTS.chat, /Slack/);
  assert.ok(CHAT_MESSAGES.some(m => /How is it going/.test(m.text)));
  assert.equal(CHAT_MESSAGES.at(-1).file, data.BRIEF_FILE);
  assert.equal(CHAT_MESSAGES.at(-1).tool, 'status · completed');
});
test('assistant popup changes geometry rather than opacity', () => {
  const early = messagePop(at('chat', 1, COMMIT_DELAY), 1);
  const settled = messagePop(at('chat', 1, COMMIT_DELAY + 300), 1);
  assert.notDeepEqual(early, settled);
  assert.deepEqual(Object.keys(early), ['transform']);
  assert.equal(settled.transform, 'translateY(0px) scale(1)');
});
test('MCP cards preserve the real tool names and corresponding state', () => {
  assert.deepEqual(Object.keys(MCP_ACTIVITIES), ['1', '3', '5', '7', '8']);
  assert.deepEqual(MCP_ACTIVITIES[5].tools, ['status', 'logs']);
  assert.equal(MCP_ACTIVITIES[8].state, 'completed');
  assert.match(scenes, /rf-mcp-activity/);
  assert.match(scenes, /rf-mcp-tools/);
});
test('MCP cards reuse the actual Satelle mark', () => {
  assert.match(scenes, /from ['"]\.\.\/mark['"]/);
  assert.match(scenes, /Mark size=\{21\}/);
  assert.match(polish, /--sa-accent:var\(--sa-11\)/);
});
test('running indicators are driven by the same pausable clock', () => {
  assert.match(scenes, /frame.elapsed - data.COMMIT_DELAY/);
  assert.match(scenes, /frame.committed === step/);
  assert.doesNotMatch(polish, /animation:.*infinite/);
});
test('the final file is a Host-local result, not a downloadable attachment', () => {
  assert.match(gallery, /not a downloadable ChatGPT attachment/);
  assert.equal(data.CHAT_STATUS.fields.status, 'completed');
  assert.equal(data.CHAT_STATUS.input.session_id, data.SESSION);
});
test('classic Clawd block geometry is retained', () => {
  assert.equal(data.CLAWD, ' ▐▛███▜▌\n▝▜█████▛▘\n  ▘▘ ▝▝');
  assert.match(scenes, /shapeRendering="crispEdges"/);
  assert.match(scenes, /quadrants\[glyph\]/);
});
test('terminal minimization finishes in 320ms, only after the click', () => {
  assert.equal(MINIMIZE_DURATION, 320);
  assert.equal(TIMELINES.transfer[2].target, 'terminal-minimize');
  assert.equal(terminalMinimize(at('transfer', 2, COMMIT_DELAY - 1)), 0);
  assert.ok(terminalMinimize(at('transfer', 2, COMMIT_DELAY + 160)) > 0);
  assert.equal(terminalMinimize(at('transfer', 2, COMMIT_DELAY + MINIMIZE_DURATION)), 1);
});
test('terminal collapses into the full bottom-left without fading or a taskbar', () => {
  const transfer = scenes.slice(scenes.indexOf('export function CompactTransferScene'), scenes.indexOf('function Profile'));
  assert.match(transfer, /terminalMinimize\(frame\)/);
  assert.match(transfer, /scale\(\$\{1 - minimize\}\)/);
  assert.doesNotMatch(transfer, /opacity|rf-taskbar/);
  assert.match(polish, /transform-origin:left bottom/);
  assert.match(polish, /\.rf-host-browser,\.sa \.rf-terminal-layer \{inset:0;\}/);
});
test('pointer reaches its target before pressing and committing', () => {
  assert.ok(POINTER_TRAVEL < POINTER_PRESS && POINTER_PRESS < COMMIT_DELAY);
  for (const [id, beats] of Object.entries(TIMELINES)) beats.forEach((beat, step) => {
    if (!beat.target) return;
    assert.equal(gesturePhase(at(id, step, POINTER_TRAVEL)).pressed, false);
    assert.equal(gesturePhase(at(id, step, POINTER_PRESS)).pressed, true);
    assert.equal(at(id, step, POINTER_PRESS).committed, step - 1);
  });
});
test('click releases, briefly lingers, then hides during the result hold', () => {
  for (const [id, beats] of Object.entries(TIMELINES)) beats.forEach((beat, step) => {
    if (!beat.target || beat.dragTo) return;
    const release = COMMIT_DELAY + POINTER_RELEASE;
    assert.equal(gesturePhase(at(id, step, release)).pressed, false);
    assert.equal(gesturePhase(at(id, step, release)).visible, true);
    assert.equal(gesturePhase(at(id, step, release + POINTER_LINGER)).visible, false);
  });
});
test('drag holds down for the shared drag duration then releases', () => {
  for (const [id, beats] of Object.entries(TIMELINES)) beats.forEach((beat, step) => {
    if (!beat.dragTo) return;
    assert.equal(gesturePhase(at(id, step, COMMIT_DELAY)).dragging, true);
    assert.equal(gesturePhase(at(id, step, COMMIT_DELAY + DRAG_DURATION - 1)).pressed, true);
    assert.equal(gesturePhase(at(id, step, COMMIT_DELAY + DRAG_DURATION)).pressed, false);
  });
});
test('typing, chat and finished-result beats never display a cursor', () => {
  for (const [id, beats] of Object.entries(TIMELINES)) {
    beats.forEach((beat, step) => { if (!beat.target) assert.equal(gesturePhase(at(id, step, 1000)).visible, false); });
    assert.equal(gesturePhase(sample(beats, duration(beats))).visible, false);
  }
});
test('missing, clipped or hidden targets cannot leave a stale cursor', () => {
  assert.match(gesture, /measured: false/);
  assert.match(gesture, /style.visibility === 'hidden'/);
  assert.match(gesture, /Number\(style.opacity\) === 0/);
  assert.match(gesture, /frame.step === this.state.step/);
  assert.match(gesture, /data-visible=\{visible\}/);
});
test('click geometry is captured before the UI removes a target', () => {
  assert.match(gesture, /frame.local >= data.COMMIT_DELAY/);
  assert.match(gesture, /previous.frame.step !== this.props.frame.step/);
  assert.match(gesture, /frame.step !== this.state.step \? this.last/);
  assert.match(gesture, /this.observer\?\.disconnect/);
});
test('every gesture endpoint has a corresponding rendered marker', () => {
  for (const beats of Object.values(TIMELINES)) for (const beat of beats) {
    for (const id of [beat.target, beat.dragTo].filter(Boolean)) assert.ok(scenes.includes(`"${id}"`) || scenes.includes(`'${id}'`), id);
  }
});
test('the clock rejects empty input and clamps invalid values', () => {
  assert.throws(() => sample([], 0), RangeError);
  for (const value of [-1, NaN, Infinity]) assert.equal(sample(TIMELINES.qa, value).elapsed, 0);
  for (const beats of Object.values(TIMELINES)) assert.equal(sample(beats, duration(beats) + 100).done, true);
});
test('offscreen suspension, explicit reduced-motion playback and cleanup remain', () => {
  for (const token of ['IntersectionObserver', '!document.hidden', 'optedIn', 'LOOP_HOLD', 'componentWillUnmount', 'cancelAnimationFrame']) assert.ok(player.includes(token));
});
test('Slack retains directory selection, cropping and both saves', () => {
  assert.deepEqual(TIMELINES.slack.flatMap(b => b.target ? [b.target] : []), ['slack-account', 'slack-profile', 'slack-edit', 'slack-upload', 'slack-pictures', 'slack-file', 'slack-open', 'slack-crop', 'slack-crop-save', 'slack-save']);
  assert.match(scenes, /Save Changes/);
});
test('Drive retains the same-Host file handoff', () => {
  assert.match(data.PROMPTS.transfer, /Google Analytics.*Google Drive/);
  assert.match(scenes, /selected=\{c >= 9\}/);
  assert.match(scenes, /Upload complete/);
});
test('monochrome logos preserve their sourced geometry and new paint uses tokens', () => {
  const expected = { chatgpt: '3fae9b38d571a5ab5aa662bc279dcda580855d6ca6b35330e4b4ba171367ffb1', slack: '69c3650cc9632f4edcf00bb5fd02792d5cb46d8af58f8db5001ba64cdd40da4b', drive: '583dfed4b5d2e771e6d1df51d78588feaa4e8f11db4bbd4e44fff7a369b061d8', analytics: '4697f13a7ce9c068abeb35c5d480e7f28f20c9404f48ba244115fe293773c9ac' };
  for (const [name, hash] of Object.entries(expected)) {
    const path = read('workflow-logos.tsx').match(new RegExp(`\\b${name}: '([^']+)'`))?.[1];
    assert.ok(path, name); assert.equal(createHash('sha256').update(path).digest('hex'), hash, name);
  }
  assert.doesNotMatch(polish, /#[0-9a-f]{3,8}\b|grayscale|hue-rotate/i);
});
test('scope stays illustrative with no live operations or invented integration', () => {
  assert.equal(data.CHATGPT_INTEGRATION.status, 'concept');
  assert.match(gallery, /not an available Satelle integration/);
  assert.equal(data.CHAT_RUN.fields.status, 'starting');
  assert.ok(data.HOST_CHECK.fields.not_checked.includes('native_computer_use'));
  assert.doesNotMatch(scenes + gesture + gallery, /\bfetch\s*\(|XMLHttpRequest|new WebSocket|execSync|window\.open|setInterval/);
});
