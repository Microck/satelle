import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { createRequire } from 'node:module';
import { createHash } from 'node:crypto';
import test from 'node:test';
const require = createRequire(import.meta.url);
const ts = require('typescript');
const dir = new URL('../app/(landing)/demos/', import.meta.url);
const read = name => readFileSync(new URL(name, dir), 'utf8');
const compile = name => ts.transpileModule(read(name), { fileName:name, reportDiagnostics:true, compilerOptions:{target:ts.ScriptTarget.ES2022,module:ts.ModuleKind.ES2022,jsx:ts.JsxEmit.React} });
const compiled = compile('exploration-data.ts');
assert.equal(compiled.diagnostics?.length ?? 0, 0);
const data = await import(`data:text/javascript;base64,${Buffer.from(compiled.outputText).toString('base64')}`);
const { DEMOS, TIMELINES, CHAT_MESSAGES, duration, stepStart, sample, phase, messagePop, qaWidth, COMMIT_DELAY, POINTER_TRAVEL, DRAG_DURATION } = data;
const focus = read('landing-scenes.tsx'), gesture = read('workflow-gesture.tsx'), gallery = read('explorations.tsx');
for (const name of ['exploration-data.ts','workflow-gesture.tsx','landing-scenes.tsx','explorations.tsx']) {
  test(`${name}: TypeScript/JSX syntax`, () => assert.equal(compile(name).diagnostics?.length ?? 0, 0));
}
test('the actual landing component mounts the same four refined scenes', () => {
  assert.deepEqual(DEMOS.map(d => d.id), ['qa','chat','transfer','slack']);
  assert.match(gallery, /qa: ResponsiveQaScene, chat: SimpleChatScene, transfer: CompactTransferScene, slack: CompactSlackScene/);
  assert.match(gallery, /DEMOS.map/);
  assert.doesNotMatch(gallery, /from '.\/workflow-scenes'/);
});
test('QA is an explicitly seeded local storefront, not a real-site accusation', () => {
  assert.equal(data.SITES.qa, 'localhost:3000/storefront');
  assert.match(focus, /seeded QA fixture/);
  assert.match(focus, /purchase button leaves the viewport/);
  assert.doesNotMatch(focus, /Swag Labs|GitHub|Last Name is required|checkout-step/);
});
test('QA narrows, restores, then reproduces the same width', () => {
  const at = (step, local) => sample(TIMELINES.qa, stepStart(TIMELINES.qa, step) + local);
  assert.equal(qaWidth(at(1, 1000)),100);
  assert.equal(qaWidth(at(2, COMMIT_DELAY)),100);
  assert.equal(qaWidth(at(3, 1000)),64);
  assert.equal(qaWidth(at(4, COMMIT_DELAY + DRAG_DURATION)),100);
  assert.equal(qaWidth(at(6, 1000)),64);
  assert.ok(qaWidth(at(2, COMMIT_DELAY + DRAG_DURATION / 2)) < 100);
  assert.ok(qaWidth(at(2, COMMIT_DELAY + DRAG_DURATION / 2)) > 64);
});
test('resizing and cropping are press-drag-release gestures, not magic state swaps', () => {
  assert.deepEqual(TIMELINES.qa.filter(b => b.dragTo).map(b => [b.target,b.dragTo]), [['qa-resize','qa-narrow'],['qa-resize','qa-wide'],['qa-resize','qa-narrow']]);
  assert.equal(TIMELINES.slack[8].dragTo, 'slack-crop-end');
  assert.match(gesture, /frame.local >= COMMIT_DELAY/);
  assert.match(gesture, /end.x - hit.x/);
  assert.match(gesture, /data-dragging/);
});
test('chat sends complete message blocks, never typed fragments', () => {
  const chat = focus.slice(focus.indexOf('export function SimpleChatScene'),focus.indexOf('export function Clawd'));
  assert.match(chat, /CHAT_MESSAGES.filter/);
  assert.match(chat, /message.text/);
  assert.doesNotMatch(chat, /typed\(|opacity|fade/i);
  assert.equal(CHAT_MESSAGES[0].text,data.PROMPTS.hosts);
});
test('chat is a new PDF task, with running checks followed by completion', () => {
  assert.notEqual(data.PROMPTS.chat,data.PROMPTS.slack);
  assert.match(data.PROMPTS.chat,/launch-notes\.odt/);
  assert.doesNotMatch(data.PROMPTS.chat,/Slack/);
  assert.ok(CHAT_MESSAGES.some(m => m.role === 'user' && /How is it going/.test(m.text)));
  assert.ok(CHAT_MESSAGES.some(m => 'tool' in m && /status \+ logs.*running/.test(m.tool)));
  const last = CHAT_MESSAGES.at(-1);
  assert.equal(last.tool,'status · completed');
  assert.equal(last.file,data.BRIEF_FILE);
});
test('assistant popup geometry overshoots slightly without changing opacity', () => {
  const beat=1, offset=stepStart(TIMELINES.chat,beat);
  const early=messagePop(sample(TIMELINES.chat,offset+COMMIT_DELAY),beat);
  const settled=messagePop(sample(TIMELINES.chat,offset+COMMIT_DELAY+300),beat);
  assert.notDeepEqual(early,settled);
  assert.deepEqual(Object.keys(early),['transform']);
  assert.equal(settled.transform,'translateY(0px) scale(1)');
});
test('chat retains the simple frame, and resizes/scrolls safely', () => {
  assert.match(focus,/className="rf-composer"/);
  assert.match(focus,/ResizeObserver/);
  assert.match(focus,/componentWillUnmount/);
  assert.doesNotMatch(focus,/Search chats|Library|model picker|rf-gpt-side/);
});
test('chat completion is a Host path, not an invented downloadable attachment', () => {
  assert.match(gallery,/not a downloadable ChatGPT attachment/);
  assert.equal(data.CHAT_STATUS.fields.schema_version,'satelle.status.v2');
  assert.equal(data.CHAT_STATUS.fields.status,'completed');
  assert.equal(data.CHAT_STATUS.input.session_id,data.SESSION);
});
test('classic Clawd block cells retain their whitespace and are rendered crisply', () => {
  assert.equal(data.CLAWD,' ▐▛███▜▌\n▝▜█████▛▘\n  ▘▘ ▝▝');
  assert.match(focus,/shapeRendering="crispEdges"/);
  assert.match(focus,/CLAWD.split/);
  assert.match(focus,/quadrants\[glyph\]/);
});
test('terminal minimization follows a real cursor target and has no fade', () => {
  assert.equal(TIMELINES.transfer[2].target,'terminal-minimize');
  assert.match(focus,/data-cursor="terminal-minimize"/);
  assert.match(focus,/phase\(frame, 2, 900, COMMIT_DELAY\)/);
  const layer=focus.match(/<div className="rf-terminal-layer"[^\n]+/)?.[0];
  assert.ok(layer); assert.doesNotMatch(layer,/opacity/);
  assert.match(layer,/visibility.*hidden.*visible/);
  assert.equal(phase(sample(TIMELINES.transfer,stepStart(TIMELINES.transfer,2)+COMMIT_DELAY-1),2,900,COMMIT_DELAY),0);
});
test('every action and drag endpoint has a concrete DOM marker', () => {
  for (const beats of Object.values(TIMELINES)) for (const b of beats) {
    for (const id of [b.target,b.dragTo].filter(Boolean)) {
      assert.ok(focus.includes(`"${id}"`) || focus.includes(`'${id}'`),id);
    }
  }
});
test('pointer geometry is captured before the target disappears', () => {
  assert.match(gesture,/previous.frame.step !== this.props.frame.step/);
  assert.doesNotMatch(gesture,/frame.committed/);
  assert.match(gesture,/frame.step !== this.state.step \? this.last/);
  assert.match(gesture,/this.observer\?\.disconnect/);
});
test('every timeline gives the cursor time to reach its target', () => {
  assert.ok(POINTER_TRAVEL < COMMIT_DELAY);
  for (const beats of Object.values(TIMELINES)) {
    assert.ok(duration(beats) < 45000);
    assert.equal(sample(beats,duration(beats)).done,true);
    beats.forEach((beat,i) => {
      assert.ok(beat.ms > COMMIT_DELAY);
      if (beat.dragTo) assert.ok(beat.ms > COMMIT_DELAY + DRAG_DURATION);
      if (i) {
        const time=stepStart(beats,i);
        assert.equal(sample(beats,time+POINTER_TRAVEL).committed,i-1);
        assert.equal(sample(beats,time+COMMIT_DELAY).committed,i);
      }
    });
  }
});
test('the clock handles empty and invalid input', () => {
  assert.throws(()=>sample([],0),RangeError);
  for(const t of [-1,NaN,Infinity]) assert.equal(sample(TIMELINES.qa,t).elapsed,0);
});
test('Slack retains directory selection, crop, and both save operations', () => {
  assert.deepEqual(TIMELINES.slack.flatMap(b=>b.target?[b.target]:[]),['slack-account','slack-profile','slack-edit','slack-upload','slack-pictures','slack-file','slack-open','slack-crop','slack-crop-save','slack-save']);
  assert.match(focus,/Save Changes/);
  assert.match(focus,/pictures=\{c >= 5\}/);
});
test('dashboard and Drive are compact but preserve the file handoff', () => {
  assert.match(focus,/Google Analytics · last month/);
  assert.match(focus,/Google Drive · sample account/);
  assert.match(focus,/selected=\{c >= 9\}/);
  assert.match(focus,/Upload complete/);
  assert.doesNotMatch(focus,/Organic Search|Engagement|Monetization|Starred|Modified/);
});
test('new scenes use Satelle paint and never a grayscale filter', () => {
  assert.doesNotMatch(read('landing-scenes.css'),/#[0-9a-f]{3,8}\b|grayscale|hue-rotate/i);
  assert.doesNotMatch(focus+gesture,/(?:fill|stroke)=["']#/);
});
test('Host configuration and ChatGPT integration stay honestly scoped', () => {
  assert.deepEqual(data.HOST_CHECK.input,{all:true});
  assert.ok(data.HOST_CHECK.fields.not_checked.includes('native_computer_use'));
  assert.equal(data.CHATGPT_INTEGRATION.status,'concept');
  assert.match(gallery,/not an available Satelle integration/);
  assert.equal(data.CHAT_RUN.fields.status,'starting');
  assert.equal(data.CHAT_RUN.input.detach,true);
});
test('logo paths retain the pinned Simple Icons 15.0.0 source geometry', () => {
  const src=read('workflow-logos.tsx');
  const expected={chatgpt:'3fae9b38d571a5ab5aa662bc279dcda580855d6ca6b35330e4b4ba171367ffb1',slack:'69c3650cc9632f4edcf00bb5fd02792d5cb46d8af58f8db5001ba64cdd40da4b',drive:'583dfed4b5d2e771e6d1df51d78588feaa4e8f11db4bbd4e44fff7a369b061d8',analytics:'4697f13a7ce9c068abeb35c5d480e7f28f20c9404f48ba244115fe293773c9ac'};
  for(const [name,hash] of Object.entries(expected)) {
    const path=src.match(new RegExp(`  ${name}: '([^']+)'`))?.[1];
    assert.ok(path,name); assert.equal(createHash('sha256').update(path).digest('hex'),hash,name);
  }
});
test('no external operation is performed by a demo', () => {
  assert.doesNotMatch(focus+gesture+gallery,/\bfetch\s*\(|XMLHttpRequest|new WebSocket|execSync|window\.open|setInterval/);
});
