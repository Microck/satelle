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
const { TIMELINES, duration, stepStart, sample, gesturePhase, COMMIT_DELAY, POINTER_TRAVEL, POINTER_PRESS, POINTER_RELEASE, POINTER_LINGER, DRAG_DURATION } = data;
const gesture = read('workflow-gesture.tsx'), player = read('workflow-motion.tsx'), polish = read('landing-polish.css');
const control = readFileSync(new URL('../app/(landing)/demos/control.tsx', import.meta.url), 'utf8');
const controlCss = readFileSync(new URL('../app/(landing)/demos/control.css', import.meta.url), 'utf8');
const at = (id, step, local) => sample(TIMELINES[id], stepStart(TIMELINES[id], step) + local);
for (const file of ['exploration-data.ts', 'workflow-motion.tsx', 'workflow-gesture.tsx']) {
  test(`${file}: TypeScript/JSX syntax`, () => assert.equal(compile(file).diagnostics?.length ?? 0, 0));
}
test('the same four generic capability headings and workflows remain', () => {
  assert.deepEqual(data.DEMOS.map(d => d.id), ['qa','chat','transfer','slack']);
  assert.deepEqual(data.DEMOS.map(d => d.title), ['Test the experience, end to end.','Talk to your computers.','Give your coding agent a computer.','Skip the repetitive clicks.']);
});
test('the QA instruction strip does not participate in the visible layout', () => {
  assert.match(polish, /\.rf-qa\s*>\s*\.rf-request\s*\{display:none;\}/);
  assert.equal(data.SITES.qa, 'localhost:3000/storefront');
});
test('no top-right playback buttons, footer, status strip or step bars are rendered', () => {
  assert.doesNotMatch(player, /<button|className="sw-controls"|className="sw-playback|className="sw-steps/);
  assert.doesNotMatch(polish, /\.sw-controls/);
});
test('chrome-free playback remains keyboard and touch operable', () => {
  assert.match(player, /role="button" tabIndex=\{0\}/);
  assert.match(player, /onClick=\{this.toggle\}/);
  assert.match(player, /aria-keyshortcuts="Space Enter R"/);
  assert.match(player, /event\.key === ' '/);
  assert.match(player, /event\.key === 'Enter'/);
  assert.match(player, /event\.key\.toLowerCase\(\) === 'r'/);
  assert.match(player, /event\.repeat/);
  assert.match(polish, /\.sw-player:focus-visible/);
});
test('the animation clock runs at exactly 1.25x, once, centrally', () => {
  assert.equal(data.PLAYBACK_RATE, 1.25);
  assert.equal(data.playbackDelta(16),20);
  assert.equal(data.playbackDelta(80),100);
  assert.equal(data.playbackDelta(100),125);
  assert.match(player, /data\.playbackDelta\(now - this.previous\)/);
});
test('invalid or stalled clock deltas cannot jump through an action', () => {
  for (const n of [NaN, Infinity, -Infinity, -1]) assert.equal(data.playbackDelta(n),0);
  assert.equal(data.playbackDelta(10000),125);
});
test('frame neighborhoods explicitly carry consecutive target continuity', () => {
  for (const [id, beats] of Object.entries(TIMELINES)) beats.forEach((beat, step) => {
    const frame=at(id,step,0);
    assert.equal(frame.previousTarget,beats[step-1]?.target);
    assert.equal(frame.nextTarget,beats[step+1]?.target);
  });
});
test('cursor stays visible through release and the gap before a consecutive click', () => {
  for (const [id, beats] of Object.entries(TIMELINES)) beats.forEach((beat, step) => {
    if (!beat.target || !beats[step+1]?.target) return;
    const release=COMMIT_DELAY+(beat.dragTo?DRAG_DURATION:POINTER_RELEASE);
    for (const local of [release,release+POINTER_LINGER,beat.ms-1]) {
      const timing=gesturePhase(at(id,step,local));
      assert.equal(timing.visible,true,`${id}/${step}/${local}: no blink`);
      assert.equal(timing.pressed,false,`${id}/${step}/${local}: release the click`);
    }
    assert.equal(gesturePhase(at(id,step+1,0)).visible,true);
  });
});
test('end of an action sequence hides once, not between every action', () => {
  for (const [id, beats] of Object.entries(TIMELINES)) beats.forEach((beat, step) => {
    if (!beat.target || beats[step+1]?.target) return;
    const release=COMMIT_DELAY+(beat.dragTo?DRAG_DURATION:POINTER_RELEASE);
    assert.equal(gesturePhase(at(id,step,release)).visible,true);
    assert.equal(gesturePhase(at(id,step,release+POINTER_LINGER)).visible,false);
  });
});
test('typing, chat, result holds and completed loops never show stray cursors', () => {
  for (const [id, beats] of Object.entries(TIMELINES)) {
    beats.forEach((beat,step)=>{if(!beat.target) for(const local of [0,500,beat.ms-1]) assert.equal(gesturePhase(at(id,step,local)).visible,false);});
    assert.equal(gesturePhase(sample(beats,duration(beats))).visible,false);
  }
});
test('arrival precedes press, and press precedes action commit', () => {
  assert.ok(POINTER_TRAVEL<POINTER_PRESS && POINTER_PRESS<COMMIT_DELAY);
  for(const [id,beats] of Object.entries(TIMELINES)) beats.forEach((beat,step)=>{
    if(!beat.target)return;
    assert.equal(gesturePhase(at(id,step,POINTER_TRAVEL)).pressed,false);
    assert.equal(gesturePhase(at(id,step,POINTER_PRESS)).pressed,true);
    if(step) assert.equal(at(id,step,POINTER_PRESS).committed,step-1);
    assert.equal(at(id,step,COMMIT_DELAY).committed,step);
  });
});
test('drag stays pressed for its complete shared duration then releases', () => {
  for(const [id,beats] of Object.entries(TIMELINES)) beats.forEach((beat,step)=>{
    if(!beat.dragTo)return;
    assert.equal(gesturePhase(at(id,step,COMMIT_DELAY)).dragging,true);
    assert.equal(gesturePhase(at(id,step,COMMIT_DELAY+DRAG_DURATION-1)).pressed,true);
    assert.equal(gesturePhase(at(id,step,COMMIT_DELAY+DRAG_DURATION)).pressed,false);
  });
});
test('the pointer can bridge the render that captures its next target', () => {
  assert.match(gesture, /const bridge =/);
  assert.match(gesture, /this\.state\.step === frame\.step - 1/);
  assert.match(gesture, /this\.state\.target === frame\.previousTarget/);
  assert.match(gesture, /current \|\| bridge/);
  assert.match(gesture, /const pressed = visible && current && timing\.pressed/);
});
test('post-click target removal retains the captured geometry', () => {
  assert.match(gesture, /this\.state\.step === frame\.step && frame\.local >= data\.COMMIT_DELAY/);
  assert.match(gesture, /previous\.frame\.step !== this\.props\.frame\.step/);
  assert.doesNotMatch(gesture, /frame\.committed/);
});
test('invalid target geometry is rejected, including hidden and clipped nodes', () => {
  for(const part of ['measured: false',"style.visibility === 'hidden'","style.display === 'none'",'Number(style.opacity) === 0','r.right > rect.right + 1']) assert.ok(gesture.includes(part));
  assert.match(gesture,/this\.observer\?\.disconnect/);
});
test('QA still narrows, widens, and reproduces the same seeded defect', () => {
  assert.equal(data.qaWidth(at('qa',1,1000)),100);
  assert.equal(data.qaWidth(at('qa',2,COMMIT_DELAY)),100);
  assert.equal(data.qaWidth(at('qa',3,1000)),64);
  assert.equal(data.qaWidth(at('qa',4,COMMIT_DELAY+DRAG_DURATION)),100);
  assert.equal(data.qaWidth(at('qa',6,1000)),64);
});
test('terminal minimizes after its click without an independent speed clock', () => {
  assert.equal(data.MINIMIZE_DURATION,320);
  assert.equal(data.terminalMinimize(at('transfer',2,COMMIT_DELAY-1)),0);
  assert.equal(data.terminalMinimize(at('transfer',2,COMMIT_DELAY+320)),1);
  assert.match(polish,/transform-origin:left bottom/);
  assert.match(polish,/\.rf-host-browser,\.sa \.rf-terminal-layer \{inset:0;\}/);
});
test('whole-message chat remains distinct from the Slack task and reaches completion', () => {
  assert.notEqual(data.PROMPTS.chat,data.PROMPTS.slack);
  assert.match(data.PROMPTS.chat,/launch-notes\.odt/);
  assert.equal(data.CHAT_MESSAGES.at(-1).tool,'status · completed');
  assert.equal(data.CHAT_MESSAGES.at(-1).file,data.BRIEF_FILE);
  assert.deepEqual(Object.keys(data.messagePop(at('chat',1,COMMIT_DELAY),1)),['transform']);
});
test('MCP cards retain their real operations and scripted progress states', () => {
  assert.deepEqual(data.MCP_ACTIVITIES[5].tools,['status','logs']);
  assert.equal(data.MCP_ACTIVITIES[8].state,'completed');
  assert.match(polish,/rf-mcp-activity/);
  assert.match(polish,/--sa-accent:var\(--sa-11\)/);
});
test('color emphasizes the issue, active work and successful outcomes only', () => {
  assert.match(polish,/rf-qa-finding\[data-found='true'\].*--sa-warn/);
  assert.match(polish,/data-mcp-state='running'.*--sa-accent-text/);
  assert.match(polish,/data-mcp-state='completed'.*--sa-ok/);
  assert.doesNotMatch(polish,/#[0-9a-f]{3,8}\b|grayscale|hue-rotate|animation:.*infinite/i);
});
test('sample handles invalid input and bounded completion', () => {
  assert.throws(()=>sample([],0),RangeError);
  for(const v of [NaN,Infinity,-1])assert.equal(sample(TIMELINES.qa,v).elapsed,0);
  for(const beats of Object.values(TIMELINES))assert.equal(sample(beats,duration(beats)+100).done,true);
});
test('frame-boundary sampling never skips a commit at the faster clock rate', () => {
  for(const [id,beats] of Object.entries(TIMELINES))beats.forEach((beat,step)=>{
    assert.ok(beat.ms>COMMIT_DELAY);
    if(beat.dragTo)assert.ok(beat.ms>COMMIT_DELAY+DRAG_DURATION);
    if(step){assert.equal(at(id,step,COMMIT_DELAY-1).committed,step-1);assert.equal(at(id,step,COMMIT_DELAY).committed,step);}
  });
});
test('offscreen/hidden suspension and reduced-motion one-run opt-in remain', () => {
  for(const s of ['IntersectionObserver','!document.hidden','optedIn','LOOP_HOLD','componentWillUnmount','cancelAnimationFrame'])assert.ok(player.includes(s));
  assert.match(player,/this\.reduced && \(!this\.optedIn/);
});
test('the same Slack file picker, crop, and two saves remain', () => {
  assert.deepEqual(TIMELINES.slack.flatMap(b=>b.target?[b.target]:[]),['slack-account','slack-profile','slack-edit','slack-upload','slack-pictures','slack-file','slack-open','slack-crop','slack-crop-save','slack-save']);
  assert.equal(TIMELINES.slack[8].dragTo,'slack-crop-end');
});
test('Host semantics and ChatGPT concept are not promoted to new capabilities', () => {
  assert.equal(data.CHATGPT_INTEGRATION.status,'concept');
  assert.ok(data.HOST_CHECK.fields.not_checked.includes('native_computer_use'));
  assert.equal(data.CHAT_RUN.fields.status,'starting');
  assert.equal(data.CHAT_RUN.input.detach,true);
  assert.equal(data.CHAT_STATUS.fields.status,'completed');
});
test('classic Clawd cells and all four vendor logo paths remain unchanged', () => {
  assert.equal(data.CLAWD,' ▐▛███▜▌\n▝▜█████▛▘\n  ▘▘ ▝▝');
  const expected={chatgpt:'3fae9b38d571a5ab5aa662bc279dcda580855d6ca6b35330e4b4ba171367ffb1',slack:'69c3650cc9632f4edcf00bb5fd02792d5cb46d8af58f8db5001ba64cdd40da4b',drive:'583dfed4b5d2e771e6d1df51d78588feaa4e8f11db4bbd4e44fff7a369b061d8',analytics:'4697f13a7ce9c068abeb35c5d480e7f28f20c9404f48ba244115fe293773c9ac'};
  for(const [name,hash] of Object.entries(expected)){
    const path=read('workflow-logos.tsx').match(new RegExp(`\\b${name}: '([^']+)'`))?.[1];
    assert.ok(path,name);assert.equal(createHash('sha256').update(path).digest('hex'),hash,name);
  }
});
test('changed code introduces no live calls or independent timer loops', () => {
  assert.doesNotMatch(player+gesture,/\bfetch\s*\(|XMLHttpRequest|new WebSocket|setInterval/);
});
test('cursor glyphs stay sharp during playback', () => {
  assert.match(controlCss, /animation: ctl-enter 160ms ease-out both/);
  assert.doesNotMatch(controlCss, /filter:\s*blur|filter:\s*\n\s*drop-shadow/);
  assert.match(controlCss, /shape-rendering: geometricPrecision/);
  assert.match(gesture, /Math\.round\(point\.x\)/);
  assert.match(player, /Math\.round\(from\.x \+ \(to\.x - from\.x\) \* q\)/);
  assert.match(control, /shapeRendering/);
});
