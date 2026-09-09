import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { createRequire } from 'node:module';
import { createHash } from 'node:crypto';
import test from 'node:test';
const require = createRequire(import.meta.url);
const ts = require('typescript');
const dir = new URL('../app/(landing)/demos/', import.meta.url);
const read = (name) => readFileSync(new URL(name, dir), 'utf8');
const compile = (name) => ts.transpileModule(read(name), {fileName:name, reportDiagnostics:true, compilerOptions:{target:ts.ScriptTarget.ES2022,module:ts.ModuleKind.ES2022,jsx:ts.JsxEmit.React}});
const compiled = compile('exploration-data.ts');
assert.equal(compiled.diagnostics?.length ?? 0, 0);
const data = await import(`data:text/javascript;base64,${Buffer.from(compiled.outputText).toString('base64')}`);
const {DEMOS,TIMELINES,duration,stepStart,sample,typed,phase,COMMIT_DELAY,POINTER_TRAVEL} = data;
const focus = read('landing-scenes.tsx'), motion = read('workflow-motion.tsx'), gallery = read('explorations.tsx');
for (const name of ['exploration-data.ts','workflow-ui.tsx','workflow-logos.tsx','workflow-motion.tsx','landing-scenes.tsx','explorations.tsx']) {
  test(`${name}: TypeScript/JSX syntax`,()=>assert.equal(compile(name).diagnostics?.length ?? 0,0));
}
test('same four workflows are mounted on the landing page',()=>{
  assert.deepEqual(DEMOS.map(d=>d.id),['qa','chat','transfer','slack']);
  assert.match(gallery,/qa: CheckoutScene, chat: SimpleChatScene, transfer: TransferScene, slack: SlackScene/);
  assert.match(gallery,/DEMOS.map/);
});
test('QA is a real practice-store checkout, not a repository or invented real-site defect',()=>{
  assert.equal(data.SITES.qa,'saucedemo.com/checkout-step-one.html');
  assert.match(focus,/Last Name is required/);
  assert.match(focus,/Stopped before purchase/);
  assert.doesNotMatch(focus,/wf-gh|GitHub|Critical|invalid email accepted/i);
});
test('chat is the small conversation, not a full desktop-app clone',()=>{
  assert.match(focus,/ChatGPT/); assert.match(focus,/lf-composer/);
  assert.doesNotMatch(focus,/wf-gpt-side|Search chats|Library|ChatViewport|Confirmation/);
  assert.match(focus,/First Turn: starting/);
});
test('Host configuration and ChatGPT integration remain honestly scoped',()=>{
  assert.deepEqual(data.HOST_CHECK.input,{all:true});
  assert.ok(data.HOST_CHECK.fields.not_checked.includes('native_computer_use'));
  assert.equal(data.CHATGPT_INTEGRATION.status,'concept');
  assert.match(gallery,/not an available Satelle integration/);
  assert.equal(data.CHAT_RUN.fields.status,'starting');
  assert.equal(data.CHAT_RUN.input.detach,true);
});
test('each sequence is bounded and gives the pointer time to arrive',()=>{
  assert.ok(POINTER_TRAVEL<COMMIT_DELAY);
  for(const beats of Object.values(TIMELINES)) {
    assert.ok(beats.every(b=>b.ms>COMMIT_DELAY));
    assert.ok(duration(beats)<60000);
    assert.equal(sample(beats,duration(beats)).done,true);
    for(let i=1;i<beats.length;i++){
      assert.equal(sample(beats,stepStart(beats,i)+POINTER_TRAVEL).committed,i-1);
      assert.equal(sample(beats,stepStart(beats,i)+COMMIT_DELAY).committed,i);
    }
  }
});
test('invalid and empty clock inputs are handled',()=>{
  assert.throws(()=>sample([],0),RangeError);
  for(const t of [-1,Infinity,NaN]) assert.equal(sample(TIMELINES.qa,t).elapsed,0);
});
test('typing and window handoff are real time-varying projections',()=>{
  const text='Test checkout';
  assert.equal(typed(text,sample(TIMELINES.qa,0),0),'');
  assert.ok(typed(text,sample(TIMELINES.qa,900),0).length>0);
  assert.equal(typed(text,sample(TIMELINES.qa,1900),0),text);
  assert.equal(phase(sample(TIMELINES.transfer,0),2),0);
  assert.equal(phase(sample(TIMELINES.transfer,duration(TIMELINES.transfer)),2),1);
});
test('visible normal playback loops instead of stopping permanently',()=>{
  assert.equal(data.LOOP_HOLD,1800);
  assert.match(motion,/!this.reduced && this.clock >= total \+ LOOP_HOLD/);
  assert.match(motion,/this.cycle\+\+/);
});
test('reduced motion has an explicit real-animation opt-in, not still-only Replay',()=>{
  assert.match(motion,/this.optedIn = true/);
  assert.match(motion,/this.clock = 0/);
  assert.match(motion,/Play animation/);
  assert.doesNotMatch(motion,/nextStill|Next frame|sw-steps|step buttons/);
});
test('offscreen/hidden work is suspended and effects clean up',()=>{
  for(const text of ['IntersectionObserver','document.hidden','cancelAnimationFrame','disconnect()','removeEventListener','private paused = false'])assert.ok(motion.includes(text));
  assert.doesNotMatch(motion,/setInterval|setTimeout/);
});
test('transfer and Slack remain the requested native task sequences',()=>{
  assert.equal(data.TRANSFER_RUN.input.host,'ops-pc');
  assert.equal(data.TRANSFER_RUN.input.detach,true);
  assert.deepEqual(TIMELINES.transfer.flatMap(b=>b.target?[b.target]:[]),['ga-report','ga-share','ga-download','ga-csv','drive-tab','drive-folder','drive-new','drive-upload','transfer-file','transfer-open']);
  assert.deepEqual(TIMELINES.slack.flatMap(b=>b.target?[b.target]:[]),['slack-account','slack-profile','slack-edit','slack-upload','slack-pictures','slack-file','slack-open','slack-crop','slack-crop-save','slack-save']);
});
test('new scenes inherit Satelle paint without vendor palette or filters',()=>{
  assert.doesNotMatch(read('landing-scenes.css'),/#[0-9a-f]{3,8}\b|grayscale|hue-rotate/i);
  assert.doesNotMatch(focus+read('workflow-logos.tsx'),/(?:fill|stroke)=["']#/);
  assert.match(read('workflow-logos.tsx'),/fill="currentColor"/);
});
test('logo paths match the pinned Simple Icons 15.0.0 source snapshots',()=>{
  const src=read('workflow-logos.tsx');
  const expected={"chatgpt": "3fae9b38d571a5ab5aa662bc279dcda580855d6ca6b35330e4b4ba171367ffb1", "slack": "69c3650cc9632f4edcf00bb5fd02792d5cb46d8af58f8db5001ba64cdd40da4b", "drive": "583dfed4b5d2e771e6d1df51d78588feaa4e8f11db4bbd4e44fff7a369b061d8", "analytics": "4697f13a7ce9c068abeb35c5d480e7f28f20c9404f48ba244115fe293773c9ac"};
  for(const [name,hash] of Object.entries(expected)){
    const path=src.match(new RegExp(`  ${name}: '([^']+)'`))?.[1];
    assert.ok(path,name);
    assert.equal(createHash('sha256').update(path).digest('hex'),hash,name);
  }
  assert.doesNotMatch(src,/rotate\(/);
});
test('no external operation is performed by a demo',()=>{
  assert.doesNotMatch(focus+motion+gallery,/\bfetch\s*\(|XMLHttpRequest|new WebSocket|execSync|window\.open/);
});
