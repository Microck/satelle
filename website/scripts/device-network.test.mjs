import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { createRequire } from 'node:module';
import test from 'node:test';
const require = createRequire(import.meta.url), ts = require('typescript');
const base = new URL('../app/(landing)/devices/', import.meta.url);
const read = name => readFileSync(new URL(name, base), 'utf8');
const compile = name => ts.transpileModule(read(name), {fileName:name,reportDiagnostics:true,compilerOptions:{target:ts.ScriptTarget.ES2022,module:ts.ModuleKind.ES2022,jsx:ts.JsxEmit.React}});
const out = compile('network-model.ts');
assert.equal(out.diagnostics?.length ?? 0, 0);
const m = await import(`data:text/javascript;base64,${Buffer.from(out.outputText).toString('base64')}`);
const component=read('device-network.tsx'),css=read('device-network.css');
test('six distinct supported Controller form factors; no invented mobile client',()=>{
  assert.equal(m.DEVICES.length,6); assert.equal(new Set(m.DEVICES.map(x=>x.shape)).size,6);
  assert.deepEqual([...new Set(m.DEVICES.map(x=>x.os))].sort(),['Linux','Windows','macOS']);
  assert.doesNotMatch(JSON.stringify(m.DEVICES),/phone|iOS|Android/);
});
test('each Controller gets one turn per round, with no overlap',()=>{
  assert.deepEqual([...m.SEND_ORDER].sort(),[0,1,2,3,4,5]);
  for(let i=0;i<12;i++)assert.equal(m.networkFrame(i*m.TIMING.cycle+1000).sender,m.SEND_ORDER[i%6]);
});
test('signals arrive before the Host becomes active',()=>{
  for(const t of [0,m.TIMING.send,m.TIMING.arrive-1])assert.equal(m.networkFrame(t).heat,0);
  assert.equal(m.networkFrame(m.TIMING.send).phase,'sending');
  assert.equal(m.networkFrame(m.TIMING.arrive).phase,'receiving');
  assert.equal(m.networkFrame(m.TIMING.work).heat,1);
  assert.equal(m.networkFrame(m.TIMING.acknowledge).phase,'complete');
  assert.equal(m.networkFrame(m.TIMING.cooldown).phase,'acknowledging');
});
test('Host visibly works then returns to idle without losing the Session',()=>{
  assert.equal(m.networkFrame(m.TIMING.work).working,true);
  assert.equal(m.networkFrame(m.TIMING.work).progress,0);
  assert.equal(m.networkFrame(m.TIMING.complete).phase,'complete');
  assert.equal(m.networkFrame(m.TIMING.complete).progress,1);
  assert.equal(m.networkFrame(m.TIMING.rest).heat,0);
  assert.equal(m.networkFrame(m.TIMING.rest).idle,true);
  assert.match(component,/while keeping its Session/);
});
test('one clock projects deterministic, bounded phase/progress/heat',()=>{
  for(const t of [-10,NaN,Infinity])assert.equal(m.networkFrame(t).elapsed,0);
  for(let t=0;t<m.TIMING.cycle*6;t+=73){const f=m.networkFrame(t);assert.ok(f.heat>=0&&f.heat<=1);assert.ok(f.progress>=0&&f.progress<=1);assert.ok(f.signal>=0&&f.signal<=1);assert.ok(f.ackSignal>=0&&f.ackSignal<=1);assert.ok(f.signalFade>=0&&f.signalFade<=1);assert.ok(f.ackFade>=0&&f.ackFade<=1);assert.deepEqual(f,m.networkFrame(t));}
});
test('both layouts keep orbiting devices inside the canvas and away from the Host',()=>{
  for(const compact of [true,false]){
    const b=m.layout(compact);
    for(let t=0;t<m.ORBIT_MS;t+=500)for(let i=0;i<6;i++){
      const p=m.devicePoint(i,t,compact),pad=60*b.deviceScale;
      assert.ok(p.x-pad>0&&p.x+pad<b.width&&p.y-pad>0&&p.y+pad<b.height,`${compact}/${i}/${t}: outside`);
      // Outer silhouettes never collide with the laptop: disjoint boxes suffice.
      assert.ok(Math.abs(p.x-b.cx)>154*b.hostScale+45*b.deviceScale||Math.abs(p.y-b.cy)>97*b.hostScale+45*b.deviceScale,`${compact}/${i}/${t}: Host collision`);
    }
  }
});
test('pulse endpoints track the moving source and stop at the Host, never teleport',()=>{
  for(const compact of [true,false])for(let i=0;i<6;i++){
    const p=m.signalPath(i,1200,compact), node=m.devicePoint(i,1200,compact);
    assert.deepEqual(m.pointOnSignal(p,0),p.a);assert.deepEqual(m.pointOnSignal(p,1),p.b);
    assert.ok(Math.abs(Math.hypot(p.a.x-node.x,p.a.y-node.y)-p.sourceDistance)<1e-6);
    assert.ok(p.sourceDistance>20&&p.sourceDistance<60);
    const mid=m.pointOnSignal(p,.5);assert.ok(Number.isFinite(mid.x)&&Number.isFinite(mid.y));
    assert.notDeepEqual(p.a,m.signalPath(i,2200,compact).a);
  }
});
test('completion returns a smooth acknowledgment to the original Controller before idle',()=>{
  const complete=m.networkFrame(m.TIMING.complete), start=m.networkFrame(m.TIMING.acknowledge), sent=m.networkFrame(m.TIMING.cooldown), idle=m.networkFrame(m.TIMING.rest);
  assert.equal(complete.phase,'complete');assert.equal(start.phase,'complete');assert.equal(sent.phase,'acknowledging');
  assert.equal(start.ackSignal,0);assert.equal(sent.ackSignal,1);assert.equal(sent.ackEffect,1);
  assert.equal(idle.phase,'idle');assert.equal(idle.heat,0);assert.equal(idle.ackEffect,0);
});
test('device rotation is a gentle tilt, not upside-down tumbling',()=>{
  for(let i=0;i<6;i++)for(let t=0;t<m.ORBIT_MS;t+=900)assert.ok(Math.abs(m.devicePoint(i,t,false).tilt)<=5);
});
test('clock pauses for offscreen and hidden documents, cleans up, and supports reduced motion',()=>{
  for(const s of ['IntersectionObserver','ResizeObserver','!document.hidden','cancelAnimationFrame','componentWillUnmount','removeEventListener','prefers-reduced-motion: reduce','playUntil'])assert.ok(component.includes(s));
  assert.match(component,/role="button" tabIndex=\{0\}/);assert.match(component,/aria-keyshortcuts="Space Enter R"/);
  assert.doesNotMatch(component,/setInterval|setTimeout|fetch\(|WebSocket/);
});
test('red uses existing tokens, not a palette, glow effect or vendor assets',()=>{
  assert.match(css,/var\(--sa-accent\)/);assert.match(css,/dn-signal-trace/);assert.doesNotMatch(css,/#[0-9a-f]{3,8}\b|drop-shadow|grayscale|@keyframes/i);
  assert.doesNotMatch(component,/https?:\/\/|<img/);
});
test('component TypeScript/JSX syntax compiles',()=>assert.equal(compile('device-network.tsx').diagnostics?.length??0,0));
