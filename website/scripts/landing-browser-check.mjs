/** Regression on the production-exported LANDING PAGE. No component test hook,
 * injected fixture UI, or standalone React runtime is used by this check. */
import assert from 'node:assert/strict';
import { mkdir, writeFile, readFile } from 'node:fs/promises';
import { createRequire } from 'node:module';
import { pathToFileURL } from 'node:url';
import path from 'node:path';
const require = createRequire(import.meta.url);
const ts = require('typescript');
const { outputText } = ts.transpileModule(await readFile(new URL('../app/(landing)/demos/exploration-data.ts',import.meta.url),'utf8'),{compilerOptions:{target:ts.ScriptTarget.ES2022,module:ts.ModuleKind.ES2022}});
const data = await import(`data:text/javascript;base64,${Buffer.from(outputText).toString('base64')}`);
const { chromium } = await import(process.env.PLAYWRIGHT_MODULE ? pathToFileURL(process.env.PLAYWRIGHT_MODULE).href : 'playwright');
const base = process.env.DEMO_BASE_URL ?? 'http://127.0.0.1:4173';
const out = path.resolve(process.env.DEMO_ARTIFACTS ?? 'landing-artifacts');
await mkdir(out,{recursive:true});
const browser = await chromium.launch({headless:true});
const errors=[],report=[],ids=['qa','chat','transfer','slack'];
let page;
const listen = p => p.on('pageerror', e => errors.push(String(e)));
const wait = ms => new Promise(resolve=>setTimeout(resolve,ms));
try {
  const context = await browser.newContext({viewport:{width:1440,height:1800},reducedMotion:'no-preference',recordVideo:{dir:path.join(out,'video'),size:{width:1440,height:1000}}});
  page=await context.newPage(); listen(page);
  await page.goto(base,{waitUntil:'networkidle'});
  const gallery=page.locator('[data-explorations="home"]');
  await gallery.scrollIntoViewIfNeeded();
  assert.equal(await gallery.locator('[data-demo]').count(),4);
  assert.equal(await gallery.locator('.rf-qa,.rf-chat,.rf-transfer,.rf-slack').count(),4);
  assert.equal(await gallery.locator('.wf-gpt-side,.wf-gh-header,.sw-steps,.lf-checkout').count(),0);
  await page.waitForFunction(()=>[...document.querySelectorAll('[data-explorations="home"] .sw-player')].every(x=>x.dataset.playing==='true'));
  // Observe the real rAF clock to validate gestures against rendered targets.
  await page.evaluate(({timelines,messages,commit,travel})=>{
    const proof={errors:[],hits:{},drags:{},messages:[],minimized:false};
    window.__landingProof=proof;
    function frame(){
      for(const card of document.querySelectorAll('[data-explorations="home"] [data-demo]')){
        const id=card.dataset.demo, player=card.querySelector('.sw-player');
        const i=Number(player.dataset.step), beat=timelines[id][i];
        const before=timelines[id].slice(0,i).reduce((a,b)=>a+b.ms,0);
        const local=Number(player.dataset.elapsed)-before;
        const cursor=card.querySelector('.rf-cursor');
        const inspect=beat.target && local>=travel && (beat.dragTo ? local<commit+1200 : local<commit);
        if(inspect && cursor){
          const target=card.querySelector(`[data-cursor="${beat.target}"]`);
          if(!target){proof.errors.push(`${id}/${i}: missing target`);continue;}
          const a=target.getBoundingClientRect(),b=cursor.getBoundingClientRect(),root=card.querySelector('.rf-stage').getBoundingClientRect();
          if(!a.width||a.left<root.left-1||a.right>root.right+1||a.bottom>root.bottom+1)proof.errors.push(`${id}/${i}: target outside scene`);
          const distance=Math.hypot(a.x+a.width/2-b.x,a.y+a.height/2-b.y);
          if(distance>4)proof.errors.push(`${id}/${i}: cursor missed by ${distance.toFixed(2)}px`);
          (beat.dragTo?proof.drags:proof.hits)[`${id}/${i}`]=true;
        }
        if(id==='chat')for(const el of card.querySelectorAll('.rf-message')){
          const n=Number(el.dataset.message),expected=messages.find(m=>m.step===n);
          if(el.querySelector('p').textContent!==expected.text)proof.errors.push(`chat/${n}: partial message`);
          if(getComputedStyle(el).opacity!=='1')proof.errors.push(`chat/${n}: faded message`);
          if(!proof.messages.includes(n))proof.messages.push(n);
        }
        if(id==='transfer'){
          const terminal=card.querySelector('.rf-terminal-layer');
          if(getComputedStyle(terminal).opacity!=='1')proof.errors.push('terminal faded');
          if(i<2||i===2&&local<commit){if(terminal.dataset.minimized==='true')proof.errors.push('terminal minimized before click');}
          if(terminal.dataset.minimized==='true')proof.minimized=true;
        }
      }
      if(proof.errors.length>100) return;
      window.__landingRaf=requestAnimationFrame(frame);
    }
    window.__landingRaf=requestAnimationFrame(frame);
  },{timelines:data.TIMELINES,messages:data.CHAT_MESSAGES,commit:data.COMMIT_DELAY,travel:data.POINTER_TRAVEL});
  // New chat blocks arrive discretely; sample over a whole message interval.
  const before=await gallery.locator('.sw-scene').evaluateAll(xs=>xs.map(x=>x.innerHTML));
  const pixels=await Promise.all(ids.map(id=>gallery.locator(`[data-demo="${id}"] .sw-scene`).screenshot()));
  await wait(3300);
  const after=await gallery.locator('.sw-scene').evaluateAll(xs=>xs.map(x=>x.innerHTML));
  for(let i=0;i<ids.length;i++){
    assert.notEqual(after[i],before[i],`${ids[i]} changes actual content`);
    assert.notDeepEqual(await gallery.locator(`[data-demo="${ids[i]}"] .sw-scene`).screenshot(),pixels[i],`${ids[i]} changes pixels`);
  }
  report.push('All four hydrated landing scenes change DOM and pixels.');
  for(const id of ids) await gallery.getByRole('button',{name:`Pause ${id} animation`,exact:true}).click();
  await wait(100);
  const frozen=await gallery.locator('.sw-scene').evaluateAll(xs=>xs.map(x=>x.innerHTML));
  await wait(450);
  assert.deepEqual(await gallery.locator('.sw-scene').evaluateAll(xs=>xs.map(x=>x.innerHTML)),frozen);
  report.push('Pause freezes messages, pointer position and native window geometry.');
  for(const id of ids) await gallery.getByRole('button',{name:`Replay ${id} demo`,exact:true}).click();
  const cycles=await gallery.locator('.sw-player').evaluateAll(xs=>xs.map(x=>Number(x.dataset.cycle)));
  await page.waitForFunction(counts=>[...document.querySelectorAll('[data-explorations="home"] .sw-player')].every((x,i)=>Number(x.dataset.cycle)>counts[i]),cycles,{timeout:45000});
  const proof=await page.evaluate(()=>{cancelAnimationFrame(window.__landingRaf);return window.__landingProof;});
  await writeFile(path.join(out,'gesture-proof.json'),JSON.stringify(proof,null,2));
  assert.deepEqual(proof.errors,[],'Every click/drag lands coherently; no text/terminal fades');
  for(const [id,beats] of Object.entries(data.TIMELINES))beats.forEach((b,i)=>{
    if(b.target)assert.ok((b.dragTo?proof.drags:proof.hits)[`${id}/${i}`],`observed ${id}/${i} ${b.target}`);
  });
  assert.equal(proof.messages.length,data.CHAT_MESSAGES.length);
  assert.ok(proof.minimized);
  report.push('Full playback: every visible click/drag aligns within 4px, complete chat messages reach completion, terminal minimizes only after the click. All scenes loop.');
  await gallery.screenshot({path:path.join(out,'landing-motion.png')});
  await page.setViewportSize({width:1440,height:650});
  await page.evaluate(()=>window.scrollTo(0,0)); await wait(200);
  assert.equal(await gallery.locator('.sw-player[data-playing="true"]').count(),0);
  report.push('Offscreen animation suspends.');
  await context.close();

  const reduced=await browser.newContext({viewport:{width:1440,height:1800},reducedMotion:'reduce'});
  page=await reduced.newPage();listen(page);
  await page.goto(base,{waitUntil:'networkidle'});
  const rg=page.locator('[data-explorations="home"]');
  await rg.scrollIntoViewIfNeeded();await wait(200);
  assert.equal(await rg.locator('.sw-player[data-playing="true"]').count(),0);
  for(const id of ids){
    const card=rg.locator(`[data-demo="${id}"]`);
    await card.getByRole('button',{name:`Play ${id} animation`,exact:true}).click();
    await wait(150);
    const initial=await card.locator('.sw-scene').innerHTML();
    await wait(3000);
    assert.equal(await card.locator('.sw-player').getAttribute('data-playing'),'true');
    assert.notEqual(await card.locator('.sw-scene').innerHTML(),initial);
    await card.getByRole('button',{name:`Pause ${id} animation`,exact:true}).click();
  }
  report.push('Reduced motion keeps autoplay off; explicit Play runs each actual animation, including whole chat messages.');
  await page.reload({waitUntil:'networkidle'});
  for(const width of [320,390,768,850,1024,1440,1920]){
    await page.setViewportSize({width,height:1000});
    for(const theme of ['light','dark']){
      await page.evaluate(t=>document.documentElement.dataset.theme=t,theme);await wait(80);
      assert.ok(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth+1),`page overflow at ${width}/${theme}`);
      for(const id of ids){
        const scene=page.locator(`[data-explorations="home"] [data-demo="${id}"] .sw-scene`);
        await scene.scrollIntoViewIfNeeded();
        const overflowing=await scene.evaluate(s=>{
          const r=s.getBoundingClientRect();
          return [...s.querySelectorAll('.rf-composer,.rf-chat-file,.rf-qa-finding,.rf-upload-note,.rf-profile')].filter(x=>{const b=x.getBoundingClientRect();return b.width>0&&(b.left<r.left-1||b.right>r.right+1||b.bottom>r.bottom+1);}).map(x=>x.className);
        });
        assert.deepEqual(overflowing,[],`${id} clipping at ${width}/${theme}`);
      }
      const bug=await page.locator('[data-explorations="home"] .rf-resize-browser').evaluate(el=>{const r=el.getBoundingClientRect(),b=el.querySelector('.rf-buy-button').getBoundingClientRect();return b.right>r.right&&b.left<r.right;});
      assert.ok(bug,'The seeded CTA is visibly clipped, not simply hidden or reported');
      if(width===390||width===1440)await page.locator('[data-explorations="home"] .sx-grid').screenshot({path:path.join(out,`landing-${width}-${theme}.png`)});
    }
  }
  report.push('Seven widths and both themes: no unintended clipping; the deliberately broken storefront button is partially visible at the narrow edge.');
  await page.goto(`${base}${process.env.DEMO_REVIEW_PATH??'/demo-explorations.html'}`,{waitUntil:'networkidle'});
  assert.equal(await page.locator('[data-explorations="review"] [data-demo]').count(),4);
  assert.ok(await page.locator('.rf-chat [data-logo="chatgpt"]').count()>0);
  assert.equal(await page.locator('[data-demo="slack"] [data-logo="slack"]').count(),1);
  report.push('Review route uses the same scenes and sourced logos.');
  await reduced.close();
  assert.deepEqual(errors,[],'No page errors / hydration exceptions');
  console.log(report.join('\n'));
} catch(error) {
  if(page&&!page.isClosed())await page.screenshot({path:path.join(out,'failure.png'),fullPage:true}).catch(()=>{});
  await writeFile(path.join(out,'failure.txt'),String(error)+'\n'+errors.join('\n'));throw error;
} finally {
  await writeFile(path.join(out,'checks.json'),JSON.stringify({report,errors},null,2));await browser.close();
}
