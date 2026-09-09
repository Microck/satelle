/** Checks the production-exported landing page; no component hook or injected UI. */
import assert from 'node:assert/strict';
import { mkdir, writeFile, readFile } from 'node:fs/promises';
import { createRequire } from 'node:module';
import { pathToFileURL } from 'node:url';
import path from 'node:path';
import { installMotionProbe } from './landing-motion-probe.mjs';
const require = createRequire(import.meta.url), ts = require('typescript');
const { outputText } = ts.transpileModule(await readFile(new URL('../app/(landing)/demos/exploration-data.ts', import.meta.url), 'utf8'), { compilerOptions: { target: ts.ScriptTarget.ES2022, module: ts.ModuleKind.ES2022 } });
const data = await import(`data:text/javascript;base64,${Buffer.from(outputText).toString('base64')}`);
const { chromium } = await import(process.env.PLAYWRIGHT_MODULE ? pathToFileURL(process.env.PLAYWRIGHT_MODULE).href : 'playwright');
const base = process.env.DEMO_BASE_URL ?? 'http://127.0.0.1:4173';
const out = path.resolve(process.env.DEMO_ARTIFACTS ?? 'landing-artifacts');
await mkdir(out, { recursive: true });
const browser = await chromium.launch({ headless: true });
const ids = ['qa','chat','transfer','slack'], errors = [], report = [];
const wait = ms => new Promise(resolve => setTimeout(resolve, ms));
const observe = page => page.on('pageerror', e => errors.push(String(e)));
const scenePlayer = (gallery, id) => gallery.locator(`[data-demo="${id}"] .sw-player`);
let page;
try {
  const context = await browser.newContext({ viewport: { width: 1440, height: 1800 }, reducedMotion: 'no-preference', recordVideo: { dir: path.join(out,'video'), size: { width:1440,height:1000 } } });
  page = await context.newPage(); observe(page);
  await page.goto(base, { waitUntil: 'networkidle' });
  const gallery = page.locator('[data-explorations="home"]');
  await gallery.scrollIntoViewIfNeeded();
  assert.equal(await gallery.locator('[data-demo]').count(),4);
  assert.equal(await gallery.locator('.sw-controls,.sw-playback,.sw-steps,.sw-notes,.sx-footnote,.rf-taskbar').count(),0);
  assert.equal(await gallery.locator('.rf-qa > .rf-request').isVisible(),false);
  await page.waitForFunction(() => [...document.querySelectorAll('[data-explorations="home"] .sw-player')].every(el => el.dataset.playing === 'true'));
  report.push('No QA prompt strip, playback buttons, captions, or taskbar.');
  const start = await scenePlayer(gallery,'qa').evaluate(el => ({ elapsed:Number(el.dataset.elapsed), at:performance.now() }));
  await wait(800);
  const end = await scenePlayer(gallery,'qa').evaluate(el => ({ elapsed:Number(el.dataset.elapsed), at:performance.now() }));
  const rate = (end.elapsed - start.elapsed) / (end.at - start.at);
  assert.ok(rate > 1.12 && rate < 1.38, `measured playback rate ${rate}`);
  assert.equal(await scenePlayer(gallery,'qa').getAttribute('data-playback-rate'),'1.25');
  report.push(`Shared playback rate: ${rate.toFixed(3)}x measured (1.25x configured).`);
  const before = await gallery.locator('.sw-scene').evaluateAll(es => es.map(e => e.innerHTML));
  const pixels = await Promise.all(ids.map(id => gallery.locator(`[data-demo="${id}"] .sw-scene`).screenshot()));
  await wait(3700);
  const after = await gallery.locator('.sw-scene').evaluateAll(es => es.map(e => e.innerHTML));
  for(let i=0;i<ids.length;i++) {
    assert.notEqual(before[i],after[i],`${ids[i]} DOM moves`);
    assert.notDeepEqual(pixels[i],await gallery.locator(`[data-demo="${ids[i]}"] .sw-scene`).screenshot(),`${ids[i]} rendered pixels move`);
  }
  for(const id of ids) { await scenePlayer(gallery,id).focus(); await page.keyboard.press('Space'); }
  await wait(80);
  const frozen = await gallery.locator('.sw-scene').evaluateAll(es => es.map(e => e.innerHTML));
  await wait(300);
  assert.deepEqual(await gallery.locator('.sw-scene').evaluateAll(es => es.map(e => e.innerHTML)),frozen);
  report.push('Scene keyboard activation pauses all actual content and cursor geometry.');
  for(const id of ids) { await scenePlayer(gallery,id).focus(); await page.keyboard.press('r'); }
  await page.evaluate(installMotionProbe, { timelines:data.TIMELINES,messages:data.CHAT_MESSAGES,commit:data.COMMIT_DELAY,travel:data.POINTER_TRAVEL,press:data.POINTER_PRESS,release:data.POINTER_RELEASE,linger:data.POINTER_LINGER,dragDuration:data.DRAG_DURATION });
  const cycles = await gallery.locator('.sw-player').evaluateAll(es => es.map(e => Number(e.dataset.cycle)));
  await page.waitForFunction(counts => [...document.querySelectorAll('[data-explorations="home"] .sw-player')].every((el,i) => Number(el.dataset.cycle) > counts[i]), cycles, { timeout:40000 });
  const proof = await page.evaluate(() => { cancelAnimationFrame(window.__landingProbeRaf); return window.__landingProof; });
  await writeFile(path.join(out,'gesture-proof.json'),JSON.stringify(proof,null,2));
  assert.deepEqual(proof.errors,[],'No cursor blinks, false clicks, partial messages or premature minimization');
  for(const [id, beats] of Object.entries(data.TIMELINES)) beats.forEach((beat,i) => { if(beat.target) assert.ok((beat.dragTo?proof.drags:proof.hits)[`${id}/${i}`],`observed ${id}/${i}`); });
  assert.ok(proof.continuitySamples>50); assert.ok(proof.hiddenIdleSamples>50);
  assert.equal(proof.messages.length,data.CHAT_MESSAGES.length); assert.ok(proof.minimized);
  report.push('Full loops: every click/drag aligned within 4px; no post-click disappearance between actions; idle cursors hidden.');
  await gallery.screenshot({ path:path.join(out,'landing-motion.png') });
  await page.setViewportSize({width:1440,height:650}); await page.evaluate(() => scrollTo(0,0)); await wait(150);
  assert.equal(await gallery.locator('.sw-player[data-playing="true"]').count(),0);
  report.push('Offscreen animation remains suspended.');
  await context.close();
  const reduced = await browser.newContext({viewport:{width:1440,height:1800},reducedMotion:'reduce'});
  page = await reduced.newPage(); observe(page); await page.goto(base,{waitUntil:'networkidle'});
  const rg=page.locator('[data-explorations="home"]'); await rg.scrollIntoViewIfNeeded(); await wait(100);
  assert.equal(await rg.locator('.sw-player[data-playing="true"]').count(),0);
  for(const id of ids) {
    const player=scenePlayer(rg,id); await player.focus(); await page.keyboard.press('Enter'); await wait(90);
    const initial=await player.locator('.sw-scene').innerHTML(); await wait(id === 'qa' ? 3800 : 2000);
    assert.notEqual(await player.locator('.sw-scene').innerHTML(),initial);
    await player.click(); assert.equal(await player.getAttribute('data-playing'),'false');
  }
  report.push('Reduced motion stays still by default; Enter/scene click explicitly plays/pauses real animation.');
  await page.reload({waitUntil:'networkidle'});
  for(const width of [320,390,768,850,1024,1440,1920]) {
    await page.setViewportSize({width,height:1000});
    for(const theme of ['light','dark']) {
      await page.evaluate(t=>document.documentElement.dataset.theme=t,theme); await wait(70);
      assert.ok(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth+1),`${width}/${theme} page overflow`);
      assert.equal(await page.locator('.rf-qa > .rf-request').isVisible(),false);
      for(const id of ids) {
        const scene=page.locator(`[data-explorations="home"] [data-demo="${id}"] .sw-scene`); await scene.scrollIntoViewIfNeeded();
        const bad=await scene.evaluate(s=>{ const r=s.getBoundingClientRect();return [...s.querySelectorAll('.rf-composer,.rf-chat-file,.rf-qa-finding,.rf-upload-note,.rf-profile')].filter(e=>{const b=e.getBoundingClientRect();return b.width&&(b.left<r.left-1||b.right>r.right+1||b.bottom>r.bottom+1);}).map(e=>e.className); });
        assert.deepEqual(bad,[],`${id}/${width}/${theme} clipping`);
      }
      const bug=await page.locator('[data-explorations="home"] .rf-resize-browser').evaluate(el=>{const r=el.getBoundingClientRect(),b=el.querySelector('.rf-buy-button').getBoundingClientRect();return b.right>r.right&&b.left<r.right;});
      assert.ok(bug,'Seeded CTA still visibly clips inside the demo only');
      if(width===390||width===1440) await page.locator('[data-explorations="home"] .sx-grid').screenshot({path:path.join(out,`landing-${width}-${theme}.png`)});
    }
  }
  report.push('Seven widths, both themes: no unintended layout overflow; seeded responsive defect stays visible.');
  await page.goto(`${base}${process.env.DEMO_REVIEW_PATH??'/demo-explorations.html'}`,{waitUntil:'networkidle'});
  assert.equal(await page.locator('[data-explorations="review"] [data-demo]').count(),4);
  assert.equal(await page.locator('.sw-controls,.sw-steps,.sw-playback').count(),0);
  assert.ok(await page.locator('.rf-chat [data-logo="chatgpt"]').count()>0);
  assert.equal(await page.locator('[data-demo="slack"] [data-logo="slack"]').count(),1);
  report.push('Review route shares the same scenes and unchanged sourced logos.');
  await reduced.close(); assert.deepEqual(errors,[],'No page or hydration errors');
  console.log(report.join('\n'));
} catch(error) {
  if(page&&!page.isClosed()) await page.screenshot({path:path.join(out,'failure.png'),fullPage:true}).catch(()=>{});
  await writeFile(path.join(out,'failure.txt'),String(error)+'\n'+errors.join('\n')); throw error;
} finally { await writeFile(path.join(out,'checks.json'),JSON.stringify({report,errors},null,2)); await browser.close(); }
