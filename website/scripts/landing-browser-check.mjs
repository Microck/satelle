/** Real-browser regression against the exported LANDING PAGE, not a screenshot
 * harness. Supply PLAYWRIGHT_MODULE for an isolated CI install; no app dependency. */
import assert from 'node:assert/strict';
import { mkdir, writeFile } from 'node:fs/promises';
import { pathToFileURL } from 'node:url';
import path from 'node:path';
const { chromium } = await import(process.env.PLAYWRIGHT_MODULE ? pathToFileURL(process.env.PLAYWRIGHT_MODULE).href : 'playwright');
const base = process.env.DEMO_BASE_URL ?? 'http://127.0.0.1:4173';
const out = path.resolve(process.env.DEMO_ARTIFACTS ?? 'landing-artifacts');
await mkdir(out, {recursive:true});
const browser = await chromium.launch({headless:true});
const errors = [];
const report = [];
const ids = ['qa','chat','transfer','slack'];
let page;
const listen = (p) => p.on('pageerror', e => errors.push(String(e)));
const wait = ms => new Promise(resolve=>setTimeout(resolve,ms));
try {
  const context = await browser.newContext({viewport:{width:1440,height:1800},reducedMotion:'no-preference',recordVideo:{dir:path.join(out,'video'),size:{width:1440,height:1000}}});
  page = await context.newPage(); listen(page);
  await page.goto(base, {waitUntil:'networkidle'});
  const gallery=page.locator('[data-explorations="home"]');
  await gallery.scrollIntoViewIfNeeded();
  assert.equal(await gallery.locator('[data-demo]').count(),4);
  assert.equal(await gallery.locator('.lf-checkout').count(),1);
  assert.equal(await gallery.locator('.lf-chat').count(),1);
  assert.equal(await gallery.locator('.wf-gpt-side,.wf-gh-header,.sw-steps').count(),0);
  await page.waitForFunction(()=>[...document.querySelectorAll('[data-explorations="home"] .sw-player')].every(x=>x.dataset.playing==='true'));
  const before = await gallery.locator('.sw-scene').evaluateAll(xs=>xs.map(x=>x.innerHTML));
  const pixels = await Promise.all(ids.map(id=>gallery.locator(`[data-demo="${id}"] .sw-scene`).screenshot()));
  await wait(1500);
  const after = await gallery.locator('.sw-scene').evaluateAll(xs=>xs.map(x=>x.innerHTML));
  for(let i=0;i<ids.length;i++){
    assert.notEqual(after[i],before[i],`${ids[i]} scene really changes`);
    assert.notDeepEqual(await gallery.locator(`[data-demo="${ids[i]}"] .sw-scene`).screenshot(),pixels[i],`${ids[i]} pixels move`);
  }
  report.push('All four hydrated landing-page scenes change both DOM and pixels.');
  for(const id of ids) await gallery.getByRole('button',{name:`Pause ${id} animation`,exact:true}).click();
  await wait(100);
  const frozen=await gallery.locator('.sw-scene').evaluateAll(xs=>xs.map(x=>x.innerHTML));
  await wait(500);
  assert.deepEqual(await gallery.locator('.sw-scene').evaluateAll(xs=>xs.map(x=>x.innerHTML)),frozen);
  report.push('Pause freezes the actual app scene, not only its progress label.');
  for(const id of ids) await gallery.getByRole('button',{name:`Replay ${id} demo`,exact:true}).click();
  const cycles=await gallery.locator('.sw-player').evaluateAll(xs=>xs.map(x=>Number(x.dataset.cycle)));
  await page.waitForFunction((counts)=>[...document.querySelectorAll('[data-explorations="home"] .sw-player')].every((x,i)=>Number(x.dataset.cycle)>counts[i]),cycles,{timeout:45000});
  report.push('All four complete a real-time playback cycle and restart while visible.');
  await gallery.screenshot({path:path.join(out,'landing-motion.png')});
  // The clocks are actively looping here: leaving view, not a manual Pause, must stop them.
  await page.setViewportSize({width:1440,height:650});
  await page.evaluate(()=>window.scrollTo(0,0));
  await wait(200);
  assert.equal(await gallery.locator('.sw-player[data-playing="true"]').count(),0);
  report.push('Scrolling away suspends playback.');
  await context.close();

  const reduced=await browser.newContext({viewport:{width:1440,height:1800},reducedMotion:'reduce'});
  page=await reduced.newPage(); listen(page);
  await page.goto(base,{waitUntil:'networkidle'});
  const rg=page.locator('[data-explorations="home"]');
  await rg.scrollIntoViewIfNeeded(); await wait(200);
  assert.equal(await rg.locator('.sw-player[data-playing="true"]').count(),0);
  for(const id of ids){
    const card=rg.locator(`[data-demo="${id}"]`);
    await card.getByRole('button',{name:`Play ${id} animation`,exact:true}).click();
    await wait(500);
    assert.equal(await card.locator('.sw-player').getAttribute('data-playing'),'true');
    const initial=await card.locator('.sw-scene').innerHTML();
    await wait(500);
    assert.notEqual(await card.locator('.sw-scene').innerHTML(),initial);
    await card.getByRole('button',{name:`Pause ${id} animation`,exact:true}).click();
  }
  report.push('Reduced motion: no autoplay; explicit Play animates all four instead of showing stills.');
  // A fresh reduced-motion load gives the stable completed states for responsive QA.
  await page.reload({waitUntil:'networkidle'});
  for(const width of [320,390,768,1024,1440,1920]){
    await page.setViewportSize({width,height:1000});
    for(const theme of ['light','dark']){
      await page.evaluate(t=>document.documentElement.dataset.theme=t,theme);
      assert.ok(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth+1),`page overflow at ${width}/${theme}`);
      for(const id of ids){
        const scene=page.locator(`[data-explorations="home"] [data-demo="${id}"] .sw-scene`);
        await scene.scrollIntoViewIfNeeded();
        const overflowing=await scene.evaluate(s=>{
          const r=s.getBoundingClientRect();
          return [...s.querySelectorAll('.lf-composer,.lf-qa-result,.lf-chat-result,.wf-drive-progress,.wf-slack-profile')].filter(x=>{const b=x.getBoundingClientRect();return b.width>0&&(b.left<r.left-1||b.right>r.right+1||b.bottom>r.bottom+1);}).map(x=>x.className);
        });
        assert.deepEqual(overflowing,[],`${id} clipping at ${width}/${theme}`);
      }
      if(width===390||width===1440) await page.locator('[data-explorations="home"] .sx-grid').screenshot({path:path.join(out,`landing-${width}-${theme}.png`)});
    }
  }
  report.push('Six widths, both themes: no page overflow or clipped final-state task content.');
  await page.goto(`${base}${process.env.DEMO_REVIEW_PATH ?? "/demo-explorations.html"}`,{waitUntil:'networkidle'});
  assert.equal(await page.locator('[data-explorations="review"] [data-demo]').count(),4);
  assert.equal(await page.locator('.lf-chat .wf-brand[data-logo="chatgpt"]').count(),3);
  assert.equal(await page.locator('[data-demo="slack"] [data-logo="slack"]').count(),1);
  report.push('Review route shares all four components and the sourced logo geometry.');
  await reduced.close();
  assert.deepEqual(errors,[],'No page errors / hydration exceptions');
  console.log(report.join('\n'));
} catch(error) {
  if(page&&!page.isClosed())await page.screenshot({path:path.join(out,'failure.png'),fullPage:true}).catch(()=>{});
  await writeFile(path.join(out,'failure.txt'),String(error)+'\n'+errors.join('\n'));
  throw error;
} finally {
  await writeFile(path.join(out,'checks.json'),JSON.stringify({report,errors},null,2));
  await browser.close();
}
