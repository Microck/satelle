/** Observe the actual production-exported homepage, never an injected renderer. */
import assert from 'node:assert/strict';
import { mkdir, writeFile } from 'node:fs/promises';
import { pathToFileURL } from 'node:url';
import path from 'node:path';
const { chromium } = await import(process.env.PLAYWRIGHT_MODULE ? pathToFileURL(process.env.PLAYWRIGHT_MODULE).href : 'playwright');
const base = process.env.DEMO_BASE_URL ?? 'http://127.0.0.1:4173';
const out = path.join(path.resolve(process.env.DEMO_ARTIFACTS ?? 'landing-artifacts'), 'device-network');
await mkdir(out, { recursive: true });
const browser = await chromium.launch({ headless: true });
const report = [], errors = [];
const wait = ms => new Promise(resolve => setTimeout(resolve, ms));
let page;
try {
  const context = await browser.newContext({viewport:{width:1440,height:1000},reducedMotion:'no-preference',recordVideo:{dir:path.join(out,'video'),size:{width:1440,height:1000}}});
  page = await context.newPage();page.on('pageerror', e => errors.push(String(e)));
  await page.goto(base,{waitUntil:'networkidle'});
  const block = page.locator('[data-device-network]');
  assert.equal(await block.count(),1);
  assert.equal(await page.locator('#claims .card').count(),0,'The three old cards are removed');
  assert.match(await page.locator('#claims h2').innerText(),/Start on one machine/);
  assert.equal(await page.locator('[data-explorations="home"] [data-demo]').count(),4,'Existing demos remain');
  // Fresh document starts well above the block. It must not animate offscreen.
  assert.equal(await block.getAttribute('data-playing'),'false');
  assert.equal(await block.getAttribute('data-elapsed'),'0');
  await block.scrollIntoViewIfNeeded();await block.focus();await page.keyboard.press('r');
  await page.waitForFunction(()=>document.querySelector('[data-device-network]').dataset.playing==='true');
  assert.equal(await block.locator('[data-network-device]').count(),6);
  report.push('The actual #claims section contains one animated block and no old cards; all four existing demos are preserved.');
  const positions = await block.locator('[data-network-device]').evaluateAll(xs=>xs.map(x=>x.getAttribute('transform')));
  const initialPixels = await block.screenshot();
  await page.evaluate(()=>{
    const evidence={errors:[],senders:[],phases:[],workSamples:0,pulseSamples:0,idleSamples:0};
    window.__deviceEvidence=evidence;
    function inspect(){
      const root=document.querySelector('[data-device-network]');if(!root)return;
      const phase=root.dataset.phase,host=root.querySelector('[data-network-host]'),heat=Number(host.dataset.heat),progress=Number(host.dataset.progress);
      const signal=root.querySelector('[data-signal]'),visible=signal.dataset.visible==='true';
      if(!evidence.phases.includes(phase))evidence.phases.push(phase);
      if(phase==='sending'){
        if(!evidence.senders.includes(root.dataset.sender))evidence.senders.push(root.dataset.sender);
        if(heat!==0||!visible)evidence.errors.push('Host activated before arrival or missing signal');
        evidence.pulseSamples++;
      }
      if(phase==='idle') {if(heat!==0||visible)evidence.errors.push('Idle Host remained active');evidence.idleSamples++;}
      if(phase==='working') {
        if(heat!==1||host.dataset.working!=='true'||visible)evidence.errors.push('Work/arrival ordering');
        const fill=root.querySelector('.dn-progress-fill');
        if(Math.abs(Number(fill.getAttribute('width'))-152*progress)>0.02)evidence.errors.push('Screen progress drift');
        evidence.workSamples++;
      }
      if(evidence.errors.length<20)window.__deviceRaf=requestAnimationFrame(inspect);
    }
    window.__deviceRaf=requestAnimationFrame(inspect);
  });
  await page.waitForFunction(()=>document.querySelector('[data-device-network]').dataset.phase==='working');
  await wait(500);
  assert.notDeepEqual(await block.locator('[data-network-device]').evaluateAll(xs=>xs.map(x=>x.getAttribute('transform'))),positions,'Devices orbit');
  assert.notDeepEqual(await block.screenshot(),initialPixels,'Real rendered pixels animate');
  await block.click();await page.evaluate(()=>document.activeElement?.blur());
  const paused=await block.innerHTML();await wait(350);assert.equal(await block.innerHTML(),paused,'Pause freezes orbit, signal, screen and state');
  await block.screenshot({path:path.join(out,'working-desktop.png')});
  await block.focus();await page.keyboard.press('Enter');
  await page.waitForFunction(()=>window.__deviceEvidence.senders.length===6&&Number(document.querySelector('[data-device-network]').dataset.cycle)>=6,{},{timeout:42000});
  const proof=await page.evaluate(()=>{cancelAnimationFrame(window.__deviceRaf);return window.__deviceEvidence;});
  await writeFile(path.join(out,'sequence-proof.json'),JSON.stringify(proof,null,2));
  assert.deepEqual(proof.errors,[]);assert.equal(proof.senders.length,6);
  for(const state of ['idle','sending','receiving','working','complete'])assert.ok(proof.phases.includes(state),state);
  assert.ok(proof.pulseSamples>10&&proof.workSamples>10&&proof.idleSamples>10);
  report.push('All six moving sources sent signals in order; the Host only turned red after arrival, advanced actual screen progress, completed, and returned to idle.');
  report.push('Mouse pause and keyboard resume freeze/restart all motion together.');
  await page.evaluate(()=>scrollTo(0,0));await wait(200);
  assert.equal(await block.getAttribute('data-playing'),'false');
  const offscreen=await block.getAttribute('data-elapsed');await wait(250);assert.equal(await block.getAttribute('data-elapsed'),offscreen);
  report.push('Offscreen animation suspends without changing elapsed time.');
  await context.close();
  const reduced=await browser.newContext({viewport:{width:1440,height:1000},reducedMotion:'reduce'});
  page=await reduced.newPage();page.on('pageerror',e=>errors.push(String(e)));
  await page.goto(base,{waitUntil:'networkidle'});
  const still=page.locator('[data-device-network]');await still.scrollIntoViewIfNeeded();await wait(100);
  assert.equal(await still.getAttribute('data-playing'),'false');
  assert.equal(await still.getAttribute('data-phase'),'idle');
  await still.focus();await page.keyboard.press('Enter');
  await page.waitForFunction(()=>document.querySelector('[data-device-network]').dataset.phase==='working');
  await page.waitForFunction(()=>document.querySelector('[data-device-network]').dataset.playing==='false',{},{timeout:10000});
  assert.equal(await still.getAttribute('data-phase'),'idle');
  report.push('Reduced motion starts static; explicit Play performs one full work cycle and stops at idle.');
  for(const width of [320,390,768,1024,1440,1920]){
    await page.setViewportSize({width,height:1000});
    for(const theme of ['light','dark']){
      await page.evaluate(t=>document.documentElement.dataset.theme=t,theme);await still.scrollIntoViewIfNeeded();await wait(100);
      assert.ok(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth+1),`${width}/${theme}: page overflow`);
      const problems=await still.evaluate(el=>{
        const r=el.getBoundingClientRect();return [...el.querySelectorAll('[data-network-device],[data-network-host],.dn-corner,.dn-host-caption')].filter(x=>{
          const b=x.getBoundingClientRect();return b.left<r.left-1||b.right>r.right+1||b.top<r.top-1||b.bottom>r.bottom+1;
        }).map(x=>x.getAttribute('data-network-device')??x.className.baseVal??x.className);
      });
      assert.deepEqual(problems,[],`${width}/${theme}: illustration cropped`);
      assert.equal(await still.locator('button').count(),0,'No visible control strip');
      if(width===390||width===1440){await page.evaluate(()=>document.activeElement?.blur());await still.screenshot({path:path.join(out,`idle-${width}-${theme}.png`)});}
    }
  }
  report.push('Six widths and both themes: no horizontal overflow, clipped devices, or visible playback chrome.');
  assert.deepEqual(errors,[],'No page/hydration errors');
  await reduced.close();console.log(report.join('\n'));
} catch(error) {
  if(page&&!page.isClosed())await page.screenshot({path:path.join(out,'failure.png'),fullPage:true}).catch(()=>{});
  await writeFile(path.join(out,'failure.txt'),String(error)+'\n'+errors.join('\n'));throw error;
} finally {await writeFile(path.join(out,'checks.json'),JSON.stringify({report,errors},null,2));await browser.close();}
