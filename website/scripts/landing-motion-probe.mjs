/** Browser-side observation only: it never drives or patches the application. */
export function installMotionProbe({ timelines, messages, commit, travel, press, release, linger, dragDuration }) {
  const proof = { errors: [], hits: {}, drags: {}, messages: [], continuitySamples: 0, hiddenIdleSamples: 0, minimized: false, seenCycles: {} };
  window.__landingProof = proof;
  function check() {
    for (const card of document.querySelectorAll('[data-explorations="home"] [data-demo]')) {
      const id = card.dataset.demo, player = card.querySelector('.sw-player');
      const step = Number(player.dataset.step), beat = timelines[id][step];
      const start = timelines[id].slice(0, step).reduce((sum, b) => sum + b.ms, 0);
      const local = Number(player.dataset.elapsed) - start;
      const cursor = card.querySelector('.rf-cursor');
      const done = player.dataset.complete === 'true';
      const releasedAt = commit + (beat.dragTo ? dragDuration : release);
      const adjacent = Boolean(timelines[id][step + 1]?.target);
      const shouldShow = Boolean(beat.target && !done && (adjacent || local < releasedAt + linger));
      const shown = Boolean(cursor && getComputedStyle(cursor).visibility === 'visible');
      // Exclude only sub-millisecond rounded boundary ambiguity, never gaps.
      const boundary = Math.abs(local - (releasedAt + linger)) < 2;
      if (!boundary && shown !== shouldShow) proof.errors.push(`${id}/${step}/${local}: cursor ${shown ? 'stray' : 'blink'}`);
      if (beat.target && adjacent && local > releasedAt) proof.continuitySamples++;
      if (!beat.target && !shown) proof.hiddenIdleSamples++;
      if (cursor && ![press, releasedAt].some(n => Math.abs(local - n) < 2)) {
        const pressed = shown && local >= press && local < releasedAt;
        if ((cursor.dataset.pressed === 'true') !== Boolean(pressed)) proof.errors.push(`${id}/${step}/${local}: incorrect press/release`);
      }
      const inspect = beat.target && local >= travel + 2 && (beat.dragTo ? local < commit + dragDuration - 2 : local < commit - 2);
      if (inspect && cursor) {
        const target = [...card.querySelectorAll(`[data-cursor="${beat.target}"]`)].find(el => { const r = el.getBoundingClientRect(); return r.width && r.height; });
        if (!target) { proof.errors.push(`${id}/${step}: missing target`); continue; }
        const a = target.getBoundingClientRect(), b = cursor.getBoundingClientRect(), root = card.querySelector('.rf-stage').getBoundingClientRect();
        if (a.left < root.left - 1 || a.right > root.right + 1 || a.top < root.top - 1 || a.bottom > root.bottom + 1) proof.errors.push(`${id}/${step}: target outside scene`);
        const distance = Math.hypot(a.x + a.width / 2 - b.x, a.y + a.height / 2 - b.y);
        if (distance > 4) proof.errors.push(`${id}/${step}: pointer missed by ${distance.toFixed(2)}px`);
        (beat.dragTo ? proof.drags : proof.hits)[`${id}/${step}`] = true;
      }
      if (id === 'chat') for (const el of card.querySelectorAll('.rf-message')) {
        const n = Number(el.dataset.message), expected = messages.find(m => m.step === n);
        if (el.querySelector('p').textContent !== expected.text) proof.errors.push(`chat/${n}: partial message`);
        if (getComputedStyle(el).opacity !== '1') proof.errors.push(`chat/${n}: opacity fade`);
        if (!proof.messages.includes(n)) proof.messages.push(n);
      }
      if (id === 'transfer') {
        const terminal = card.querySelector('.rf-terminal-layer');
        if (getComputedStyle(terminal).opacity !== '1') proof.errors.push('terminal fade');
        if ((step < 2 || step === 2 && local < commit) && terminal.dataset.minimized === 'true') proof.errors.push('terminal minimized before click');
        if (step === 2 && local >= commit && local < commit + 300) {
          const root = card.querySelector('.rf-transfer').getBoundingClientRect(), r = terminal.getBoundingClientRect();
          if (Math.abs(root.left - r.left) > 2 || Math.abs(root.bottom - r.bottom) > 2) proof.errors.push('terminal left the bottom-left anchor');
        }
        if (terminal.dataset.minimized === 'true') proof.minimized = true;
      }
      proof.seenCycles[id] = Math.max(proof.seenCycles[id] ?? 0, Number(player.dataset.cycle));
    }
    if (proof.errors.length < 100) window.__landingProbeRaf = requestAnimationFrame(check);
  }
  window.__landingProbeRaf = requestAnimationFrame(check);
}
