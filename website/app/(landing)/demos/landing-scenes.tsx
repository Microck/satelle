'use client';
import * as React from 'react';
import { COMMIT_DELAY, PROMPTS, SITES, phase, typed, type SceneProps } from './exploration-data';
import { Brand, Chrome, Icon, Lights, Pointer, Prompt } from './workflow-ui';

const reveal = (frame: SceneProps['frame'], step: number) => ({ opacity: phase(frame, step, 260, COMMIT_DELAY) });

/** A checkout, not repository navigation. Sauce Demo is a real practice store.
 * These illustrative outcomes are not presented as tests actually run on it. */
export function CheckoutScene({ frame, moving }: SceneProps) {
  const c = frame.committed;
  const review = c >= 5;
  const first = frame.step === 1 ? typed('Alex', frame, 1, 1350) : c >= 1 ? 'Alex' : '';
  const last = frame.step === 4 ? typed('Morgan', frame, 4, 1500) : c >= 4 ? 'Morgan' : '';
  return <div className="wf-stage lf-checkout">
    <Prompt text={typed(PROMPTS.qa, frame, 0, 1800)} />
    <Chrome url={review ? 'saucedemo.com/checkout-step-two.html' : SITES.qa} />
    <div className="lf-store-nav"><strong>Swag Labs</strong><span>Checkout <Icon name="lock" size={13} /></span></div>
    <div className="lf-checkout-main">
      <div className="lf-order-summary"><div className="lf-product-art"><svg viewBox="0 0 110 130" width="86" height="103"><path d="M37 24V17a18 18 0 0 1 36 0v7" fill="none" stroke="var(--sa-9)" strokeWidth="6"/><rect x="22" y="22" width="66" height="99" rx="18" fill="var(--sa-6)"/><path d="M22 64h66M35 82h40" stroke="var(--sa-10)" strokeWidth="2"/><rect x="32" y="72" width="46" height="34" rx="9" fill="var(--sa-5)"/><path d="M35 81h40" stroke="var(--sa-9)" strokeWidth="2"/><rect x="45" y="36" width="20" height="10" rx="2" fill="var(--sa-10)"/></svg></div><div><strong>Sauce Labs Backpack</strong><span>Quantity 1</span><b>$29.99</b></div></div>
      <div className="lf-checkout-form">
        <small>{review ? '02 / OVERVIEW' : '01 / YOUR INFORMATION'}</small>
        <h4>{review ? 'Review your order' : 'Your details'}</h4>
        {!review ? <><div className="lf-field" data-cursor="qa-first" data-filled={!!first}>{first || 'First Name'}</div><div className="lf-field" data-cursor="qa-last" data-filled={!!last} data-invalid={c >= 2 && c < 4}>{last || 'Last Name'}</div><div className="lf-field" data-filled={c >= 4}>{c >= 4 ? '94103' : 'Zip / Postal Code'}</div><div className="lf-validation" style={{ opacity: c >= 2 && c < 4 ? 1 : 0 }}><Icon name="issue" size={14} />Last Name is required</div><span className="lf-action" data-cursor="qa-continue">Continue <Icon name="arrow" size={14} /></span></> : <><div className="lf-total"><span>Item total</span><b>$29.99</b></div><div className="lf-total"><span>Tax</span><b>$2.40</b></div><div className="lf-total lf-grand-total"><span>Total</span><b>$32.39</b></div><span className="lf-action lf-no-purchase">Finish</span><p className="lf-stopped">Stopped before purchase.</p></>}
      </div>
    </div>
    <div className="lf-qa-result"><div><b>Checkout QA</b><small>Illustrative run</small></div><p><span>{c >= 2 ? '✓' : '○'} Required fields</span><span>{c >= 5 ? '✓' : '○'} Order review</span></p><strong>{c >= 6 ? 'Validation checked. No purchase made.' : c >= 2 && c < 4 ? 'Empty last name is correctly blocked.' : 'Following the checkout in the browser.'}</strong></div>
    <Pointer frame={frame} moving={moving} />
  </div>;
}

/** Deliberately the earlier small chat treatment: title, messages, one composer.
 * No sidebar, app navigation, nested dashboards, or model/version claim. */
export function SimpleChatScene({ frame }: SceneProps) {
  const c = frame.committed;
  return <div className="wf-stage lf-chat">
    <header className="lf-chat-title"><Lights /><Brand name="chatgpt" /><strong>ChatGPT</strong><small>Concept</small></header>
    <div className="lf-conversation">
      <div className="lf-user-message">{typed(PROMPTS.hosts, frame, 0, 1300) || '\u00a0'}</div>
      <div className="lf-assistant" style={reveal(frame, 1)}><Brand name="chatgpt" /><div><small>Satelle · config_check</small><p>{c >= 2 ? 'You have two configured Hosts:' : 'Checking your Host configuration…'}</p><div className="lf-hosts" style={reveal(frame, 2)}><span><Icon name="monitor" /><b>studio-mac</b><em>Configured</em></span><span><Icon name="monitor" /><b>ops-pc</b><em>Configured</em></span></div></div></div>
      <div className="lf-user-message" style={{ opacity: frame.step >= 3 ? 1 : 0 }}>{typed(PROMPTS.chat, frame, 3, 2050) || '\u00a0'}</div>
      <div className="lf-assistant lf-chat-result" style={reveal(frame, 4)}><Brand name="chatgpt" /><div><small>Satelle · run</small><p>{c >= 5 ? 'Task admitted on studio-mac.' : 'Sending the requested task to studio-mac…'}</p><p className="lf-muted" style={reveal(frame, 5)}>First Turn: starting.</p></div></div>
    </div>
    <div className="lf-composer"><span>Message ChatGPT…</span><span>＋ <i>↑</i></span></div>
  </div>;
}
