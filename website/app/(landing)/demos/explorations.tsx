'use client';
import * as React from 'react';
import { CHAT_RUN, CHAT_STATUS, CHATGPT_INTEGRATION, DEMOS, HOST_CHECK, RELEASE, TRANSFER_RUN } from './exploration-data';
import { WorkflowPlayer } from './workflow-motion';
import { ResponsiveQaScene, SimpleChatScene, CompactTransferScene, CompactSlackScene } from './landing-scenes';
import { ToolDetails } from './workflow-ui';
import './explorations.css';
import './landing-scenes.css';

const SCENES = { qa: ResponsiveQaScene, chat: SimpleChatScene, transfer: CompactTransferScene, slack: CompactSlackScene };
const NOTES = {
  qa: 'Local storefront with a seeded layout bug. A QA illustration, not a claim about a third-party website.',
  chat: CHATGPT_INTEGRATION.note,
  transfer: 'Signed-in sample accounts. Browser download and upload stay on the same Host. Mutation tools are enabled.',
  slack: 'A native Slack task, not a Slack API integration. No real profile is changed by this demo.',
};
export default function DemoGallery({ explore = false }: { explore?: boolean }) {
  return <div className="sx-gallery" data-explorations={explore ? 'review' : 'home'}>
    <div className="sx-grid">
      {DEMOS.map((demo) => {
        const Scene = SCENES[demo.id];
        const titleId = `${explore ? 'explore' : 'home'}-${demo.id}-title`;
        return <article className="sx-card" key={demo.id} aria-labelledby={titleId} data-demo={demo.id} data-surface={demo.surface}>
          <header className="sx-card-head">
            {explore && <span className="sx-eyebrow">{demo.number} / {demo.label}</span>}
            <h3 id={titleId}>{demo.title}</h3><p>{demo.lead}</p>
            <a href={demo.href}>{demo.cta} <span aria-hidden="true">→</span></a>
          </header>
          <div className="sx-card-body"><WorkflowPlayer id={demo.id}>{(frame, moving) => <Scene frame={frame} moving={moving} />}</WorkflowPlayer></div>
          <div className="sw-notes"><p>{NOTES[demo.id]}</p>
            {explore && demo.id === 'chat' && <><ToolDetails label="Proposed config_check · configured Hosts" input={HOST_CHECK.input} fields={HOST_CHECK.fields} /><ToolDetails label="Proposed run · PDF task" input={CHAT_RUN.input} fields={CHAT_RUN.fields} /><ToolDetails label="Proposed status · completion" input={CHAT_STATUS.input} fields={CHAT_STATUS.fields} /></>}
            {explore && demo.id === 'transfer' && <ToolDetails label="run · Claude Code task" input={TRANSFER_RUN.input} fields={TRANSFER_RUN.fields} />}
          </div>
        </article>;
      })}
    </div>
    {explore && <section id="chatgpt-requirements" className="wf-integration-note" aria-labelledby="chatgpt-requirements-title">
      <h2 id="chatgpt-requirements-title">ChatGPT connection requirements</h2>
      <p>The simplified chat is a concept, not an available Satelle integration. This release serves MCP over local stdio and has no ChatGPT installer. A compatible remote bridge and client compatibility need separate implementation and verification. Configured Hosts are not automatically online or ready. Progress and completion are scripted summaries of hypothetical status/log checks; the displayed PDF path refers to the Host, not a downloadable ChatGPT attachment.</p>
      <a href="https://help.openai.com/en/articles/12584461-developer-mode-and-mcp-apps-in-chatgpt">OpenAI’s MCP requirements ↗</a>
    </section>}
    <p className="sx-footnote">Animated illustrations, not live runs or recordings. Normal playback repeats while visible; Pause stops it. Reduced motion disables autoplay, with Play animation available by choice. Native macOS and Windows Hosts are candidates requiring a live readiness pass; native Linux Host execution is unsupported in {RELEASE}.</p>
  </div>;
}
