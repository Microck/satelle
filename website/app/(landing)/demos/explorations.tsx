'use client';
import * as React from 'react';
import { CHAT_RUN, CHAT_STATUS, DEMOS, HOST_CHECK, TRANSFER_RUN } from './exploration-data';
import { WorkflowPlayer } from './workflow-motion';
import { ResponsiveQaScene, SimpleChatScene, CompactTransferScene, CompactSlackScene } from './landing-scenes';
import { ToolDetails } from './workflow-ui';
import './explorations.css';
import './landing-scenes.css';
import './landing-polish.css';

const SCENES = { qa: ResponsiveQaScene, chat: SimpleChatScene, transfer: CompactTransferScene, slack: CompactSlackScene };
export default function DemoGallery({ explore = false }: { explore?: boolean }) {
  return <div className="sx-gallery" data-explorations={explore ? 'review' : 'home'}>
    {explore && <details id="chatgpt-requirements" className="rf-review-notes">
      <summary>About these illustrations and connection requirements</summary>
      <p>All four scenes are scripted illustrations, not live tasks. The QA example has an intentionally seeded layout bug. Native Hosts still need a live readiness pass; configured contexts do not mean reachable or ready computers.</p>
      <p>The simplified ChatGPT window is not an available Satelle integration. This release serves local stdio MCP, without a ChatGPT installer or compatible remote bridge. Progress and completion are hypothetical status/log summaries. The PDF path belongs to the Host, not a downloadable ChatGPT attachment.</p>
      <a href="https://help.openai.com/en/articles/12584461-developer-mode-and-mcp-apps-in-chatgpt">OpenAI’s MCP requirements ↗</a>
      <ToolDetails label="Proposed config_check · configured Hosts" input={HOST_CHECK.input} fields={HOST_CHECK.fields} />
      <ToolDetails label="Proposed run · PDF task" input={CHAT_RUN.input} fields={CHAT_RUN.fields} />
      <ToolDetails label="Proposed status · completion" input={CHAT_STATUS.input} fields={CHAT_STATUS.fields} />
      <ToolDetails label="run · coding-agent task" input={TRANSFER_RUN.input} fields={TRANSFER_RUN.fields} />
    </details>}
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
        </article>;
      })}
    </div>
  </div>;
}
