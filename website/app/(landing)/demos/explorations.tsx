'use client';

import * as React from 'react';
import { CHAT_RUN, DEMOS, HOST_CHECK, RELEASE, TRANSFER_RUN } from './exploration-data';
import { WorkflowPlayer } from './workflow-motion';
import { ChatScene, QaScene, ToolDetails, TransferScene, WallpaperScene } from './workflow-scenes';
import './explorations.css';

const SCENES = { qa: QaScene, chat: ChatScene, transfer: TransferScene, wallpaper: WallpaperScene };
const NOTES = {
  qa: 'Synthetic checkout and findings. A browser walkthrough, not a built-in QA report or a measured test.',
  chat: 'Configured does not mean online or ready. This example uses a server started with --enable-mutations.',
  transfer: 'Mutation tools enabled; websites signed in. Browser download and upload stay on the same Host.',
  wallpaper: 'Illustrative macOS task on a configured, ready Host. Satelle does not grant native permissions.',
};

/** Both routes present the four requested workflows, in the same order.
 * The former six-option selector and its URL state have intentionally gone. */
export default function DemoGallery({ explore = false }: { explore?: boolean }) {
  return <div className="sx-gallery" data-explorations={explore ? 'review' : 'home'}>
    <div className="sx-grid">
      {DEMOS.map((demo) => {
        const Scene = SCENES[demo.id];
        const titleId = `${explore ? 'explore' : 'home'}-${demo.id}-title`;
        return <article className="sx-card" key={demo.id} aria-labelledby={titleId} data-demo={demo.id} data-surface={demo.surface}>
          <header className="sx-card-head">
            {explore && <span className="sx-eyebrow">{demo.number} / {demo.label}</span>}
            <h3 id={titleId}>{demo.title}</h3>
            <p>{demo.lead}</p>
            <a href={demo.href}>{demo.cta} <span aria-hidden="true">→</span></a>
          </header>
          <div className="sx-card-body">
            <WorkflowPlayer id={demo.id}>{(frame, moving) => <Scene frame={frame} moving={moving} />}</WorkflowPlayer>
          </div>
          <div className="sw-notes">
            <p>{NOTES[demo.id]}</p>
            {explore && demo.id === 'chat' && <><ToolDetails label="config_check · configured Hosts" input={HOST_CHECK.input} fields={HOST_CHECK.fields} /><ToolDetails label="run · desktop-chat task" input={CHAT_RUN.input} fields={CHAT_RUN.fields} /></>}
            {explore && demo.id === 'transfer' && <ToolDetails label="run · Claude Code task" input={TRANSFER_RUN.input} fields={TRANSFER_RUN.fields} />}
          </div>
        </article>;
      })}
    </div>
    <p className="sx-footnote">Animated illustrations, not live runs or recordings. App outcomes are examples, not guarantees or app-specific integrations. Native macOS and Windows Hosts are candidates and must pass the live readiness probe; native Linux Host execution is not supported in {RELEASE}. Controls only replay this page.</p>
  </div>;
}
