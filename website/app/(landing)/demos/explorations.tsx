'use client';
import * as React from "react";
import * as data from "./exploration-data";
import * as motion from "./workflow-motion";
import * as scenes from "./workflow-scenes";
import "./explorations.css";
const SCENES: Record<data.DemoId, React.ComponentType<data.SceneProps>> = { qa: scenes.QaScene, chat: scenes.ChatScene, transfer: scenes.TransferScene, slack: scenes.SlackScene };
const NOTES = {
    qa: 'GitHub UI reenactment. The QA notes are scripted, not measured results or a built-in Satelle report.',
    chat: data.CHATGPT_INTEGRATION.note,
    transfer: 'Signed-in sample accounts. Browser download and upload occur on the same Host, with mutation tools enabled.',
    slack: 'A Slack desktop task, not a Slack API integration. The image is illustrative; no account is changed.',
};
export default function DemoGallery({ explore = false }: {
    explore?: boolean;
}) {
    return <div className="sx-gallery" data-explorations={explore ? 'review' : 'home'}>
    <div className="sx-grid">
        {data.DEMOS.map((demo) => {
            const Scene = SCENES[demo.id];
            const titleId = `${explore ? 'explore' : 'home'}-${demo.id}-title`;
            return <article className="sx-card" key={demo.id} aria-labelledby={titleId} data-demo={demo.id} data-surface={demo.surface}>
            <header className="sx-card-head">
            {explore && <span className="sx-eyebrow">
            {demo.number}
            {" / "}
            {demo.label}
            </span>}
            <h3 id={titleId}>
            {demo.title}
            </h3>
            <p>
            {demo.lead}
            </p>
            <a href={demo.href}>
            {demo.cta}
            {" "}
            <span aria-hidden="true">
            {"\u2192"}
            </span>
            </a>
            </header>
            <div className="sx-card-body">
            <motion.WorkflowPlayer id={demo.id}>
            {(frame, moving) => <Scene frame={frame} moving={moving}/>}
            </motion.WorkflowPlayer>
            </div>
            <div className="sw-notes">
            <p>
            {NOTES[demo.id]}
            </p>
            {explore && demo.id === 'chat' && <React.Fragment>
            <scenes.ToolDetails label="Proposed config_check · configured Hosts" input={data.HOST_CHECK.input} fields={data.HOST_CHECK.fields}/>
            <scenes.ToolDetails label="Proposed run · ChatGPT concept" input={data.CHAT_RUN.input} fields={data.CHAT_RUN.fields}/>
            </React.Fragment>}
            {explore && demo.id === 'transfer' && <scenes.ToolDetails label="run · Claude Code task" input={data.TRANSFER_RUN.input} fields={data.TRANSFER_RUN.fields}/>}
            </div>
            </article>;
        })}
    </div>
    {explore && <section id="chatgpt-requirements" className="wf-integration-note" aria-labelledby="chatgpt-requirements-title">
    <h2 id="chatgpt-requirements-title">
    {"ChatGPT connection requirements"}
    </h2>
    <p>
    {"The desktop conversation is a design concept, not an available Satelle integration. This release serves MCP over local stdio and has no ChatGPT installer target. ChatGPT custom MCP requires a compatible remote transport; a bridge and desktop-client compatibility would need implementation and verification. Neither is supplied by this PR. Configured Hosts are not automatically discovered, online, or ready."}
    </p>
    <a href="https://help.openai.com/en/articles/12584461-developer-mode-and-mcp-apps-in-chatgpt">
    {"OpenAI\u2019s MCP requirements \u2197"}
    </a>
    </section>}
    <p className="sx-footnote">
    {"Animated UI reenactments, not live runs or recordings. Sample data and outcomes are illustrative. Native macOS and Windows Hosts are candidates and must pass the live readiness probe; native Linux Host execution is not supported in "}
    {data.RELEASE}
    {". Playback controls affect this page only. App brands do not imply a partnership."}
    </p>
    </div>;
}
