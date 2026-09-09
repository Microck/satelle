'use client';
import * as React from "react";
import * as data from "./exploration-data";
import * as motion from "./workflow-motion";
export function Pointer({ frame, moving }: data.SceneProps) {
    return <motion.DemoCursor target={frame.target} progress={frame.pointer} click={frame.local >= 620 && frame.local < data.COMMIT_DELAY + 160} visible={!frame.done && moving} layout={frame.committed}/>;
}
export function Lights() {
    return <span className="wf-lights">
    <i />
    <i />
    <i />
    </span>;
}
export function Icon({ name, size = 16 }: {
    name: string;
    size?: number;
}) {
    const paths: Record<string, string> = {
        search: 'M14 14l5 5M16 9a7 7 0 1 1-14 0 7 7 0 0 1 14 0',
        arrow: 'M4 10h12m-5-5 5 5-5 5', check: 'm4 10 4 4 8-8',
        home: 'M2 9 10 2l8 7v9H3V9M7 18v-7h6v7',
        folder: 'M2 5h6l2 2h8v10H2z', file: 'M5 2h7l4 4v12H5zM12 2v5h4M8 11h5M8 14h5',
        edit: 'm13 2 5 5-10 10-6 1 1-6ZM11 4l5 5',
        photo: 'M2 3h16v14H2zM3 15l5-6 4 4 2-2 4 5M13 6h.1',
        chat: 'M2 3h16v11H8l-5 4v-4H2zM6 7h8M6 10h5',
        gear: 'M10 2v2m0 12v2M2 10h2m12 0h2M4 4l2 2m8 8 2 2M4 16l2-2m8-8 2-2M14 10a4 4 0 1 1-8 0 4 4 0 0 1 8 0',
        download: 'M10 2v10m-4-4 4 4 4-4M3 13v5h14v-5',
        upload: 'M10 13V3m-4 4 4-4 4 4M3 13v5h14v-5',
        share: 'M12 2l5 4-5 4M17 6H8v8M4 6H2v12h15v-5',
        branch: 'M5 6v8m0-8a2 2 0 1 0 0-4 2 2 0 0 0 0 4m0 8a2 2 0 1 0 0 4 2 2 0 0 0 0-4m10-8a2 2 0 1 0 0-4 2 2 0 0 0 0 4M15 6v4c0 3-10 0-10 4',
        monitor: 'M2 3h16v11H2zM6 18h8m-4-4v4',
        lock: 'M5 9h10v9H5zM7 9V5a3 3 0 0 1 6 0v4',
        issue: 'M18 10a8 8 0 1 1-16 0 8 8 0 0 1 16 0M10 6v5m0 3h.1',
        grid: 'M2 2h6v6H2zM12 2h6v6h-6zM2 12h6v6H2zM12 12h6v6h-6z',
    };
    return <svg width={size} height={size} viewBox="0 0 20 20" fill="none" stroke="currentColor" strokeWidth="1.45" strokeLinecap="round" strokeLinejoin="round" focusable="false">
    <path d={paths[name] ?? paths.file}/>
    </svg>;
}
export function Brand({ name }: {
    name: "github" | "chatgpt" | "slack" | "drive" | "analytics";
}) {
    if (name === 'github')
        return <svg className="wf-brand" viewBox="0 0 24 24" fill="currentColor">
        <path d="M12 .9a11.1 11.1 0 0 0-3.5 21.6c.6.1.8-.2.8-.5v-2.1c-3.1.7-3.8-1.3-3.8-1.3-.5-1.3-1.3-1.7-1.3-1.7-1-.7.1-.7.1-.7 1.1.1 1.7 1.2 1.7 1.2 1 1.7 2.6 1.2 3.3.9.1-.7.4-1.2.7-1.5-2.5-.3-5.1-1.2-5.1-5.5 0-1.2.4-2.2 1.1-3-.1-.3-.5-1.4.1-2.9 0 0 .9-.3 3 1.1a10.4 10.4 0 0 1 5.5 0c2.1-1.4 3-1.1 3-1.1.6 1.5.2 2.6.1 2.9.7.8 1.1 1.8 1.1 3 0 4.3-2.6 5.2-5.1 5.5.4.4.8 1.1.8 2.1V22c0 .3.2.6.8.5A11.1 11.1 0 0 0 12 .9Z"/>
        </svg>;
    if (name === 'chatgpt')
        return <svg className="wf-brand wf-knot" viewBox="0 0 32 32" fill="none" stroke="currentColor" strokeWidth="1.8">
        {[0, 60, 120, 180, 240, 300].map((r) => <path key={r} transform={`rotate(${r} 16 16)`} d="M16 3c-5.5-1.5-10 3-8.5 8.3l12.7 7.4v-6.1L12 7.8c-.4-2.3 1.8-4.7 4-4.8Z"/>)}
        </svg>;
    if (name === 'slack')
        return <svg className="wf-brand" viewBox="0 0 24 24">
        {[0, 90, 180, 270].map((rotate) => <g key={rotate} fill="currentColor" transform={`rotate(${rotate} 12 12)`}>
        <rect x="2" y="8" width="10" height="4" rx="2"/>
        <path d="M8 2a2 2 0 1 1 4 0v4h-2a2 2 0 0 1-2-2Z" transform="translate(0 2)"/>
        </g>)}
        </svg>;
    if (name === 'drive')
        return <svg className="wf-brand" viewBox="0 0 24 24">
        <path d="m8 2-8 14 4 7 8-14Z" fill="var(--sa-11)"/>
        <path d="M8 2h8l8 14h-8Z" fill="var(--sa-9)"/>
        <path d="M0 16h24l-4 7H4Z" fill="var(--sa-12)"/>
        </svg>;
    return <svg className="wf-brand" viewBox="0 0 24 24">
    <rect x="16" y="1" width="7" height="22" rx="3.5" fill="var(--sa-12)"/>
    <rect x="8" y="9" width="7" height="14" rx="3.5" fill="var(--sa-10)"/>
    <circle cx="3.5" cy="19.5" r="3.5" fill="var(--sa-10)"/>
    </svg>;
}
export function Chrome({ url, children }: {
    url: string;
    children?: React.ReactNode;
}) {
    return <React.Fragment>
    <div className="wf-chrome">
    <Lights />
    <div className="wf-address">
    <Icon name="lock" size={12}/>
    <span>
    {url}
    </span>
    </div>
    <span>
    {"\u22EE"}
    </span>
    </div>
    {children}
    </React.Fragment>;
}
export function Prompt({ text }: {
    text: string;
}) {
    return <div className="wf-request">
    <span className="wf-request-mark">
    {"\u2197"}
    </span>
    <span>
    {text || '\u00a0'}
    </span>
    </div>;
}
/** An original abstract avatar, not an invented photograph of the visitor. */
export function Photo({ variant = 'new' }: {
    variant?: string;
}) {
    if (variant === 'old')
        return <span className="wf-avatar-old">
        {"Y"}
        </span>;
    return <svg className="wf-photo" viewBox="0 0 100 100" role="presentation">
    <rect width="100" height="100" fill={variant === 'alt' ? 'var(--sa-5)' : 'var(--sa-4)'}/>
    <circle cx="70" cy="28" r="16" fill="var(--sa-10)"/>
    <path d="m0 77 35-41 25 31 16-18 24 28v23H0Z" fill="var(--sa-9)"/>
    <path d="M0 82c27-20 54 25 100-9v27H0Z" fill="var(--sa-12)"/>
    <path d="m12 89 25-28 16 15-13 21Z" fill="var(--sa-6)"/>
    </svg>;
}
export function ToolDetails({ label, input, fields }: {
    label: string;
    input: object;
    fields: object;
}) {
    return <details className="wf-tool-details">
    <summary>
    {label}
    </summary>
    <div>
    <p>
    {"Illustrative arguments"}
    </p>
    <pre>
    {JSON.stringify(input, null, 2)}
    </pre>
    <p>
    {"Selected fields, not a full response"}
    </p>
    <pre>
    {JSON.stringify(fields, null, 2)}
    </pre>
    </div>
    </details>;
}
