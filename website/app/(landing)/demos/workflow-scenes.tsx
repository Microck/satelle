'use client';
import * as React from "react";
import * as data from "./exploration-data";
import * as ui from "./workflow-ui";
/** A real, read-only website scenario, with explicitly scripted QA notes.
 * No fictional security finding or product defect is attributed to GitHub. */
export function QaScene({ frame, moving }: data.SceneProps) {
    const c = frame.committed;
    const query = frame.step >= 3 ? data.typed('is:issue is:open satelle-qa-no-match', frame, 3, 2000) : 'is:issue is:open';
    return <div className="wf-stage wf-qa">
    <ui.Prompt text={data.typed(data.PROMPTS.qa, frame, 0, 2600)}/>
    <div className="wf-qa-browser">
    <ui.Chrome url={data.SITES.qa + (c >= 2 ? '/issues' : c >= 1 ? '#readme' : '')}/>
    <div className="wf-gh-header">
    <ui.Brand name="github"/>
    <span>
    {"Microck "}
    <i>
    {"/"}
    </i>
    {" "}
    <b>
    {"satelle"}
    </b>
    </span>
    <span className="wf-gh-public">
    {"Public"}
    </span>
    <span className="wf-gh-menu">
    {"\u2630"}
    </span>
    </div>
    <div className="wf-gh-tabs">
    <span data-active={c < 2}>
    {"\u3008\u3009 Code"}
    </span>
    <span data-cursor="qa-issues" data-active={c >= 2}>
    <ui.Icon name="issue"/>
    {" Issues"}
    </span>
    <span>
    <ui.Icon name="branch"/>
    {" Pull requests"}
    </span>
    <span className="wf-optional">
    {"\u25C9 Actions"}
    </span>
    </div>
    <div className="wf-gh-body">
    {c < 2 ? <React.Fragment>
    <div className="wf-gh-repo-tools">
    <span>
    <ui.Icon name="branch"/>
    {" main \u2304"}
    </span>
    <span>
    {"Go to file"}
    </span>
    <span className="wf-gh-green">
    {"Code \u2304"}
    </span>
    </div>
    {c === 0 ? <div className="wf-gh-files">
    {['crates', 'docs', 'website'].map((folder) => <div key={folder}>
    <ui.Icon name="folder"/>
    <span>
    {folder}
    </span>
    <small>
    {"Browse directory"}
    </small>
    </div>)}
    <div data-cursor="qa-readme">
    <ui.Icon name="file"/>
    <b>
    {"README.md"}
    </b>
    <small>
    {"Read the documentation"}
    </small>
    </div>
    </div> : <div className="wf-gh-readme">
    <small>
    {"\u2637 README"}
    </small>
    <h4>
    {"Satelle"}
    </h4>
    <p>
    {"A self-hosted control plane for durable native Computer Use."}
    </p>
    <p>
    {"A Controller sends work to an operator-controlled Host."}
    </p>
    <span data-cursor="qa-readme">
    {"First Session tutorial \u2197"}
    </span>
    </div>}
    </React.Fragment> : <React.Fragment>
    <div className="wf-gh-search-row">
    <span className="wf-gh-search" data-cursor="qa-search">
    <ui.Icon name="search"/>
    <span>
    {query}
    </span>
    </span>
    <span data-cursor="qa-submit">
    <ui.Icon name="arrow"/>
    </span>
    </div>
    <div className="wf-gh-filter-row">
    <span>
    {"Labels"}
    </span>
    <span>
    {"Milestones"}
    </span>
    <span>
    {"Sort \u2304"}
    </span>
    </div>
    <div className="wf-gh-empty">
    <ui.Icon name="search" size={28}/>
    <h4>
    {c >= 4 ? 'No results matched your search.' : 'Search issues'}
    </h4>
    <p>
    {c >= 4 ? 'Try a different keyword or remove a filter.' : 'Find an issue by keyword or label.'}
    </p>
    {c >= 4 && <span className="wf-gh-link">
    {"Clear current search query"}
    </span>}
    </div>
    </React.Fragment>}
    </div>
    </div>
    <div className="wf-qa-notes">
    <div>
    <span>
    {"QA notes"}
    </span>
    <small>
    {"Scripted example"}
    </small>
    </div>
    <ul>
    {['README navigation', 'Issues navigation', 'Empty-state handling'].map((check, i) => <li key={check} data-done={c >= [1, 2, 4][i]}>
    <span>
    {c >= [1, 2, 4][i] ? '✓' : '○'}
    </span>
    {check}
    </li>)}
    </ul>
    <p>
    {c >= 5 ? 'Three paths checked. Nothing submitted.' : 'Checking the experience in a real browser.'}
    </p>
    </div>
    <ui.Pointer frame={frame} moving={moving}/>
    </div>;
}
/** Requested ChatGPT desktop look. The persistent concept badge and caption are
 * intentional: Satelle has no ChatGPT installer or remote MCP bridge. */
class ChatViewport extends React.Component<data.SceneProps & {
    children: React.ReactNode;
}> {
    private viewport: HTMLDivElement | null = null;
    private content: HTMLDivElement | null = null;
    private target = 0;
    private from = 0;
    private changedAt = 0;
    private lastElapsed = -1;
    componentDidMount() { this.syncScroll(); }
    componentDidUpdate() { this.syncScroll(); }
    syncScroll() {
        if (!this.viewport || !this.content)
            return;
        const elapsed = this.props.frame.elapsed;
        const target = Math.max(0, this.content.scrollHeight - this.viewport.clientHeight);
        const reset = elapsed < this.lastElapsed || this.lastElapsed < 0 || (!this.props.moving && elapsed !== this.lastElapsed);
        if (reset) {
            this.viewport.scrollTop = target;
            this.from = target;
            this.target = target;
            this.changedAt = elapsed;
        }
        else {
            if (target !== this.target) {
                this.from = this.viewport.scrollTop;
                this.target = target;
                this.changedAt = elapsed;
            }
            const p = Math.min(1, Math.max(0, (elapsed - this.changedAt) / 420));
            this.viewport.scrollTop = this.from + (this.target - this.from) * data.ease(p);
        }
        this.lastElapsed = elapsed;
    }
    render() {
        return <div className="wf-gpt-scroll" ref={(node) => { this.viewport = node; }}>
        <div className="wf-gpt-thread" ref={(node) => { this.content = node; }}>
        {this.props.children}
        </div>
        </div>;
    }
}
export function ChatScene({ frame, moving }: data.SceneProps) {
    const c = frame.committed;
    return <div className="wf-stage wf-chatgpt">
    <div className="wf-gpt-side">
    <ui.Lights />
    <div className="wf-gpt-side-icons">
    <ui.Brand name="chatgpt"/>
    <ui.Icon name="edit"/>
    </div>
    <span>
    <ui.Icon name="edit"/>
    {" New chat"}
    </span>
    <span>
    <ui.Icon name="search"/>
    {" Search chats"}
    </span>
    <span>
    <ui.Icon name="grid"/>
    {" Library"}
    </span>
    <small>
    {"Today"}
    </small>
    <span className="wf-gpt-selected">
    {"Your computers"}
    </span>
    <span>
    {"Website QA"}
    </span>
    <span>
    {"Monthly reporting"}
    </span>
    <div className="wf-gpt-user">
    <ui.Photo variant="old"/>
    {"You"}
    </div>
    </div>
    <div className="wf-gpt-main">
    <div className="wf-gpt-top">
    <strong>
    {"ChatGPT "}
    <span>
    {"\u2304"}
    </span>
    </strong>
    <span className="wf-concept">
    {"Integration concept"}
    </span>
    <ui.Icon name="edit"/>
    </div>
    <ChatViewport frame={frame} moving={moving}>
    <div className="wf-gpt-bubble">
    {data.typed(data.PROMPTS.hosts, frame, 0, 1500) || '\u00a0'}
    </div>
    {c >= 1 && <div className="wf-gpt-tool">
    <span className="wf-satelle-mark">
    {"\u2197"}
    </span>
    {" Satelle "}
    <span>
    {"\u00B7"}
    </span>
    {" Check configuration "}
    <span>
    {"\u2304"}
    </span>
    </div>}
    {c >= 2 && <div className="wf-gpt-answer">
    <p>
    {"Your configuration lists two Hosts:"}
    </p>
    <div className="wf-gpt-hosts">
    {[['studio-mac', 'macOS'], ['ops-pc', 'Windows']].map(([host, os]) => <div key={host}>
    <ui.Icon name="monitor"/>
    <span>
    <b>
    {host}
    </b>
    <small>
    {os}
    </small>
    </span>
    <em>
    {"Configured"}
    </em>
    </div>)}
    </div>
    <small>
    {"Reachability and native readiness are checked separately."}
    </small>
    </div>}
    {frame.step >= 3 && <div className="wf-gpt-bubble">
    {data.typed(data.PROMPTS.chat, frame, 3, 2300) || '\u00a0'}
    </div>}
    {c >= 4 && c < 6 && <div className="wf-gpt-approval">
    <b>
    {"Allow Satelle to start this task?"}
    </b>
    <p>
    {"Use studio-mac to update your Slack profile photo."}
    </p>
    <div>
    <span>
    {"Decline"}
    </span>
    <span data-cursor="chat-confirm" className="wf-gpt-confirm">
    {c >= 5 ? 'Confirmed ✓' : 'Confirm'}
    </span>
    </div>
    </div>}
    {c >= 6 && <div className="wf-gpt-answer wf-gpt-result">
    <span>
    {"\u2713"}
    </span>
    <div>
    <b>
    {"Task admitted on studio-mac."}
    </b>
    <p>
    {"The Host reports "}
    <code>
    {"starting"}
    </code>
    {". It is not a completed task yet."}
    </p>
    </div>
    </div>}
    </ChatViewport>
    <div className="wf-gpt-composer">
    <span>
    {"Message ChatGPT"}
    </span>
    <div>
    <span>
    {"\uFF0B"}
    </span>
    <span className="wf-gpt-chip">
    {"\u2197 Satelle \u00B7 concept"}
    </span>
    <i>
    {"\u2191"}
    </i>
    </div>
    </div>
    <div className="wf-gpt-fine">
    {"Concept requires a remote MCP bridge. Not shipped."}
    </div>
    </div>
    <ui.Pointer frame={frame} moving={moving}/>
    </div>;
}
/** Compact/classic Claude Code renderer: Clawd, ANSI-like transcript, prompt
 * rules and MCP tool output. A DOM reenactment, not a captured terminal session. */
function ClaudeTerminal({ frame }: Pick<data.SceneProps, "frame">) {
    const sent = frame.committed >= 1;
    return <div className="wf-claude-window">
    <div className="wf-claude-bar">
    <ui.Lights />
    <span>
    {"claude \u2014 ~/work/reports"}
    </span>
    <span>
    {"\u2318 1"}
    </span>
    </div>
    <div className="wf-claude-content">
    <div className="wf-claude-welcome">
    <pre>
    {' ▐▛███▜▌\n▝▜█████▛▘\n  ▘▘ ▝▝'}
    </pre>
    <div>
    <strong>
    {"Claude Code"}
    </strong>
    <span>
    {"Welcome back!"}
    </span>
    <small>
    {"~/work/reports"}
    </small>
    </div>
    </div>
    <div className="wf-claude-request">
    <span>
    {"\u276F"}
    </span>
    <div>
    {data.typed(data.PROMPTS.transfer, frame, 0, 3300)}
    {frame.step === 0 && <i className="wf-type-caret"/>}
    </div>
    </div>
    {sent && <div className="wf-claude-transcript">
    <p>
    <b>
    {"\u25CF"}
    </b>
    {" I\u2019ll use Satelle to run this on ops-pc."}
    </p>
    <p>
    <b>
    {"\u25CF"}
    </b>
    {" "}
    <strong>
    {"satelle - run (MCP)"}
    </strong>
    <br />
    <span className="wf-claude-args">
    {"(host: \"ops-pc\", detach: true)"}
    </span>
    </p>
    <p className="wf-claude-output">
    {"\u23BF \u00A0"}
    {'{ "status": "starting", … }'}
    <br />
    {"\u00A0\u00A0\u00A0Result excerpt \u00B7 task admitted"}
    </p>
    </div>}
    <div className="wf-claude-bottom">
    <div className="wf-claude-working">
    {sent ? '✻ Working…' : '\u00a0'}
    </div>
    <div className="wf-claude-input">
    {"\u276F "}
    <i className="wf-type-caret"/>
    </div>
    <small>
    {sent ? 'esc to interrupt' : '? for shortcuts'}
    </small>
    </div>
    </div>
    </div>;
}
function Analytics({ c }: {
    c: number;
}) {
    return <div className="wf-google-app wf-analytics">
    <div className="wf-google-top">
    <ui.Brand name="analytics"/>
    <strong>
    {"Analytics"}
    </strong>
    <span>
    {"Satelle \u00B7 sample property"}
    </span>
    <ui.Icon name="search"/>
    </div>
    <div className="wf-google-layout">
    <aside>
    <span>
    {"\u2302 Home"}
    </span>
    <b>
    {"\u25A4 Reports"}
    </b>
    <span>
    {"Reports snapshot"}
    </span>
    <small>
    {"Life cycle"}
    </small>
    <span>
    {"Acquisition \u2304"}
    </span>
    <b data-cursor="ga-report" className="wf-google-selected">
    {"Traffic acquisition"}
    </b>
    <span>
    {"Engagement"}
    </span>
    <span>
    {"Monetization"}
    </span>
    </aside>
    <div className="wf-analytics-report">
    <div className="wf-ga-mobile-nav" data-cursor="ga-report">
    {"Reports "}
    <span>
    {"\u203A Traffic acquisition"}
    </span>
    </div>
    <div className="wf-report-heading">
    <h4>
    {c >= 3 ? 'Traffic acquisition' : 'Reports snapshot'}
    </h4>
    <span data-cursor="ga-share">
    <ui.Icon name="share"/>
    </span>
    </div>
    <div className="wf-date-range">
    {"Aug 1 \u2013 Aug 31 "}
    <span>
    {"\u2304"}
    </span>
    </div>
    <div className="wf-ga-metrics">
    <div>
    <span>
    {"Sessions"}
    </span>
    <strong>
    {"12,480"}
    </strong>
    </div>
    <div>
    <span>
    {"Engaged sessions"}
    </span>
    <strong>
    {"9,210"}
    </strong>
    </div>
    </div>
    <div className="wf-ga-chart">
    <span>
    {"Sessions over time"}
    </span>
    <svg viewBox="0 0 400 85" preserveAspectRatio="none">
    <path d="M0 20H400M0 45H400M0 70H400" stroke="currentColor" fill="none"/>
    <path d="m0 65 20-7 18 4 22-23 20 8 18-8 20 14 20-26 20 9 20-17 20 19 20-14 20 8 20-13 20 16 20-26 20 13 22-12 20-8 20 9" fill="none" stroke="var(--sa-12)" strokeWidth="2.5"/>
    </svg>
    <div>
    <small>
    {"01 Aug"}
    </small>
    <small>
    {"15 Aug"}
    </small>
    <small>
    {"31 Aug"}
    </small>
    </div>
    </div>
    <div className="wf-ga-table">
    <div>
    <b>
    {"Channel group"}
    </b>
    <b>
    {"Sessions"}
    </b>
    </div>
    {[['Organic Search', '5,340'], ['Direct', '4,210'], ['Referral', '2,930']].map(([a, b]) => <div key={a}>
    <span>
    {a}
    </span>
    <span>
    {b}
    </span>
    </div>)}
    </div>
    </div>
    </div>
    {c === 4 && <div className="wf-ga-share">
    <b>
    {"Share this report"}
    </b>
    <span>
    {"Share Link "}
    <ui.Icon name="share"/>
    </span>
    <span data-cursor="ga-download">
    {"Download File "}
    <ui.Icon name="download"/>
    </span>
    </div>}
    {c === 5 && <div className="wf-ga-share">
    <b>
    {"Download File"}
    </b>
    <span>
    {"Download PDF"}
    </span>
    <span data-cursor="ga-csv">
    {"Download CSV "}
    <ui.Icon name="download"/>
    </span>
    <span>
    {"Export to Google Sheets"}
    </span>
    </div>}
    {c >= 6 && <div className="wf-download-toast">
    <ui.Icon name="file"/>
    <div>
    <b>
    {data.REPORT_FILE}
    </b>
    <small>
    {"Done \u00B7 saved to Downloads"}
    </small>
    </div>
    <span>
    {"\u2713"}
    </span>
    </div>}
    </div>;
}
function Drive({ frame }: Pick<data.SceneProps, "frame">) {
    const c = frame.committed;
    const inside = c >= 8;
    const uploading = c >= 12;
    return <div className="wf-google-app wf-drive">
    <div className="wf-google-top">
    <ui.Brand name="drive"/>
    <strong>
    {"Drive"}
    </strong>
    <div className="wf-drive-search">
    <ui.Icon name="search"/>
    {"Search in Drive"}
    </div>
    <span className="wf-google-avatar">
    {"Y"}
    </span>
    </div>
    <div className="wf-google-layout">
    <aside>
    <span data-cursor="drive-new" className="wf-drive-new">
    {"\uFF0B New"}
    </span>
    <span>
    {"\u2302 Home"}
    </span>
    <b>
    {"\u25A3 My Drive"}
    </b>
    <span>
    {"Shared with me"}
    </span>
    <span>
    {"\u25F7 Recent"}
    </span>
    <span>
    {"\u2606 Starred"}
    </span>
    <span>
    {"\u2672 Trash"}
    </span>
    </aside>
    <div className="wf-drive-files">
    <div className="wf-drive-breadcrumb">
    {"My Drive "}
    <span>
    {"\u203A"}
    </span>
    {" "}
    {inside && 'Reports'}
    </div>
    <div className="wf-drive-filters">
    <span>
    {"Type \u2304"}
    </span>
    <span>
    {"People \u2304"}
    </span>
    <span>
    {"Modified \u2304"}
    </span>
    </div>
    <div className="wf-drive-table">
    <div className="wf-drive-table-head">
    <span>
    {"Name"}
    </span>
    <span>
    {"Owner"}
    </span>
    <span>
    {"Modified"}
    </span>
    </div>
    {!inside ? <div data-cursor="drive-folder">
    <span>
    <ui.Icon name="folder"/>
    <b>
    {"Reports"}
    </b>
    </span>
    <span>
    {"me"}
    </span>
    <span>
    {"Today"}
    </span>
    </div> : <React.Fragment>
    <div>
    <span>
    <ui.Icon name="folder"/>
    <b>
    {"Archive"}
    </b>
    </span>
    <span>
    {"me"}
    </span>
    <span>
    {"Aug 31"}
    </span>
    </div>
    {uploading && <div className="wf-drive-uploaded">
    <span>
    <ui.Icon name="file"/>
    <b>
    {data.REPORT_FILE}
    </b>
    </span>
    <span>
    {"me"}
    </span>
    <span>
    {"Today"}
    </span>
    </div>}
    </React.Fragment>}
    </div>
    <small className="wf-sample-data">
    {"Sample account and files"}
    </small>
    </div>
    </div>
    {c === 9 && <div className="wf-drive-menu">
    <span>
    <ui.Icon name="folder"/>
    {"New folder"}
    </span>
    <span data-cursor="drive-upload">
    <ui.Icon name="upload"/>
    {"File upload"}
    </span>
    <span>
    <ui.Icon name="folder"/>
    {"Folder upload"}
    </span>
    </div>}
    {c >= 10 && c < 12 && <div className="wf-modal-shade">
    <div className="wf-file-picker wf-windows-picker">
    <header>
    <span>
    <ui.Icon name="folder"/>
    {"Open"}
    </span>
    <span>
    {"\u00D7"}
    </span>
    </header>
    <div className="wf-picker-toolbar">
    {"\u2039 \u00A0 \u203A \u00A0 \u2191 "}
    <b>
    {"Downloads"}
    </b>
    <ui.Icon name="search"/>
    </div>
    <div className="wf-picker-body">
    <aside>
    <span>
    {"Home"}
    </span>
    <span>
    {"Desktop"}
    </span>
    <b>
    {"Downloads"}
    </b>
    <span>
    {"Documents"}
    </span>
    <span>
    {"Pictures"}
    </span>
    </aside>
    <div className="wf-picker-files">
    <div className="wf-file-list-head">
    {"Name "}
    <span>
    {"Type"}
    </span>
    </div>
    <div data-cursor="transfer-file" className="wf-file-list-row" data-selected={c >= 11}>
    <ui.Icon name="file"/>
    <span>
    {data.REPORT_FILE}
    </span>
    <small>
    {"CSV file"}
    </small>
    </div>
    </div>
    </div>
    <footer>
    <div>
    {"File name: "}
    <span>
    {c >= 11 ? data.REPORT_FILE : ''}
    </span>
    </div>
    <span>
    {"Cancel"}
    </span>
    <span className="wf-native-primary" data-cursor="transfer-open">
    {"Open"}
    </span>
    </footer>
    </div>
    </div>}
    {uploading && <div className="wf-drive-progress">
    <div>
    <b>
    {c >= 13 ? '1 upload complete' : 'Uploading 1 item'}
    </b>
    <span>
    {"\u2304 \u00A0 \u00D7"}
    </span>
    </div>
    <p>
    <ui.Icon name="file"/>
    {data.REPORT_FILE}
    <span>
    {c >= 13 ? '✓' : ''}
    </span>
    </p>
    {c < 13 && <i>
    <i style={{ width: `${data.phase(frame, 12, 1200, data.COMMIT_DELAY) * 100}%` }}/>
    </i>}
    </div>}
    </div>;
}
export function TransferScene({ frame, moving }: data.SceneProps) {
    const handoff = data.ease(data.phase(frame, 2, 1100));
    const c = frame.committed;
    return <div className="wf-stage wf-transfer">
    <div className="wf-host-window" style={{ opacity: handoff, transform: `translateY(${18 * (1 - handoff)}px) scale(${0.96 + 0.04 * handoff})` }}>
    <div className="wf-host-title">
    <ui.Icon name="monitor"/>
    <b>
    {"ops-pc"}
    </b>
    <span>
    {"Windows \u00B7 Host browser"}
    </span>
    </div>
    <div className="wf-browser-tabs">
    <span data-active={c < 7}>
    <ui.Brand name="analytics"/>
    {"Analytics "}
    <i>
    {"\u00D7"}
    </i>
    </span>
    <span data-cursor="drive-tab" data-active={c >= 7}>
    <ui.Brand name="drive"/>
    {"Google Drive "}
    <i>
    {"\u00D7"}
    </i>
    </span>
    <span>
    {"\uFF0B"}
    </span>
    </div>
    <ui.Chrome url={c >= 7 ? data.SITES.drive : data.SITES.analytics}/>
    <div className="wf-host-content">
    {c >= 7 ? <Drive frame={frame}/> : <Analytics c={c}/>}
    </div>
    <div className="wf-minimized-terminal">
    <span>
    {"\u276F"}
    </span>
    {" Claude Code "}
    <i>
    {"\u00B7"}
    </i>
    {" Task admitted on ops-pc "}
    <span>
    {"\u2199"}
    </span>
    </div>
    </div>
    <div className="wf-terminal-layer" style={{ opacity: 1 - handoff, visibility: handoff === 1 ? 'hidden' : 'visible', transform: `translate(${handoff * -31}%,${handoff * 36}%) scale(${1 - handoff * .78})` }}>
    <ClaudeTerminal frame={frame}/>
    </div>
    <ui.Pointer frame={frame} moving={moving}/>
    </div>;
}
function SlackProfile({ saved }: {
    saved: boolean;
}) {
    return <div className="wf-slack-profile">
    <header>
    <b>
    {"Profile"}
    </b>
    <span>
    {"\u00D7"}
    </span>
    </header>
    <div className="wf-slack-profile-photo">
    <ui.Photo variant={saved ? 'new' : 'old'}/>
    </div>
    <div className="wf-slack-profile-name">
    <h4>
    {"You"}
    </h4>
    <span data-cursor="slack-edit">
    {"Edit"}
    </span>
    </div>
    <p>
    {"\u25CF Active"}
    </p>
    <small>
    {"Profile photo"}
    </small>
    <div className="wf-slack-profile-actions">
    <span>
    {"Set a status"}
    </span>
    <span>
    {"View as"}
    </span>
    </div>
    {saved && <div className="wf-slack-saved">
    {"\u2713 Profile updated"}
    </div>}
    </div>;
}
function EditProfile({ c }: {
    c: number;
}) {
    return <div className="wf-edit-profile">
    <header>
    <b>
    {"Edit your profile"}
    </b>
    <span>
    {"\u00D7"}
    </span>
    </header>
    <div className="wf-edit-profile-body">
    <div className="wf-slack-fields">
    <label>
    {"Full name"}
    <span>
    {"You"}
    </span>
    </label>
    <label>
    {"Display name"}
    <span>
    {"You"}
    </span>
    </label>
    <label>
    {"What I do"}
    <span>
    {"Product & design"}
    </span>
    </label>
    <small>
    {"Your profile is visible to your workspace."}
    </small>
    </div>
    <div className="wf-slack-edit-photo">
    <b>
    {"Profile photo"}
    </b>
    <ui.Photo variant={c >= 9 ? 'new' : 'old'}/>
    <span data-cursor="slack-upload">
    {"Upload Photo"}
    </span>
    <small>
    {"JPG, PNG or GIF"}
    </small>
    </div>
    </div>
    <footer>
    <span>
    {"Cancel"}
    </span>
    <span className="wf-slack-primary" data-cursor="slack-save">
    {"Save Changes"}
    </span>
    </footer>
    </div>;
}
function PhotoPicker({ c }: {
    c: number;
}) {
    return <div className="wf-file-picker wf-mac-picker">
    <header>
    <ui.Lights />
    <b>
    {"Choose a photo"}
    </b>
    <span>
    {"\u00D7"}
    </span>
    </header>
    <div className="wf-picker-toolbar">
    {"\u2039 \u00A0 \u203A "}
    <b>
    {c >= 5 ? 'Pictures' : 'Recents'}
    </b>
    <ui.Icon name="search"/>
    </div>
    <div className="wf-picker-body">
    <aside>
    <small>
    {"Favorites"}
    </small>
    <span>
    {"Recents"}
    </span>
    <span>
    {"Applications"}
    </span>
    <span>
    {"Desktop"}
    </span>
    <span>
    {"Documents"}
    </span>
    <span>
    {"Downloads"}
    </span>
    <b data-cursor="slack-pictures" data-selected={c >= 5}>
    {"Pictures"}
    </b>
    </aside>
    <div className="wf-photo-files">
    {c >= 5 ? <React.Fragment>
    {[[data.PHOTO_FILE, 'new'], ['cover.png', 'alt'], ['previous.png', 'old']].map(([name, variant]) => <div key={name} data-cursor={name === data.PHOTO_FILE ? 'slack-file' : undefined} data-selected={c >= 6 && name === data.PHOTO_FILE}>
    <ui.Photo variant={variant}/>
    <span>
    {name}
    </span>
    </div>)}
    </React.Fragment> : <div className="wf-picker-help">
    <ui.Icon name="photo" size={30}/>
    <p>
    {"Choose an image from Pictures."}
    </p>
    </div>}
    </div>
    </div>
    <footer>
    <span>
    {"Cancel"}
    </span>
    <span className="wf-native-primary" data-cursor="slack-open">
    {"Open"}
    </span>
    </footer>
    </div>;
}
function CropPhoto({ frame }: Pick<data.SceneProps, "frame">) {
    const zoom = data.ease(data.phase(frame, 8, 1000, data.COMMIT_DELAY));
    return <div className="wf-crop-modal">
    <header>
    <b>
    {"Crop your photo"}
    </b>
    <span>
    {"\u00D7"}
    </span>
    </header>
    <div className="wf-crop-preview">
    <div style={{ transform: `scale(${1 + zoom * .2})` }}>
    <ui.Photo />
    </div>
    <div className="wf-crop-grid"/>
    </div>
    <div className="wf-crop-slider" data-cursor="slack-crop">
    <span>
    {"\u2212"}
    </span>
    <i>
    <i style={{ width: `${35 + zoom * 25}%` }}/>
    <b style={{ left: `${35 + zoom * 25}%` }}/>
    </i>
    <span>
    {"\uFF0B"}
    </span>
    </div>
    <footer>
    <span>
    {"Cancel"}
    </span>
    <span className="wf-slack-primary" data-cursor="slack-crop-save">
    {"Save"}
    </span>
    </footer>
    </div>;
}
export function SlackScene({ frame, moving }: data.SceneProps) {
    const c = frame.committed;
    const saved = c >= 10;
    return <div className="wf-stage wf-slack">
    <div className="wf-slack-top">
    <ui.Lights />
    <span>
    {"\u2039 \u00A0 \u203A"}
    </span>
    <div>
    <ui.Icon name="search"/>
    {"Search Satelle"}
    </div>
    <span>
    {"?"}
    </span>
    </div>
    <div className="wf-slack-layout">
    <div className="wf-slack-rail">
    <ui.Brand name="slack"/>
    <span className="wf-slack-home">
    <ui.Icon name="home"/>
    {"Home"}
    </span>
    <span>
    <ui.Icon name="chat"/>
    {"DMs"}
    </span>
    <span>
    <ui.Icon name="issue"/>
    {"Activity"}
    </span>
    <span>
    {"\u2022\u2022\u2022"}
    <small>
    {"More"}
    </small>
    </span>
    <div className="wf-slack-you" data-cursor="slack-account">
    <ui.Photo variant={saved ? 'new' : 'old'}/>
    <i />
    </div>
    </div>
    <aside className="wf-slack-sidebar">
    <strong>
    {"Satelle \u2304"}
    </strong>
    <span>
    {"Threads"}
    </span>
    <span>
    {"Drafts & sent"}
    </span>
    <small>
    {"\u25BE Channels"}
    </small>
    <span className="wf-slack-channel">
    {"# \u00A0design"}
    </span>
    <span>
    {"# \u00A0general"}
    </span>
    <span>
    {"# \u00A0engineering"}
    </span>
    <small>
    {"\u25BE Direct messages"}
    </small>
    <span>
    {"You (you)"}
    </span>
    </aside>
    <div className="wf-slack-channel-body">
    <header>
    {"# \u00A0design "}
    <span>
    {"\u2315 \u00A0 \u25C9"}
    </span>
    </header>
    <div className="wf-slack-channel-tabs">
    {"Messages \u00A0 Files \u00A0 \uFF0B"}
    </div>
    <div className="wf-slack-message">
    <ui.Photo variant="old"/>
    <div>
    <strong>
    {"You "}
    <small>
    {"9:41"}
    </small>
    </strong>
    <p>
    {"Keeping the workspace up to date."}
    </p>
    </div>
    </div>
    <div className="wf-slack-compose">
    {"Message #design"}
    <div>
    {"B \u00A0 I \u00A0 \u2637 \u00A0 \u2197 "}
    <span>
    {"\u27A4"}
    </span>
    </div>
    </div>
    </div>
    {c >= 2 && <SlackProfile saved={saved}/>}
    </div>
    {c === 0 && <div className="wf-slack-request">
    <ui.Prompt text={data.typed(data.PROMPTS.slack, frame, 0, 2300)}/>
    </div>}
    {c === 1 && <div className="wf-slack-account-menu">
    <div>
    <ui.Photo variant="old"/>
    <span>
    <b>
    {"You"}
    </b>
    <small>
    {"\u25CF Active"}
    </small>
    </span>
    </div>
    <span>
    {"Set a status"}
    </span>
    <span data-cursor="slack-profile">
    {"Profile"}
    </span>
    <span>
    {"Preferences"}
    </span>
    <span>
    {"Set yourself as away"}
    </span>
    </div>}
    {c >= 3 && c < 10 && <div className="wf-modal-shade">
    <EditProfile c={c}/>
    </div>}
    {c >= 4 && c <= 6 && <div className="wf-modal-shade wf-front">
    <PhotoPicker c={c}/>
    </div>}
    {c >= 7 && c <= 8 && <div className="wf-modal-shade wf-front">
    <CropPhoto frame={frame}/>
    </div>}
    <ui.Pointer frame={frame} moving={moving}/>
    </div>;
}
export { ToolDetails } from "./workflow-ui";
