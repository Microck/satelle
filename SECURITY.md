# Security policy

Satelle controls visible desktops and handles Host authentication, provider
credential references, prompts, and durable execution state. Treat suspected
security issues as private until a fix and disclosure plan are ready.

## Supported versions

Satelle has not published a public release. Security fixes currently target the
latest commit on the default branch. Include the exact commit or `satelle
--version` output in a report so the affected code can be identified.

## Report a vulnerability

Email `contact@micr.dev` with the subject `Satelle security report`. Do not open
a public issue for a suspected vulnerability.

Include only the information needed to reproduce and assess the problem:

- The affected Satelle commit or version and Controller/Host platforms.
- The transport in use: local, direct HTTPS/WSS, or SSH tunnel.
- The security boundary that was crossed or could be crossed.
- Minimal reproduction steps and the observed result.
- Whether credentials, desktop content, prompts, or durable state were exposed.
- Any temporary mitigation already applied.

Do not send live bearer tokens, provider secrets, private keys, raw credential
store values, or full configuration files. Replace them with clearly marked
placeholders. If a minimal encrypted artifact is necessary, first request a
safe transfer method in the report.

## Handle diagnostics safely

Normal Satelle logs are designed to exclude raw provider secrets, prompts,
transcripts, and desktop content. They can still contain sensitive operational
metadata such as Host aliases, Session identifiers, usernames, filesystem
paths, network names, error details, and timing information.

Before sharing diagnostic output:

1. Reproduce with the narrowest command and scope that demonstrates the issue.
2. Remove bearer tokens, authorization headers, Secret Source values, private
   keys, certificates that identify a private deployment, and provider secrets.
3. Redact Host aliases, usernames, addresses, tailnet names, Session identifiers,
   local paths, prompts, transcripts, and desktop content unless essential.
4. State what was redacted and whether the output came from a Controller or
   Host.
5. Send the result only through the private reporting channel.

`--verbose`, `--json`, and event output are not diagnostic-export consent.
Support bundle export is not implemented in this release; do not substitute an
unreviewed archive of Satelle state directories.

## Security boundaries in scope

Reports are especially useful when they involve:

- Authentication or authorization bypass across API Principal scopes.
- Host identity, TLS, CA bundle, bearer-token, or SSH tunnel confusion.
- Unsafe file ownership, permissions, replacement, or secret persistence.
- Project configuration gaining user-level trust or mutation authority.
- YOLO or approval behavior exceeding its documented Turn boundary.
- Session isolation, idempotency, lease ownership, or durable-state corruption.
- Prompt, provider credential, transcript, screenshot, or desktop-content leaks.
- Path traversal, command injection, archive extraction, or update integrity.

Operational failures without a security impact can use a normal issue after all
sensitive data is removed. General feature requests and public design questions
do not belong in the private security channel.

## Disclosure

The maintainer will validate the report against the current source, coordinate
a fix when needed, and agree on public disclosure timing with the reporter.
Please avoid public discussion until that coordination is complete.
