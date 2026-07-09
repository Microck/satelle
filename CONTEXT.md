# Satelle Control Context

Satelle coordinates durable Computer Use work on an operator-controlled Host while keeping live observation distinct from authoritative state and retained diagnostics.

## Language

**Satelle Event**:
A live, non-durable lifecycle observation emitted for a Session or Turn. Its sequence number orders one consumer stream only and is never a replay cursor.
_Avoid_: Stored event, event record

**Event State Subject**:
The committed Session or Turn revision described by a lifecycle Satelle Event. It lets a consumer relate a live observation to authoritative durable state.
_Avoid_: Event target, resource version

**Live Event Subscription**:
One WebSocket connection's complete current set of host, Session, or Turn scopes. A new subscribe message replaces the set atomically and does not replay earlier events.
_Avoid_: Watch, listener registration

**Log Cursor**:
An opaque durable position in normalized retained Host logs. It resumes log delivery but never resumes Satelle Events.
_Avoid_: Event cursor, WebSocket resume token

**Host Scope**:
A Live Event Subscription scope that selects every authorized Session and Turn lifecycle event produced by one Host Identity.
_Avoid_: Global scope
