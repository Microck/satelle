use super::{
    PublicSession, PublicSnapshotError, PublicTurn, SafeSummary, SessionActivity,
    SessionStateRevision, TurnState, TurnStateRevision, terminal_summary_matches,
};
use crate::{SessionId, TurnId};
use serde::{Deserialize, Deserializer};
use std::collections::HashSet;
use time::OffsetDateTime;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PublicTurnWire {
    session_id: SessionId,
    turn_id: TurnId,
    turn_state_revision: TurnStateRevision,
    state: TurnState,
    #[serde(with = "time::serde::rfc3339")]
    started_at: OffsetDateTime,
    #[serde(with = "time::serde::rfc3339")]
    updated_at: OffsetDateTime,
    #[serde(with = "time::serde::rfc3339::option")]
    terminal_at: Option<OffsetDateTime>,
    #[serde(deserialize_with = "Option::deserialize")]
    safe_summary: Option<SafeSummary>,
}

impl<'de> Deserialize<'de> for PublicTurn {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let wire = PublicTurnWire::deserialize(deserializer)?;
        let turn = Self {
            session_id: wire.session_id,
            turn_id: wire.turn_id,
            turn_state_revision: wire.turn_state_revision,
            state: wire.state,
            started_at: wire.started_at,
            updated_at: wire.updated_at,
            terminal_at: wire.terminal_at,
            safe_summary: wire.safe_summary,
        };
        validate_turn(&turn).map_err(serde::de::Error::custom)?;
        Ok(turn)
    }
}

fn validate_turn(turn: &PublicTurn) -> Result<(), &'static str> {
    if turn.started_at > turn.updated_at {
        return Err("a public Turn starts after its update time");
    }
    if (turn.state == TurnState::Starting) != (turn.turn_state_revision.get() == 1) {
        return Err("a public Turn state contradicts its revision");
    }
    if turn.state.is_terminal() {
        if turn.terminal_at != Some(turn.updated_at) {
            return Err("a terminal public Turn has incoherent terminal time");
        }
        if !terminal_summary_matches(turn.state, turn.safe_summary) {
            return Err("a terminal public Turn has incoherent safe summary");
        }
    } else if turn.terminal_at.is_some() || turn.safe_summary.is_some() {
        return Err("a nonterminal public Turn contains terminal metadata");
    }
    Ok(())
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PublicSessionWire {
    session_id: SessionId,
    #[serde(deserialize_with = "Option::deserialize")]
    display_name: Option<String>,
    session_state_revision: SessionStateRevision,
    #[serde(with = "time::serde::rfc3339")]
    created_at: OffsetDateTime,
    #[serde(with = "time::serde::rfc3339")]
    updated_at: OffsetDateTime,
    activity: SessionActivity,
    turns: Vec<PublicTurn>,
}

impl<'de> Deserialize<'de> for PublicSession {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let wire = PublicSessionWire::deserialize(deserializer)?;
        Self::try_from_parts(
            wire.session_id,
            wire.display_name,
            wire.session_state_revision,
            wire.created_at,
            wire.updated_at,
            wire.activity,
            wire.turns,
        )
        .map_err(serde::de::Error::custom)
    }
}

impl PublicSession {
    pub(crate) fn try_from_parts(
        session_id: SessionId,
        display_name: Option<String>,
        session_state_revision: SessionStateRevision,
        created_at: OffsetDateTime,
        updated_at: OffsetDateTime,
        activity: SessionActivity,
        turns: Vec<PublicTurn>,
    ) -> Result<Self, PublicSnapshotError> {
        let session = Self {
            session_id,
            display_name,
            session_state_revision,
            created_at,
            updated_at,
            activity,
            turns,
        };
        validate_session(&session).map_err(|_| PublicSnapshotError)?;
        Ok(session)
    }
}

fn validate_session(session: &PublicSession) -> Result<(), &'static str> {
    if session.turns.is_empty() {
        return Err("a public Session requires Turn history");
    }
    if session.created_at > session.updated_at {
        return Err("a public Session starts after its update time");
    }

    let mut seen_turn_ids = HashSet::with_capacity(session.turns.len());
    let mut active_turn = None;
    let mut revision_sum = 0_u64;
    let mut previous_updated_at = None;

    for (index, turn) in session.turns.iter().enumerate() {
        if turn.session_id != session.session_id {
            return Err("a public Turn belongs to a different Session");
        }
        if !seen_turn_ids.insert(&turn.turn_id) {
            return Err("a public Session contains a duplicate Turn identifier");
        }
        if turn.started_at < session.created_at || turn.updated_at > session.updated_at {
            return Err("a public Turn timestamp is outside its Session bounds");
        }
        if index == 0 && turn.started_at != session.created_at {
            return Err("the first public Turn does not start with its Session");
        }
        if previous_updated_at.is_some_and(|previous| turn.started_at < previous) {
            return Err("public Turn history moves backwards in time");
        }
        previous_updated_at = Some(turn.updated_at);
        if !turn.state.is_terminal() && active_turn.replace((index, turn)).is_some() {
            return Err("a public Session contains more than one active Turn");
        }
        revision_sum = revision_sum
            .checked_add(turn.turn_state_revision.get())
            .ok_or("public Session revision sum overflow")?;
    }

    if active_turn.is_some_and(|(index, _)| index + 1 != session.turns.len()) {
        return Err("an active public Turn is not last in history");
    }
    if revision_sum != session.session_state_revision.get() {
        return Err("a public Session revision contradicts its Turn revisions");
    }
    if session.turns.last().map(|turn| turn.updated_at) != Some(session.updated_at) {
        return Err("a public Session update time differs from its latest Turn");
    }

    let expected_activity = match active_turn {
        None => SessionActivity::Idle,
        Some((_, turn)) => match turn.state {
            TurnState::Starting => SessionActivity::Starting {
                turn_id: turn.turn_id.clone(),
                turn_state_revision: turn.turn_state_revision,
            },
            TurnState::Running => SessionActivity::Running {
                turn_id: turn.turn_id.clone(),
                turn_state_revision: turn.turn_state_revision,
            },
            TurnState::RecoveryPending => SessionActivity::RecoveryPending {
                turn_id: turn.turn_id.clone(),
                turn_state_revision: turn.turn_state_revision,
            },
            TurnState::Completed | TurnState::Blocked | TurnState::Failed | TurnState::Stopped => {
                return Err("a terminal public Turn was selected as active");
            }
        },
    };
    if session.activity != expected_activity {
        return Err("public Session activity contradicts Turn history");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::{Value, json};

    const SESSION_ID: &str = "rs_01890a5d-ac96-7b7c-8f89-37c3d0a66e11";
    const OTHER_SESSION_ID: &str = "rs_01890a5d-ac96-7b7c-8f89-37c3d0a66e12";
    const TURN_ID: &str = "rt_01890a5d-ac96-7b7c-8f89-37c3d0a66e21";

    fn starting_session() -> Value {
        json!({
            "session_id": SESSION_ID,
            "display_name": null,
            "session_state_revision": 1,
            "created_at": "2024-01-01T00:00:00Z",
            "updated_at": "2024-01-01T00:00:00Z",
            "activity": {
                "state": "starting",
                "turn_id": TURN_ID,
                "turn_state_revision": 1
            },
            "turns": [{
                "session_id": SESSION_ID,
                "turn_id": TURN_ID,
                "turn_state_revision": 1,
                "state": "starting",
                "started_at": "2024-01-01T00:00:00Z",
                "updated_at": "2024-01-01T00:00:00Z",
                "terminal_at": null,
                "safe_summary": null
            }]
        })
    }

    #[test]
    fn public_session_deserialization_accepts_one_coherent_snapshot() {
        let expected = starting_session();
        let session = serde_json::from_value::<PublicSession>(expected.clone())
            .expect("decode coherent public Session");
        assert_eq!(session.session_id().as_str(), SESSION_ID);
        assert_eq!(
            serde_json::to_value(session).expect("serialize public Session"),
            expected,
            "public lifecycle serialization must not expose private upstream or policy fields"
        );
    }

    #[test]
    fn public_turn_requires_nullable_metadata_fields() {
        for field in ["terminal_at", "safe_summary"] {
            let mut wire = starting_session();
            let turn = wire["turns"][0]
                .as_object_mut()
                .expect("starting Session contains a Turn object");
            assert!(
                turn.remove(field).is_some(),
                "fixture must contain nullable field {field}"
            );
            assert!(!turn.contains_key(field), "mutation must remove {field}");

            assert!(
                serde_json::from_value::<PublicSession>(wire).is_err(),
                "omitted nullable field {field} must be rejected"
            );
        }
    }

    #[test]
    fn public_session_requires_nullable_display_name() {
        let mut wire = starting_session();
        assert!(
            wire.as_object_mut()
                .expect("Session fixture is an object")
                .remove("display_name")
                .is_some()
        );
        assert!(serde_json::from_value::<PublicSession>(wire).is_err());
    }

    #[test]
    fn public_session_deserialization_rejects_cross_field_contradictions() {
        let mut cases = Vec::new();

        let mut wrong_activity = starting_session();
        wrong_activity["activity"] = json!({"state": "idle"});
        cases.push(wrong_activity);

        let mut wrong_session = starting_session();
        wrong_session["turns"][0]["session_id"] = json!(OTHER_SESSION_ID);
        cases.push(wrong_session);

        let mut wrong_revision = starting_session();
        wrong_revision["session_state_revision"] = json!(2);
        cases.push(wrong_revision);

        let mut terminal_metadata = starting_session();
        terminal_metadata["turns"][0]["terminal_at"] = json!("2024-01-01T00:00:00Z");
        cases.push(terminal_metadata);

        for case in cases {
            assert!(serde_json::from_value::<PublicSession>(case).is_err());
        }
    }
}
