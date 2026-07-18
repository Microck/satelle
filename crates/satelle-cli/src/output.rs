use clap::{ArgMatches, Args, ValueEnum};
use satelle_core::session::{PublicSession, PublicTurn, TurnState};
use satelle_core::{SatelleError, SessionId};
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

use super::{
    Command, ConfigCommand, EventMode, HostCommand, HostStorageCommand, SelfSubcommand,
    SupportCommand,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq, ValueEnum)]
pub(crate) enum OutputFormat {
    Human,
    Json,
}

/// Command-specific schema tokens for JSON results backed by a Satelle session.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub(crate) enum SessionResultSchemaVersion {
    #[serde(rename = "satelle.run.v2")]
    RunV2,
    #[serde(rename = "satelle.steer.v2")]
    SteerV2,
    #[serde(rename = "satelle.status.v2")]
    StatusV2,
}

#[derive(Serialize)]
pub(crate) struct StatusReport<'a> {
    schema_version: SessionResultSchemaVersion,
    session_id: &'a SessionId,
    host: &'a str,
    status: TurnState,
    #[serde(with = "time::serde::rfc3339")]
    created_at: OffsetDateTime,
    #[serde(with = "time::serde::rfc3339")]
    updated_at: OffsetDateTime,
    turns: &'a [PublicTurn],
}

impl<'a> StatusReport<'a> {
    pub(crate) fn new(session: &'a PublicSession, host: &'a str) -> Self {
        let latest_turn = session
            .turns()
            .last()
            .expect("validated public Sessions always contain Turn history");
        Self {
            schema_version: SessionResultSchemaVersion::StatusV2,
            session_id: session.session_id(),
            host,
            status: latest_turn.state(),
            created_at: session.created_at(),
            updated_at: session.updated_at(),
            turns: session.turns(),
        }
    }
}

impl OutputFormat {
    pub(crate) const fn is_json(self) -> bool {
        matches!(self, Self::Json)
    }
}

#[derive(Args, Clone, Copy, Debug, Default)]
pub(crate) struct OutputArgs {
    // Preserve omission separately from explicit human output because JSON event streams conflict
    // with every explicit final-result selector, including `--format human`.
    #[arg(long, value_enum, value_name = "FORMAT")]
    format: Option<OutputFormat>,

    #[arg(long, help = "Alias for --format json")]
    json: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum EventOutput {
    None,
    LifecycleJson,
    DoctorEvents,
}

impl EventOutput {
    /// JSON event streams are also machine-readable error selectors.
    pub(crate) const fn requests_json_errors(self) -> bool {
        matches!(self, Self::LifecycleJson | Self::DoctorEvents)
    }
}

impl Command {
    // Keep output flags on executable leaves so intermediate command help never advertises formats
    // that a descendant does not support.
    pub(super) fn output_request(&self) -> (OutputArgs, EventOutput) {
        match self {
            Self::Completions(_) => (OutputArgs::default(), EventOutput::None),
            Self::Setup(command) => (command.output_args, EventOutput::None),
            Self::Repair(command) => (command.output_args, EventOutput::None),
            Self::Doctor(command) => (
                command.output_args,
                if command.events {
                    EventOutput::DoctorEvents
                } else {
                    EventOutput::None
                },
            ),
            Self::Config { command } => command.output_request(),
            Self::Paths(command) => (command.output_args, EventOutput::None),
            Self::Host { command } => command.output_request(),
            Self::SelfCtl { command } => command.output_request(),
            Self::Run(command) => (
                command.output_args,
                if command.events == EventMode::Json {
                    EventOutput::LifecycleJson
                } else {
                    EventOutput::None
                },
            ),
            Self::Steer(command) => (
                command.output_args,
                if command.events == EventMode::Json {
                    EventOutput::LifecycleJson
                } else {
                    EventOutput::None
                },
            ),
            Self::Status(command) => (command.output_args, EventOutput::None),
            Self::Stop(command) => (command.output_args, EventOutput::None),
            Self::Logs(command) => (command.output_args, EventOutput::None),
            Self::Mcp { .. } => (OutputArgs::default(), EventOutput::None),
            Self::Support { command } => command.output_request(),
        }
    }

    pub(super) fn requests_machine_errors(&self) -> bool {
        let (output, events) = self.output_request();
        output.requests_json() || events.requests_json_errors()
    }
}

/// Resolves only selectors that Clap accepted before a parser failure.
///
/// `ArgMatches` preserves the parser's ordering semantics, including the `--` delimiter, so this
/// deliberately does not inspect raw argv. Event selectors are interpreted only on the leaves
/// that define their machine-readable behavior.
pub(crate) fn partial_requests_machine_errors(matches: &ArgMatches) -> bool {
    if parsed_output_selector(matches) {
        return true;
    }

    match matches.subcommand() {
        Some(("run" | "steer", command)) => {
            parsed_output_selector(command)
                || command
                    .try_get_one::<EventMode>("events")
                    .ok()
                    .flatten()
                    .is_some_and(|mode| *mode == EventMode::Json)
        }
        Some(("doctor", command)) => {
            parsed_output_selector(command)
                || command
                    .try_get_one::<bool>("events")
                    .ok()
                    .flatten()
                    .copied()
                    .unwrap_or(false)
        }
        Some((_, command)) => partial_requests_machine_errors(command),
        None => false,
    }
}

fn parsed_output_selector(matches: &ArgMatches) -> bool {
    matches
        .try_get_one::<bool>("json")
        .ok()
        .flatten()
        .copied()
        .unwrap_or(false)
        || matches
            .try_get_one::<OutputFormat>("format")
            .ok()
            .flatten()
            .is_some_and(|format| *format == OutputFormat::Json)
}

impl ConfigCommand {
    const fn output_request(&self) -> (OutputArgs, EventOutput) {
        match self {
            Self::Check(command) => (command.output_args, EventOutput::None),
            Self::Explain(command) => (command.output_args, EventOutput::None),
        }
    }
}

impl HostCommand {
    const fn output_request(&self) -> (OutputArgs, EventOutput) {
        match self {
            Self::Start(command) => (command.output_args, EventOutput::None),
            Self::BootstrapLock | Self::ReleaseState => (
                OutputArgs {
                    format: None,
                    json: false,
                },
                EventOutput::None,
            ),
            Self::Trust(command) => (command.output_args, EventOutput::None),
            Self::Status(command) => (command.output_args, EventOutput::None),
            Self::Stop(command) | Self::Restart(command) => {
                (command.output_args, EventOutput::None)
            }
            Self::Update(command) => (command.output_args, EventOutput::None),
            Self::Sessions(command) => (command.output_args, EventOutput::None),
            Self::Storage { command } => command.output_request(),
        }
    }
}

impl HostStorageCommand {
    const fn output_request(&self) -> (OutputArgs, EventOutput) {
        match self {
            Self::Migrate(command) => (command.output_args, EventOutput::None),
        }
    }
}

impl SelfSubcommand {
    const fn output_request(&self) -> (OutputArgs, EventOutput) {
        match self {
            Self::Update(command) => (command.output_args, EventOutput::None),
        }
    }
}

impl SupportCommand {
    const fn output_request(&self) -> (OutputArgs, EventOutput) {
        match self {
            Self::Bundle(command) => (command.output_args, EventOutput::None),
        }
    }
}

impl OutputArgs {
    pub(crate) fn resolve(self, events: EventOutput) -> Result<OutputFormat, SatelleError> {
        if self.json && self.format.is_some() {
            return Err(SatelleError::output_mode_conflict(
                "--json cannot be combined with --format",
            ));
        }

        if self.is_explicit() {
            match events {
                EventOutput::LifecycleJson => {
                    return Err(SatelleError::output_mode_conflict(
                        "--events json cannot be combined with --json or --format",
                    ));
                }
                EventOutput::DoctorEvents => {
                    return Err(SatelleError::output_mode_conflict(
                        "doctor --events cannot be combined with --json or --format",
                    ));
                }
                EventOutput::None => {}
            }
        }

        Ok(if self.json {
            OutputFormat::Json
        } else {
            self.format.unwrap_or(OutputFormat::Human)
        })
    }

    pub(crate) const fn requests_json(self) -> bool {
        self.json || matches!(self.format, Some(OutputFormat::Json))
    }

    const fn is_explicit(self) -> bool {
        self.json || self.format.is_some()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn starting_public_session() -> PublicSession {
        serde_json::from_value(json!({
            "session_id": "rs_01890a5d-ac96-7b7c-8f89-37c3d0a66e11",
            "session_state_revision": 1,
            "created_at": "2024-01-01T00:00:00Z",
            "updated_at": "2024-01-01T00:00:00Z",
            "activity": {
                "state": "starting",
                "turn_id": "rt_01890a5d-ac96-7b7c-8f89-37c3d0a66e21",
                "turn_state_revision": 1
            },
            "turns": [{
                "session_id": "rs_01890a5d-ac96-7b7c-8f89-37c3d0a66e11",
                "turn_id": "rt_01890a5d-ac96-7b7c-8f89-37c3d0a66e21",
                "turn_state_revision": 1,
                "state": "starting",
                "started_at": "2024-01-01T00:00:00Z",
                "updated_at": "2024-01-01T00:00:00Z",
                "terminal_at": null,
                "safe_summary": null
            }]
        }))
        .expect("fixture should be a valid public Session")
    }

    fn args(format: Option<OutputFormat>, json: bool) -> OutputArgs {
        OutputArgs { format, json }
    }

    #[test]
    fn implicit_and_explicit_formats_resolve_without_changing_the_selected_mode() {
        assert_eq!(
            args(None, false)
                .resolve(EventOutput::None)
                .expect("implicit output should resolve"),
            OutputFormat::Human
        );
        assert_eq!(
            args(Some(OutputFormat::Human), false)
                .resolve(EventOutput::None)
                .expect("explicit human output should resolve"),
            OutputFormat::Human
        );
        assert_eq!(
            args(Some(OutputFormat::Json), false)
                .resolve(EventOutput::None)
                .expect("explicit JSON output should resolve"),
            OutputFormat::Json
        );
        assert_eq!(
            args(None, true)
                .resolve(EventOutput::None)
                .expect("the JSON alias should resolve"),
            OutputFormat::Json
        );
    }

    #[test]
    fn explicit_final_output_conflicts_with_other_final_or_streaming_selectors() {
        for format in [OutputFormat::Human, OutputFormat::Json] {
            let alias_conflict = args(Some(format), true)
                .resolve(EventOutput::None)
                .expect_err("the alias and canonical selector must conflict");
            assert_eq!(alias_conflict.code.as_str(), "output-mode-conflict");

            for events in [EventOutput::LifecycleJson, EventOutput::DoctorEvents] {
                let stream_conflict = args(Some(format), false)
                    .resolve(events)
                    .expect_err("explicit final output and JSON events must conflict");
                assert_eq!(stream_conflict.code.as_str(), "output-mode-conflict");
            }
        }
    }

    #[test]
    fn json_event_streams_select_machine_readable_errors() {
        assert!(EventOutput::LifecycleJson.requests_json_errors());
        assert!(!EventOutput::None.requests_json_errors());
        assert!(EventOutput::DoctorEvents.requests_json_errors());
    }

    #[test]
    fn session_result_schema_tokens_are_exact_and_strict() {
        for (schema, expected) in [
            (SessionResultSchemaVersion::RunV2, "satelle.run.v2"),
            (SessionResultSchemaVersion::SteerV2, "satelle.steer.v2"),
            (SessionResultSchemaVersion::StatusV2, "satelle.status.v2"),
        ] {
            assert_eq!(
                serde_json::to_value(schema).expect("session result schema should serialize"),
                json!(expected)
            );
        }

        assert!(
            serde_json::from_value::<SessionResultSchemaVersion>(json!("satelle.run.v1")).is_err()
        );
    }

    #[test]
    fn status_report_projects_the_canonical_public_session_without_a_legacy_shape() {
        let session = starting_public_session();
        let report = serde_json::to_value(StatusReport::new(&session, "remote"))
            .expect("status report should serialize");

        assert_eq!(report["schema_version"], "satelle.status.v2");
        assert_eq!(report["host"], "remote");
        assert_eq!(report["status"], "starting");
        assert_eq!(report["turns"][0]["state"], "starting");
        assert_eq!(report["turns"][0]["turn_state_revision"], 1);
        assert!(report["turns"][0].get("status").is_none());
    }
}
