use clap::builder::{PossibleValuesParser, TypedValueParser};
use clap::{ArgMatches, Args, ValueEnum};
use satelle_core::session::{PublicSession, PublicTurn, TurnState};
use satelle_core::{ErrorCode, SatelleError, SessionId};
use serde::{Deserialize, Serialize};
use std::io::Write;
use time::OffsetDateTime;

#[path = "output-toon.rs"]
mod toon;

use super::{
    Command, ConfigCommand, DesktopCommand, EventMode, HostCommand, HostStorageBackupCommand,
    HostStorageCommand, HostStoreCommand, SelfSubcommand, SupportCommand,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq, ValueEnum)]
pub(crate) enum OutputFormat {
    Human,
    Json,
    CompactJson,
    Toon,
    Markdown,
    Csv,
}

pub(crate) const CONFIG_REPAIR_SCHEMA_VERSION: &str = "satelle.config.repair.v1";
pub(crate) const HOST_UPDATE_PLAIN_SCHEMA_VERSION: &str = "satelle.host.update.plain.v1";

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
    pub(crate) const FINAL: [Self; 5] = [
        Self::Human,
        Self::Json,
        Self::CompactJson,
        Self::Toon,
        Self::Markdown,
    ];
    pub(crate) const STREAM: [Self; 2] = [Self::Human, Self::Json];

    pub(crate) fn parser(formats: &[Self]) -> impl TypedValueParser<Value = Self> {
        PossibleValuesParser::new(
            formats
                .iter()
                .map(|format| {
                    format
                        .to_possible_value()
                        .expect("every output format has a CLI value")
                })
                .collect::<Vec<_>>(),
        )
        .map(|value| {
            Self::from_str(&value, false).expect("the parser accepts only declared output formats")
        })
    }

    pub(crate) const fn is_structured(self) -> bool {
        !matches!(self, Self::Human)
    }

    pub(crate) fn print(self, value: &impl Serialize) -> Result<(), SatelleError> {
        self.write(&mut std::io::stdout().lock(), value)
    }

    fn write(self, writer: &mut impl Write, value: &impl Serialize) -> Result<(), SatelleError> {
        let encoded = match self {
            Self::Json => return write_json(writer, value),
            Self::CompactJson => serde_json::to_string(value),
            Self::Markdown => {
                serde_json::to_string_pretty(value).map(|json| format!("```json\n{json}\n```"))
            }
            Self::Toon => serde_json::to_value(value).map(|value| toon::encode(&value)),
            Self::Human | Self::Csv => {
                return Err(SatelleError::invalid_usage(
                    "the selected format requires its command-specific renderer",
                ));
            }
        }
        .map_err(|error| SatelleError::invalid_usage(error.to_string()))?;
        writeln!(writer, "{encoded}")
            .map_err(|error| SatelleError::invalid_usage(error.to_string()))
    }
}

fn write_json(writer: &mut impl Write, value: &impl Serialize) -> Result<(), SatelleError> {
    serde_json::to_writer_pretty(&mut *writer, value).map_err(|source| SatelleError {
        code: ErrorCode::InvalidUsage,
        message: "could not serialize JSON output".to_string(),
        recovery_command: None,
        source_detail: Some(source.to_string()),
        details: std::collections::BTreeMap::new(),
    })?;
    writeln!(writer).map_err(|source| SatelleError {
        code: ErrorCode::InvalidUsage,
        message: "could not write JSON output".to_string(),
        recovery_command: None,
        source_detail: Some(source.to_string()),
        details: std::collections::BTreeMap::new(),
    })
}

#[derive(Args, Clone, Copy, Debug, Default)]
pub(crate) struct OutputArgs {
    // Preserve omission separately from explicit human output because JSON event streams conflict
    // with every explicit final-result selector, including `--format human`.
    #[arg(long, value_parser = OutputFormat::parser(&OutputFormat::FINAL), value_name = "FORMAT")]
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
            Self::Desktop {
                command: DesktopCommand::Snapshot(command),
            } => (command.output_args, EventOutput::None),
            Self::Telemetry { command } => match command {
                super::TelemetryCommand::Status(command) => {
                    (command.output_args, EventOutput::None)
                }
                super::TelemetryCommand::Deliver(_) => (OutputArgs::default(), EventOutput::None),
            },
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
            Self::Queue { command } => match command {
                super::QueueCommand::Status(command) => (command.output_args, EventOutput::None),
                super::QueueCommand::Cancel(command) => (command.output_args, EventOutput::None),
            },
            Self::Status(command) => (command.output_args, EventOutput::None),
            Self::Stop(command) => (command.output_args, EventOutput::None),
            Self::Session { .. } => (OutputArgs::default(), EventOutput::None),
            Self::Logs(command) => (command.output_args, EventOutput::None),
            Self::Skills { command } => command.output_request(),
            Self::Mcp {
                command: super::McpCommand::Install(command),
            } => (command.output_args, EventOutput::None),
            Self::Mcp {
                command: super::McpCommand::Serve(_),
            } => (OutputArgs::default(), EventOutput::None),
            Self::Support { command } => command.output_request(),
        }
    }

    pub(super) fn requests_machine_errors(&self) -> bool {
        let (output, events) = self.output_request();
        output.requests_machine() || events.requests_json_errors()
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
            .is_some_and(|format| format.is_structured())
}

impl ConfigCommand {
    const fn output_request(&self) -> (OutputArgs, EventOutput) {
        match self {
            Self::Check(command) => (command.output_args, EventOutput::None),
            Self::Explain(command) => (command.output_args, EventOutput::None),
            Self::Repair(command) => (command.output_args, EventOutput::None),
        }
    }
}

impl super::SkillsCommand {
    const fn output_request(&self) -> (OutputArgs, EventOutput) {
        let output = match self {
            Self::List(command) => command.output_args,
            Self::Get(command) | Self::Path(command) => command.output_args,
        };
        (output, EventOutput::None)
    }
}

impl HostCommand {
    const fn output_request(&self) -> (OutputArgs, EventOutput) {
        match self {
            Self::Start(command) => (command.output_args, EventOutput::None),
            Self::ReleaseState => (
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
            Self::Cleanup(command) => (command.output_args, EventOutput::None),
            Self::Sessions(command) => (command.output_args, EventOutput::None),
            Self::Storage { command } => command.output_request(),
            Self::Store { command } => command.output_request(),
            Self::StorageCompletionRecovery(command) => (command.output_args, EventOutput::None),
            Self::OfflineStorageMaintenance(_)
            | Self::OfflineStorageMigration { .. }
            | Self::OfflineStorageRestorePreview(_)
            | Self::OfflineStorageBackupCleanupPlan(_) => (
                OutputArgs {
                    format: None,
                    json: false,
                },
                EventOutput::None,
            ),
        }
    }
}

impl HostStorageCommand {
    const fn output_request(&self) -> (OutputArgs, EventOutput) {
        match self {
            Self::Migrate(command) => (command.output_args, EventOutput::None),
            Self::Complete(command) => (command.output_args, EventOutput::None),
            Self::Source {
                command: super::HostStorageSourceCommand::Cleanup(command),
            } => (command.output_args, EventOutput::None),
            Self::Restore(command) => (command.output_args, EventOutput::None),
            Self::Backup {
                command: HostStorageBackupCommand::Cleanup(command),
            } => (command.output_args, EventOutput::None),
        }
    }
}

impl HostStoreCommand {
    const fn output_request(&self) -> (OutputArgs, EventOutput) {
        match self {
            Self::Reset(command) => (command.output_args, EventOutput::None),
        }
    }
}

impl SelfSubcommand {
    const fn output_request(&self) -> (OutputArgs, EventOutput) {
        match self {
            Self::Update(command) => (command.output_args, EventOutput::None),
            Self::UpdateRemotes(command) => (command.output_args, EventOutput::None),
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
        self.resolve_with_default(events, None)
    }

    pub(crate) fn resolve_with_default(
        self,
        events: EventOutput,
        default: Option<satelle_core::PresentationOutputFormat>,
    ) -> Result<OutputFormat, SatelleError> {
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
            self.format.unwrap_or(match default {
                Some(satelle_core::PresentationOutputFormat::Json) => OutputFormat::Json,
                Some(satelle_core::PresentationOutputFormat::Human) | None => OutputFormat::Human,
            })
        })
    }

    pub(crate) const fn requests_machine(self) -> bool {
        self.json || matches!(self.format, Some(format) if format.is_structured())
    }

    pub(crate) const fn is_explicit(self) -> bool {
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
            "display_name": null,
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
        for &format in OutputFormat::value_variants() {
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
