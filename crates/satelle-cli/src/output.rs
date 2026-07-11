use clap::{Args, ValueEnum};
use satelle_core::SatelleError;

use super::{
    Command, ConfigCommand, EventMode, HostCommand, HostStorageCommand, SelfSubcommand,
    SupportCommand,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq, ValueEnum)]
pub(crate) enum OutputFormat {
    Human,
    Json,
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

impl Command {
    // Keep output flags on executable leaves so intermediate command help never advertises formats
    // that a descendant does not support.
    pub(super) fn output_request(&self) -> (OutputArgs, EventOutput) {
        match self {
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
            Self::Support { command } => command.output_request(),
        }
    }
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
}
