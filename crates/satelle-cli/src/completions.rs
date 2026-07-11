use clap::{Args, CommandFactory, ValueEnum};
use clap_complete::{Generator, Shell};
use satelle_core::{CLI_NAME, ErrorCode, SatelleError};
use std::io::{self, ErrorKind};

use super::Cli;

#[derive(Args, Debug)]
pub(super) struct CompletionsCommand {
    #[arg(value_enum)]
    shell: CompletionShell,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, ValueEnum)]
enum CompletionShell {
    Bash,
    Zsh,
    Fish,
    Powershell,
}

impl From<CompletionShell> for Shell {
    fn from(shell: CompletionShell) -> Self {
        match shell {
            CompletionShell::Bash => Self::Bash,
            CompletionShell::Zsh => Self::Zsh,
            CompletionShell::Fish => Self::Fish,
            CompletionShell::Powershell => Self::PowerShell,
        }
    }
}

pub(super) fn generate_completions(command: CompletionsCommand) -> Result<(), SatelleError> {
    let mut cli = Cli::command();
    cli.set_bin_name(CLI_NAME);
    cli.build();

    let stdout = io::stdout();
    let mut stdout = stdout.lock();
    match Shell::from(command.shell).try_generate(&cli, &mut stdout) {
        Ok(()) => Ok(()),
        // Early-closing consumers such as `head` are a successful CLI pipeline outcome.
        Err(source) if source.kind() == ErrorKind::BrokenPipe => Ok(()),
        Err(source) => Err(SatelleError {
            code: ErrorCode::InvalidUsage,
            message: "could not write shell completion script".to_string(),
            recovery_command: None,
            source_detail: Some(source.to_string()),
            details: Default::default(),
        }),
    }
}
