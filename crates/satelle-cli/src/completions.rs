use clap::{Args, CommandFactory, ValueEnum};
use clap_complete::{Shell, generate};
use satelle_core::{CLI_NAME, ErrorCode, SatelleError};
use std::io::{self, ErrorKind, Write};

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
    // Some clap generators still panic on writer errors inside their fallible path. Generate
    // against an infallible memory buffer so stdout remains the only I/O failure boundary.
    let mut script = Vec::new();
    generate(
        Shell::from(command.shell),
        &mut Cli::command(),
        CLI_NAME,
        &mut script,
    );

    let stdout = io::stdout();
    let mut stdout = stdout.lock();
    match stdout.write_all(&script).and_then(|()| stdout.flush()) {
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
