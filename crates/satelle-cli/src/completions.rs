use clap::{Args, CommandFactory, ValueEnum};
use clap_complete::{Shell, generate};
use satelle_core::CLI_NAME;
use std::io;

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

pub(super) fn generate_completions(command: CompletionsCommand) {
    generate(
        Shell::from(command.shell),
        &mut Cli::command(),
        CLI_NAME,
        &mut io::stdout(),
    );
}
