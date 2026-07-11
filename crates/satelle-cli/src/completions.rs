mod profile;

use clap::{Args, CommandFactory, ValueEnum};
use clap_complete::{Generator, Shell, generate};
use satelle_core::{CLI_NAME, ErrorCode, SatelleError};
use std::fs;
use std::io::{self, ErrorKind, Write};
use std::path::{Path, PathBuf};

use super::Cli;
use profile::update_shell_profile;

#[derive(Args, Debug)]
pub(super) struct CompletionsCommand {
    #[arg(value_enum, required_unless_present = "output_dir")]
    shell: Option<CompletionShell>,

    #[arg(
        long,
        value_name = "DIRECTORY",
        help = "Install the completion script in DIRECTORY; detect the shell when omitted"
    )]
    output_dir: Option<PathBuf>,

    #[arg(
        long,
        value_name = "FILE",
        requires = "output_dir",
        help = "Activate the installed script through one managed block in FILE"
    )]
    update_profile: Option<PathBuf>,
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

pub(super) fn run_completions(command: CompletionsCommand) -> Result<(), SatelleError> {
    if let Some(output_dir) = command.output_dir {
        let shell = match command.shell {
            Some(shell) => shell,
            None => detect_shell()?,
        };
        return install_completions(shell, &output_dir, command.update_profile.as_deref());
    }

    let shell = command
        .shell
        .expect("clap requires a shell when --output-dir is absent");
    write_stdout(
        &completion_script(shell),
        "could not write shell completion script",
    )
}

fn completion_script(shell: CompletionShell) -> Vec<u8> {
    // Some clap generators still panic on writer errors inside their fallible path. Generate
    // against an infallible memory buffer so stdout remains the only I/O failure boundary.
    let mut script = Vec::new();
    generate(
        Shell::from(shell),
        &mut Cli::command(),
        CLI_NAME,
        &mut script,
    );
    script
}

fn install_completions(
    shell: CompletionShell,
    output_dir: &Path,
    profile_path: Option<&Path>,
) -> Result<(), SatelleError> {
    fs::create_dir_all(output_dir).map_err(|source| {
        completion_install_error(
            format!(
                "could not create completion output directory {}",
                output_dir.display()
            ),
            source,
        )
    })?;

    let destination = output_dir.join(Shell::from(shell).file_name(CLI_NAME));
    fs::write(&destination, completion_script(shell)).map_err(|source| {
        completion_install_error(
            format!(
                "could not write shell completion script {}",
                destination.display()
            ),
            source,
        )
    })?;

    if let Some(profile_path) = profile_path {
        update_shell_profile(shell, &destination, profile_path)?;
    }

    write_stdout(
        format!("{}\n", destination.display()).as_bytes(),
        "could not write installed completion path",
    )
}

fn detect_shell() -> Result<CompletionShell, SatelleError> {
    match Shell::from_env() {
        Some(Shell::Bash) => Ok(CompletionShell::Bash),
        Some(Shell::Zsh) => Ok(CompletionShell::Zsh),
        Some(Shell::Fish) => Ok(CompletionShell::Fish),
        Some(Shell::PowerShell) => Ok(CompletionShell::Powershell),
        Some(_) | None => Err(SatelleError {
            code: ErrorCode::InvalidUsage,
            message: "could not detect a supported shell; select bash, zsh, fish, or powershell"
                .to_string(),
            recovery_command: Some(
                "satelle completions <shell> --output-dir <directory>".to_string(),
            ),
            source_detail: None,
            details: Default::default(),
        }),
    }
}

fn write_stdout(bytes: &[u8], message: &'static str) -> Result<(), SatelleError> {
    let stdout = io::stdout();
    let mut stdout = stdout.lock();
    match stdout.write_all(bytes).and_then(|()| stdout.flush()) {
        Ok(()) => Ok(()),
        // Early-closing consumers such as `head` are a successful CLI pipeline outcome.
        Err(source) if source.kind() == ErrorKind::BrokenPipe => Ok(()),
        Err(source) => Err(SatelleError {
            code: ErrorCode::InvalidUsage,
            message: message.to_string(),
            recovery_command: None,
            source_detail: Some(source.to_string()),
            details: Default::default(),
        }),
    }
}

fn completion_install_error(message: String, source: io::Error) -> SatelleError {
    SatelleError {
        code: ErrorCode::CompletionInstallFailed,
        message,
        recovery_command: Some("choose a writable output directory and retry".to_string()),
        source_detail: Some(source.to_string()),
        details: Default::default(),
    }
}
