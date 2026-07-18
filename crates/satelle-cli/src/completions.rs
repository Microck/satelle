mod profile;

use clap::{Args, CommandFactory, ValueEnum};
use clap_complete::{Generator, Shell, generate};
use satelle_core::{CLI_NAME, ErrorCode, SatelleError};
use std::fs::{self, Permissions};
use std::io::{self, ErrorKind, Write};
use std::path::{Path, PathBuf};
use tempfile::NamedTempFile;

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
    let output_dir = absolute_output_dir(output_dir)?;
    let destination = output_dir.join(Shell::from(shell).file_name(CLI_NAME));
    let destination_text = completion_output_path(&destination)?;
    fs::create_dir_all(&output_dir).map_err(|source| {
        completion_install_error(
            format!(
                "could not create completion output directory {}",
                output_dir.display()
            ),
            source,
        )
    })?;

    persist_completion_script(&destination, &completion_script(shell))?;

    if let Some(profile_path) = profile_path {
        update_shell_profile(shell, &destination, profile_path)?;
    }

    write_stdout(
        format!("{destination_text}\n").as_bytes(),
        "could not write installed completion path",
    )
}

fn completion_output_path(destination: &Path) -> Result<&str, SatelleError> {
    let Some(path) = destination.to_str() else {
        return Err(invalid_completion_path_error());
    };
    if path
        .chars()
        .any(|character| matches!(character, '\n' | '\r'))
    {
        return Err(invalid_completion_path_error());
    }
    Ok(path)
}

fn invalid_completion_path_error() -> SatelleError {
    SatelleError {
        code: ErrorCode::CompletionInstallFailed,
        message: "completion output must use a single-line UTF-8 path".to_string(),
        recovery_command: Some("choose a writable output directory and retry".to_string()),
        source_detail: None,
        details: Default::default(),
    }
}

fn persist_completion_script(destination: &Path, script: &[u8]) -> Result<(), SatelleError> {
    let permissions = completion_permissions(destination)?;
    let parent = destination
        .parent()
        .expect("an installed completion path always has an output directory");
    let mut temporary = NamedTempFile::new_in(parent).map_err(|source| {
        completion_install_error(
            format!(
                "could not create temporary completion script in {}",
                parent.display()
            ),
            source,
        )
    })?;
    temporary.write_all(script).map_err(|source| {
        completion_install_error(
            format!(
                "could not write temporary completion script for {}",
                destination.display()
            ),
            source,
        )
    })?;
    if let Some(permissions) = permissions {
        temporary
            .as_file()
            .set_permissions(permissions)
            .map_err(|source| {
                completion_install_error(
                    format!(
                        "could not preserve completion script permissions {}",
                        destination.display()
                    ),
                    source,
                )
            })?;
    }
    temporary.as_file().sync_all().map_err(|source| {
        completion_install_error(
            format!(
                "could not synchronize temporary completion script for {}",
                destination.display()
            ),
            source,
        )
    })?;
    temporary.persist(destination).map_err(|source| {
        completion_install_error(
            format!(
                "could not atomically replace completion script {}",
                destination.display()
            ),
            source.error,
        )
    })?;
    Ok(())
}

fn completion_permissions(destination: &Path) -> Result<Option<Permissions>, SatelleError> {
    match fs::symlink_metadata(destination) {
        Ok(metadata) if metadata.file_type().is_file() => Ok(Some(metadata.permissions())),
        Ok(_) => Err(SatelleError {
            code: ErrorCode::CompletionInstallFailed,
            message: format!(
                "completion destination is not a regular file {}",
                destination.display()
            ),
            recovery_command: Some("choose a writable output directory and retry".to_string()),
            source_detail: None,
            details: Default::default(),
        }),
        Err(source) if source.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(source) => Err(completion_install_error(
            format!(
                "could not inspect completion destination {}",
                destination.display()
            ),
            source,
        )),
    }
}

fn absolute_output_dir(output_dir: &Path) -> Result<PathBuf, SatelleError> {
    if output_dir.is_absolute() {
        return Ok(output_dir.to_path_buf());
    }

    std::env::current_dir()
        .map(|current_dir| current_dir.join(output_dir))
        .map_err(|source| {
            completion_install_error(
                format!(
                    "could not resolve completion output directory {}",
                    output_dir.display()
                ),
                source,
            )
        })
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
