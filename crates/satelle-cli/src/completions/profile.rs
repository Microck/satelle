use satelle_core::{ErrorCode, SatelleError};
use std::fs::{self, Permissions};
use std::io::{self, Write};
use std::ops::Range;
use std::path::Path;
use tempfile::NamedTempFile;

use super::CompletionShell;

const MANAGED_BLOCK_START: &str = "# >>> satelle completions >>>";
const MANAGED_BLOCK_NOTICE: &str =
    "# Managed by Satelle. Re-run the install command to update this block.";
const MANAGED_BLOCK_END: &str = "# <<< satelle completions <<<";

pub(super) fn update_shell_profile(
    shell: CompletionShell,
    completion_path: &Path,
    profile_path: &Path,
) -> Result<(), SatelleError> {
    let (original, permissions) = read_profile(profile_path)?;
    let contents = std::str::from_utf8(&original).map_err(|source| {
        profile_error(
            profile_path,
            "completion profile is not valid UTF-8",
            Some(source.to_string()),
        )
    })?;
    let newline = if contents.contains("\r\n") {
        "\r\n"
    } else {
        "\n"
    };
    let block = managed_block(shell, completion_path, profile_path, newline)?;
    let updated = upsert_managed_block(contents, &block, profile_path, newline)?;

    if updated.as_bytes() == original {
        return Ok(());
    }

    persist_profile(profile_path, updated.as_bytes(), permissions)
}

fn read_profile(profile_path: &Path) -> Result<(Vec<u8>, Option<Permissions>), SatelleError> {
    let metadata = match fs::symlink_metadata(profile_path) {
        Ok(metadata) if !metadata.file_type().is_file() => {
            return Err(profile_error(
                profile_path,
                "completion profile is not a regular file",
                None,
            ));
        }
        Ok(metadata) => Some(metadata),
        Err(source) if source.kind() == io::ErrorKind::NotFound => None,
        Err(source) => {
            return Err(profile_error(
                profile_path,
                "could not inspect completion profile",
                Some(source.to_string()),
            ));
        }
    };

    let contents = match &metadata {
        Some(_) => fs::read(profile_path).map_err(|source| {
            profile_error(
                profile_path,
                "could not read completion profile",
                Some(source.to_string()),
            )
        })?,
        None => Vec::new(),
    };
    #[cfg(unix)]
    let permissions = metadata.map(|metadata| metadata.permissions());
    #[cfg(not(unix))]
    let permissions: Option<Permissions> = None;
    Ok((contents, permissions))
}

fn managed_block(
    shell: CompletionShell,
    completion_path: &Path,
    profile_path: &Path,
    newline: &str,
) -> Result<String, SatelleError> {
    let path = completion_path.to_str().ok_or_else(|| {
        profile_error(
            profile_path,
            "installed completion path is not valid UTF-8",
            None,
        )
    })?;
    let activation = match shell {
        CompletionShell::Bash => format!(". {}", quote_posix(path)),
        CompletionShell::Zsh => format!(
            "autoload -Uz compinit{newline}(( $+functions[compdef] )) || compinit{newline}source {}{newline}compdef _satelle satelle",
            quote_posix(path)
        ),
        CompletionShell::Fish => format!("source {}", quote_fish(path)),
        CompletionShell::Powershell => format!(". {}", quote_powershell(path)),
    };

    Ok(format!(
        "{MANAGED_BLOCK_START}{newline}{MANAGED_BLOCK_NOTICE}{newline}{activation}{newline}{MANAGED_BLOCK_END}{newline}"
    ))
}

fn quote_posix(path: &str) -> String {
    format!("'{}'", path.replace('\'', "'\\''"))
}

fn quote_fish(path: &str) -> String {
    let escaped = path.replace('\\', "\\\\").replace('\'', "\\'");
    format!("'{escaped}'")
}

fn quote_powershell(path: &str) -> String {
    format!("'{}'", path.replace('\'', "''"))
}

fn upsert_managed_block(
    contents: &str,
    block: &str,
    profile_path: &Path,
    newline: &str,
) -> Result<String, SatelleError> {
    let starts = marker_lines(contents, MANAGED_BLOCK_START);
    let ends = marker_lines(contents, MANAGED_BLOCK_END);

    match (starts.as_slice(), ends.as_slice()) {
        ([], []) => {
            let mut updated = String::with_capacity(contents.len() + block.len() + newline.len());
            updated.push_str(contents);
            if !contents.is_empty() && !contents.ends_with('\n') {
                updated.push_str(newline);
            }
            updated.push_str(block);
            Ok(updated)
        }
        ([start], [end]) if start.start < end.start => {
            let mut updated =
                String::with_capacity(contents.len() - (end.end - start.start) + block.len());
            updated.push_str(&contents[..start.start]);
            updated.push_str(block);
            updated.push_str(&contents[end.end..]);
            Ok(updated)
        }
        _ => Err(profile_error(
            profile_path,
            "completion profile contains malformed Satelle completion markers",
            None,
        )),
    }
}

fn marker_lines(contents: &str, marker: &str) -> Vec<Range<usize>> {
    let mut matches = Vec::new();
    let mut offset = 0;
    for line in contents.split_inclusive('\n') {
        let body = line.strip_suffix('\n').unwrap_or(line);
        let body = body.strip_suffix('\r').unwrap_or(body);
        let end = offset + line.len();
        if body == marker {
            matches.push(offset..end);
        }
        offset = end;
    }
    matches
}

fn persist_profile(
    profile_path: &Path,
    contents: &[u8],
    permissions: Option<Permissions>,
) -> Result<(), SatelleError> {
    let parent = profile_path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    fs::create_dir_all(parent).map_err(|source| {
        profile_error(
            profile_path,
            "could not create completion profile directory",
            Some(source.to_string()),
        )
    })?;

    let mut temporary = NamedTempFile::new_in(parent).map_err(|source| {
        profile_error(
            profile_path,
            "could not create temporary completion profile",
            Some(source.to_string()),
        )
    })?;
    temporary.write_all(contents).map_err(|source| {
        profile_error(
            profile_path,
            "could not write temporary completion profile",
            Some(source.to_string()),
        )
    })?;
    if let Some(permissions) = permissions {
        temporary
            .as_file()
            .set_permissions(permissions)
            .map_err(|source| {
                profile_error(
                    profile_path,
                    "could not preserve completion profile permissions",
                    Some(source.to_string()),
                )
            })?;
    }
    temporary.as_file().sync_all().map_err(|source| {
        profile_error(
            profile_path,
            "could not synchronize temporary completion profile",
            Some(source.to_string()),
        )
    })?;
    temporary.persist(profile_path).map_err(|source| {
        profile_error(
            profile_path,
            "could not atomically replace completion profile",
            Some(source.error.to_string()),
        )
    })?;
    Ok(())
}

fn profile_error(
    profile_path: &Path,
    message: &str,
    source_detail: Option<String>,
) -> SatelleError {
    SatelleError {
        code: ErrorCode::CompletionProfileUpdateFailed,
        message: format!("{message} {}", profile_path.display()),
        recovery_command: Some(
            "repair the profile or choose another writable regular UTF-8 profile file".to_string(),
        ),
        source_detail,
        details: Default::default(),
    }
}
