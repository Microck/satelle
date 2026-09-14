use std::fs;
use std::io;
use std::path::Path;

#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;

pub fn write_user_controlled(path: &Path, contents: impl AsRef<[u8]>) -> io::Result<()> {
    fs::write(path, contents)?;

    #[cfg(unix)]
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;

    #[cfg(windows)]
    secure_windows_file(path)?;

    Ok(())
}

#[cfg(windows)]
fn secure_windows_file(path: &Path) -> io::Result<()> {
    let identity = std::process::Command::new("whoami.exe").output()?;
    if !identity.status.success() {
        return Err(command_error("whoami", &identity.stderr));
    }
    let identity = String::from_utf8(identity.stdout)
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
    let identity = identity.trim();

    let owner = std::process::Command::new("icacls.exe")
        .arg(path)
        .args(["/setowner", identity])
        .output()?;
    if !owner.status.success() {
        return Err(command_error("icacls /setowner", &owner.stderr));
    }

    let acl = std::process::Command::new("icacls.exe")
        .arg(path)
        .args(["/inheritance:r", "/grant:r", &format!("{identity}:(F)")])
        .output()?;
    if !acl.status.success() {
        return Err(command_error("icacls /grant:r", &acl.stderr));
    }

    Ok(())
}

#[cfg(windows)]
fn command_error(command: &str, stderr: &[u8]) -> io::Error {
    io::Error::other(format!(
        "{command} failed: {}",
        String::from_utf8_lossy(stderr).trim()
    ))
}
