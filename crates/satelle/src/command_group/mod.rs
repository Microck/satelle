//! Background process creation and process groups used to stop Satelle children as a unit.
//!
//! This is command-group 5.0.1 with Satelle's Windows lifecycle fix. It lives
//! in the package because a crates.io install cannot depend on a workspace
//! patch. The upstream MIT and Apache-2.0 licenses are in `licenses/`.

pub mod stdlib;

#[cfg(unix)]
mod unix_ext;

pub mod tokio;

pub mod builder;

#[cfg(windows)]
pub(crate) mod winres;

#[cfg(unix)]
#[doc(inline)]
pub use crate::command_group::unix_ext::UnixChildExt;
#[cfg(unix)]
#[doc(no_inline)]
pub use nix::sys::signal::Signal;

pub use crate::command_group::stdlib::CommandGroup;
#[doc(inline)]
pub use crate::command_group::stdlib::child::GroupChild;

pub use crate::command_group::tokio::AsyncCommandGroup;
#[doc(inline)]
pub use crate::command_group::tokio::child::AsyncGroupChild;

/// Build a background helper without allocating a Windows console.
/// Callers still select their input and output handles normally.
pub fn background_command(program: impl AsRef<std::ffi::OsStr>) -> std::process::Command {
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        let mut command = std::process::Command::new(program);
        command.creation_flags(winapi::um::winbase::CREATE_NO_WINDOW);
        command
    }
    #[cfg(not(windows))]
    {
        std::process::Command::new(program)
    }
}

#[cfg(all(windows, test))]
mod tests {
    #[test]
    fn background_command_has_no_console_and_preserves_output() {
        let output = super::builder::hidden_console_probe_command(super::background_command)
            .output()
            .expect("collect background Windows helper output");
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert_eq!(output.stdout, b"hidden-console");
    }
}
