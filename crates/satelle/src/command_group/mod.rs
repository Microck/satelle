//! Process-group support used to stop Satelle child processes as a unit.
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
