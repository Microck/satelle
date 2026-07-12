use std::{
    os::windows::{io::AsRawHandle, process::CommandExt},
    process::Command,
};
use winapi::um::winbase::CREATE_SUSPENDED;

use crate::{builder::CommandGroupBuilder, winres::*, GroupChild};

impl CommandGroupBuilder<'_, Command> {
    /// Executes the command as a child process group, returning a handle to it.
    ///
    /// By default, stdin, stdout and stderr are inherited from the parent.
    ///
    /// On Windows, this creates a job object instead of a POSIX process group.
    ///
    /// # Examples
    ///
    /// Basic usage:
    ///
    /// ```no_run
    /// use std::process::Command;
    /// use command_group::CommandGroup;
    ///
    /// Command::new("ls")
    ///         .group()
    /// 		.spawn()
    ///         .expect("ls command failed to start");
    /// ```
    pub fn spawn(&mut self) -> std::io::Result<GroupChild> {
        self.command
            .creation_flags(self.creation_flags | CREATE_SUSPENDED);

        let handles = job_object(self.kill_on_drop)?;
        let mut child = self.command.spawn()?;
        if let Err(error) = assign_child(child.as_raw_handle(), handles.job) {
            // std::process::Child does not terminate on drop. Because the child
            // was created suspended, explicitly terminate and reap it before the
            // job handles are closed and the spawn error is returned.
            unsafe { winapi::um::jobapi2::TerminateJobObject(handles.job, 1) };
            let _ = child.kill();
            let _ = child.wait();
            return Err(error);
        }
        let (job, completion_port) = handles.into_raw();

        Ok(GroupChild::new(child, job, completion_port))
    }
}
