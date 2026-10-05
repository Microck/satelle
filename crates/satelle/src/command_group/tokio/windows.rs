use tokio::process::Command;
use winapi::um::winbase::{CREATE_NO_WINDOW, CREATE_SUSPENDED};

use crate::command_group::{AsyncGroupChild, builder::CommandGroupBuilder, winres::*};

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
    /// use tokio::process::Command;
    /// use command_group::CommandGroup;
    ///
    /// Command::new("ls")
    ///         .group()
    ///         .spawn()
    ///         .expect("ls command failed to start");
    /// ```
    pub fn spawn(&mut self) -> std::io::Result<AsyncGroupChild> {
        let handles = job_object(self.kill_on_drop)?;
        self.command
            .creation_flags(self.creation_flags | CREATE_SUSPENDED | CREATE_NO_WINDOW);

        let mut child = self.command.spawn()?;
        if let Err(error) = assign_child(
            child
                .raw_handle()
                .expect("child has exited but it has not even started"),
            handles.job,
        ) {
            // start_kill is synchronous on Windows and guarantees that the
            // suspended process cannot survive this failed spawn operation.
            unsafe { winapi::um::jobapi2::TerminateJobObject(handles.job, 1) };
            let _ = child.start_kill();
            return Err(error);
        }
        let (job, completion_port) = handles.into_raw();

        Ok(AsyncGroupChild::new(child, job, completion_port))
    }
}

#[cfg(test)]
mod tests {
    use crate::command_group::AsyncCommandGroup;

    #[tokio::test]
    async fn background_async_group_has_no_console_and_preserves_output() {
        let command =
            crate::command_group::builder::hidden_console_probe_command(std::process::Command::new);
        let output = tokio::process::Command::from(command)
            .group_spawn()
            .expect("start hidden async Windows child")
            .wait_with_output()
            .await
            .expect("collect hidden async child output");
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert_eq!(output.stdout, b"hidden-console");
    }
}
