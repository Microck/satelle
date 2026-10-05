/// CommandGroupBuilder is a builder for a group of processes.
///
/// It is created via the `group` method on [`Command`](std::process::Command) or
/// [`AsyncCommand`](tokio::process::Command).
pub struct CommandGroupBuilder<'a, T> {
    pub(crate) command: &'a mut T,
    #[allow(dead_code)]
    pub(crate) kill_on_drop: bool,
    #[allow(dead_code)]
    pub(crate) creation_flags: u32,
}

impl<'a, T> CommandGroupBuilder<'a, T> {
    pub(crate) fn new(command: &'a mut T) -> Self {
        Self {
            command,
            kill_on_drop: false,
            creation_flags: 0,
        }
    }

    /// See [`tokio::process::Command::kill_on_drop`].
    pub fn kill_on_drop(&mut self, kill_on_drop: bool) -> &mut Self {
        self.kill_on_drop = kill_on_drop;
        self
    }

    /// Set the creation flags for the process.
    #[cfg(windows)]
    pub fn creation_flags(&mut self, creation_flags: u32) -> &mut Self {
        self.creation_flags = creation_flags;
        self
    }
}

#[cfg(all(windows, test))]
pub(crate) fn hidden_console_probe_command(
    build: impl FnOnce(std::path::PathBuf) -> std::process::Command,
) -> std::process::Command {
    let system_root = std::env::var_os("SystemRoot").expect("Windows system root");
    let powershell = std::path::PathBuf::from(system_root)
        .join(r"System32\WindowsPowerShell\v1.0\powershell.exe");
    let mut command = build(powershell);
    command.args(["-NoProfile", "-NonInteractive", "-Command", r#"
Add-Type -TypeDefinition 'using System; using System.Runtime.InteropServices; public static class SatelleConsoleProbe { [DllImport("kernel32.dll")] public static extern IntPtr GetConsoleWindow(); }'
if ([SatelleConsoleProbe]::GetConsoleWindow() -ne [IntPtr]::Zero) { exit 41 }
[Console]::Write('hidden-console')
"#]);
    command
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped());
    command
}
