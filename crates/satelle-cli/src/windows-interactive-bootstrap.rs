use std::env;
use std::ffi::{OsStr, OsString};
use std::fs;
use std::io;
use std::os::windows::ffi::{OsStrExt, OsStringExt};
use std::path::{Path, PathBuf};
use std::process::{Command, ExitStatus};

use base64::Engine;
use uuid::Uuid;

const INTERACTIVE_BOOTSTRAP_BOUNDARY: &str = "--interactive-bootstrap";
const DAEMON_PATH_ENVIRONMENT_VARIABLES: [&str; 5] = [
    "SATELLE_HOME",
    "SATELLE_CONFIG_FILE",
    "SATELLE_STATE_DIR",
    "SATELLE_CACHE_DIR",
    "SATELLE_LOG_DIR",
];

pub(super) fn relaunch() -> io::Result<ExitStatus> {
    let nonce = Uuid::now_v7().simple().to_string();
    let task_name = format!("SatelleInteractiveBootstrap-{nonce}");
    let pipe_prefix = format!("satelle-interactive-bootstrap-{nonce}");
    let script_directory = env::temp_dir().join(&pipe_prefix);
    let child_path = script_directory.join("interactive-bootstrap-child.ps1");
    let parent_path = script_directory.join("interactive-bootstrap-parent.ps1");
    let arguments = current_arguments_without_boundary(env::args_os().collect())?;
    let executable = env::current_exe()?;
    let working_directory = env::current_dir()?;
    let child_script = child_script(
        executable.as_os_str(),
        working_directory.as_os_str(),
        &arguments,
    );
    let parent_script = parent_script(&task_name, &pipe_prefix, &child_path);
    let script_directory_guard =
        satelle_core::open_or_create_owner_only_directory(&script_directory)
            .map_err(|error| io::Error::other(error.to_string()))?;

    let run_result = (|| {
        write_windows_powershell_script(&child_path, &child_script)?;
        write_windows_powershell_script(&parent_path, &parent_script)?;
        Command::new(windows_powershell_path()?)
            .args([
                "-NoProfile",
                "-NonInteractive",
                "-ExecutionPolicy",
                "Bypass",
                "-File",
            ])
            .arg(&parent_path)
            .status()
    })();
    drop(script_directory_guard);
    if let Err(error) = fs::remove_dir_all(&script_directory) {
        eprintln!(
            "warning: failed to remove interactive bootstrap scripts at {}: {error}",
            script_directory.display()
        );
    }
    run_result
}

fn windows_powershell_path() -> io::Result<PathBuf> {
    let system_root = env::var_os("SystemRoot")
        .ok_or_else(|| io::Error::other("SystemRoot is not configured"))?;
    Ok(PathBuf::from(system_root).join(r"System32\WindowsPowerShell\v1.0\powershell.exe"))
}

fn current_arguments_without_boundary(mut arguments: Vec<OsString>) -> io::Result<Vec<OsString>> {
    if arguments.is_empty() {
        return Err(io::Error::other(
            "interactive bootstrap executable is missing",
        ));
    }
    arguments.remove(0);
    let boundaries = arguments
        .iter()
        .enumerate()
        .filter(|(_, argument)| argument == &INTERACTIVE_BOOTSTRAP_BOUNDARY)
        .map(|(index, _)| index)
        .collect::<Vec<_>>();
    if boundaries.len() != 1 {
        return Err(io::Error::other(format!(
            "expected exactly one {INTERACTIVE_BOOTSTRAP_BOUNDARY} boundary argument, found {}",
            boundaries.len()
        )));
    }
    arguments.remove(boundaries[0]);
    Ok(arguments)
}

fn child_script(executable: &OsStr, working_directory: &OsStr, arguments: &[OsString]) -> String {
    let environment = DAEMON_PATH_ENVIRONMENT_VARIABLES
        .into_iter()
        .map(|name| {
            let value = env::var_os(name)
                .map(|value| format!("'{}'", utf16_base64(&value)))
                .unwrap_or_else(|| "$null".to_owned());
            format!("    '{name}' = {value}")
        })
        .collect::<Vec<_>>()
        .join("\n");
    CHILD_SCRIPT_TEMPLATE
        .replace("__EXECUTABLE__", &utf16_base64(executable))
        .replace("__WORKING_DIRECTORY__", &utf16_base64(working_directory))
        .replace("__ARGUMENTS__", &utf16_base64(&quoted_arguments(arguments)))
        .replace("__ENVIRONMENT__", &environment)
}

fn parent_script(task_name: &str, pipe_prefix: &str, child_path: &Path) -> String {
    let interactive_launch = crate::transport::windows_interactive_task_launch_script(
        r"\",
        task_name,
        "$identity.User.Value",
    );
    PARENT_SCRIPT_TEMPLATE
        .replace("__TASK_NAME__", task_name)
        .replace("__PIPE_PREFIX__", pipe_prefix)
        .replace("__CHILD_PATH__", &utf16_base64(child_path.as_os_str()))
        .replace("__INTERACTIVE_LAUNCH__", &interactive_launch)
}

fn write_windows_powershell_script(path: &Path, script: &str) -> io::Result<()> {
    // Windows PowerShell 5.1 does not reliably infer UTF-8 without a BOM. UTF-16LE
    // also preserves paths and command arguments when the active code page cannot.
    let mut encoded = vec![0xff, 0xfe];
    for unit in script.encode_utf16() {
        encoded.extend_from_slice(&unit.to_le_bytes());
    }
    fs::write(path, encoded)
}

fn utf16_base64(value: &OsStr) -> String {
    let bytes = value
        .encode_wide()
        .flat_map(u16::to_le_bytes)
        .collect::<Vec<_>>();
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

fn quoted_arguments(arguments: &[OsString]) -> OsString {
    let mut command_line = Vec::new();
    for (index, argument) in arguments.iter().enumerate() {
        if index != 0 {
            command_line.push(' ' as u16);
        }
        append_quoted_argument(&mut command_line, argument);
    }
    OsString::from_wide(&command_line)
}

fn append_quoted_argument(command_line: &mut Vec<u16>, argument: &OsStr) {
    let units = argument.encode_wide().collect::<Vec<_>>();
    let quote = units.is_empty() || units.iter().any(|unit| matches!(*unit, 0x20 | 0x09 | 0x22));
    if !quote {
        command_line.extend(units);
        return;
    }
    command_line.push('"' as u16);
    let mut backslashes = 0usize;
    for unit in units {
        if unit == '\\' as u16 {
            backslashes += 1;
        } else if unit == '"' as u16 {
            command_line.extend(std::iter::repeat_n('\\' as u16, backslashes * 2 + 1));
            command_line.push(unit);
            backslashes = 0;
        } else {
            command_line.extend(std::iter::repeat_n('\\' as u16, backslashes));
            backslashes = 0;
            command_line.push(unit);
        }
    }
    command_line.extend(std::iter::repeat_n('\\' as u16, backslashes * 2));
    command_line.push('"' as u16);
}

const PARENT_SCRIPT_TEMPLATE: &str = r#"$ErrorActionPreference = 'Stop'
$taskName = '__TASK_NAME__'
$pipePrefix = '__PIPE_PREFIX__'
$childPath = [System.Text.Encoding]::Unicode.GetString(
    [Convert]::FromBase64String('__CHILD_PATH__')
)
$controlName = "$pipePrefix-control"
$stdoutName = "$pipePrefix-stdout"
$stderrName = "$pipePrefix-stderr"
$identity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
$security = New-Object System.IO.Pipes.PipeSecurity
$security.SetAccessRuleProtection($true, $false)
$rule = New-Object System.IO.Pipes.PipeAccessRule(
    $identity.User,
    [System.IO.Pipes.PipeAccessRights]::FullControl,
    [System.Security.AccessControl.AccessControlType]::Allow
)
$security.AddAccessRule($rule)
$control = New-Object System.IO.Pipes.NamedPipeServerStream(
    $controlName, [System.IO.Pipes.PipeDirection]::InOut, 1,
    [System.IO.Pipes.PipeTransmissionMode]::Byte,
    [System.IO.Pipes.PipeOptions]::Asynchronous,
    4096, 4096, $security
)
$stdout = New-Object System.IO.Pipes.NamedPipeServerStream(
    $stdoutName, [System.IO.Pipes.PipeDirection]::In, 1,
    [System.IO.Pipes.PipeTransmissionMode]::Byte,
    [System.IO.Pipes.PipeOptions]::Asynchronous,
    4096, 4096, $security
)
$stderr = New-Object System.IO.Pipes.NamedPipeServerStream(
    $stderrName, [System.IO.Pipes.PipeDirection]::In, 1,
    [System.IO.Pipes.PipeTransmissionMode]::Byte,
    [System.IO.Pipes.PipeOptions]::Asynchronous,
    4096, 4096, $security
)
$exitCode = 1
try {
    Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction SilentlyContinue
    $arguments = "-NoProfile -NonInteractive -ExecutionPolicy Bypass -File `"$childPath`" -TaskName $taskName -ControlPipe $controlName -StdoutPipe $stdoutName -StderrPipe $stderrName"
    $powerShellPath = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
    $action = New-ScheduledTaskAction -Execute $powerShellPath -Argument $arguments
    $principal = New-ScheduledTaskPrincipal -UserId $identity.Name -LogonType Interactive -RunLevel Limited
    $settings = New-ScheduledTaskSettingsSet -ExecutionTimeLimit ([TimeSpan]::Zero) -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries
    Register-ScheduledTask -TaskName $taskName -Action $action -Principal $principal -Settings $settings | Out-Null
    $controlConnect = $control.WaitForConnectionAsync()
    $stdoutConnect = $stdout.WaitForConnectionAsync()
    $stderrConnect = $stderr.WaitForConnectionAsync()
    __INTERACTIVE_LAUNCH__
    if (-not $controlConnect.Wait(30000) -or -not $stdoutConnect.Wait(30000) -or -not $stderrConnect.Wait(30000)) {
        throw 'The interactive bootstrap task did not connect its private pipes.'
    }

    $utf8 = New-Object System.Text.UTF8Encoding($false)
    $token = [Console]::In.ReadToEnd()
    $controlWriter = New-Object System.IO.StreamWriter($control, $utf8, 1024, $true)
    $controlWriter.AutoFlush = $true
    $controlReader = New-Object System.IO.StreamReader($control, $utf8, $false, 1024, $true)
    $controlWriter.WriteLine([Convert]::ToBase64String($utf8.GetBytes($token)))
    $token = $null
    $stdoutCopy = $stdout.CopyToAsync([Console]::OpenStandardOutput())
    $stderrCopy = $stderr.CopyToAsync([Console]::OpenStandardError())
    $exitLine = $controlReader.ReadLine()
    [void]$stdoutCopy.GetAwaiter().GetResult()
    [void]$stderrCopy.GetAwaiter().GetResult()
    if (-not [int]::TryParse($exitLine, [ref]$exitCode)) {
        throw 'The interactive bootstrap task returned an invalid exit status.'
    }
} catch {
    [Console]::Error.WriteLine("satelle-host: interactive bootstrap relay failed: $($_.Exception.Message)")
    $exitCode = 1
} finally {
    Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction SilentlyContinue
    $stderr.Dispose()
    $stdout.Dispose()
    $control.Dispose()
}
exit $exitCode
"#;

const CHILD_SCRIPT_TEMPLATE: &str = r#"param(
    [Parameter(Mandatory = $true)][string]$TaskName,
    [Parameter(Mandatory = $true)][string]$ControlPipe,
    [Parameter(Mandatory = $true)][string]$StdoutPipe,
    [Parameter(Mandatory = $true)][string]$StderrPipe
)
$ErrorActionPreference = 'Stop'
$control = New-Object System.IO.Pipes.NamedPipeClientStream(
    '.', $ControlPipe, [System.IO.Pipes.PipeDirection]::InOut,
    [System.IO.Pipes.PipeOptions]::Asynchronous
)
$stdout = New-Object System.IO.Pipes.NamedPipeClientStream(
    '.', $StdoutPipe, [System.IO.Pipes.PipeDirection]::Out,
    [System.IO.Pipes.PipeOptions]::Asynchronous
)
$stderr = New-Object System.IO.Pipes.NamedPipeClientStream(
    '.', $StderrPipe, [System.IO.Pipes.PipeDirection]::Out,
    [System.IO.Pipes.PipeOptions]::Asynchronous
)
$process = $null
$processStarted = $false
$controlWriter = $null
$stdoutCopy = $null
$stderrCopy = $null
$exitCode = 1
try {
    $control.Connect(30000)
    $stdout.Connect(30000)
    $stderr.Connect(30000)
    $utf8 = New-Object System.Text.UTF8Encoding($false)
    $controlReader = New-Object System.IO.StreamReader($control, $utf8, $false, 1024, $true)
    $controlWriter = New-Object System.IO.StreamWriter($control, $utf8, 1024, $true)
    $controlWriter.AutoFlush = $true
    $encodedToken = $controlReader.ReadLine()
    if ([string]::IsNullOrEmpty($encodedToken)) {
        throw 'The bootstrap token frame is empty.'
    }
    $token = $utf8.GetString([Convert]::FromBase64String($encodedToken))
    $decode = {
        param([string]$Value)
        [System.Text.Encoding]::Unicode.GetString([Convert]::FromBase64String($Value))
    }

    $start = New-Object System.Diagnostics.ProcessStartInfo
    $start.FileName = & $decode '__EXECUTABLE__'
    $start.WorkingDirectory = & $decode '__WORKING_DIRECTORY__'
    $start.Arguments = & $decode '__ARGUMENTS__'
    $start.UseShellExecute = $false
    $start.RedirectStandardInput = $true
    $start.RedirectStandardOutput = $true
    $start.RedirectStandardError = $true
    $environment = @{
__ENVIRONMENT__
    }
    foreach ($name in $environment.Keys) {
        if ($null -eq $environment[$name]) {
            $start.EnvironmentVariables.Remove($name)
        } else {
            $start.EnvironmentVariables[$name] = & $decode $environment[$name]
        }
    }
    $process = New-Object System.Diagnostics.Process
    $process.StartInfo = $start
    if (-not $process.Start()) {
        throw 'The interactive bootstrap process did not start.'
    }
    $processStarted = $true
    $process.StandardInput.Write($token)
    $process.StandardInput.Close()
    $token = $null
    $encodedToken = $null
    $stdoutCopy = $process.StandardOutput.BaseStream.CopyToAsync($stdout)
    $stderrCopy = $process.StandardError.BaseStream.CopyToAsync($stderr)
    $disconnectProbe = New-Object byte[] 1
    $parentClosed = $control.ReadAsync($disconnectProbe, 0, 1)
    while (-not $process.WaitForExit(500)) {
        if ($parentClosed.IsCompleted -and $parentClosed.GetAwaiter().GetResult() -eq 0) {
            $process.Kill()
            throw 'The SSH bootstrap controller disconnected.'
        }
    }
    [void]$stdoutCopy.GetAwaiter().GetResult()
    [void]$stderrCopy.GetAwaiter().GetResult()
    $exitCode = $process.ExitCode
    $controlWriter.WriteLine([string]$exitCode)
} catch {
    if ($processStarted -and -not $process.HasExited) {
        $process.Kill()
    }
    foreach ($copy in @($stdoutCopy, $stderrCopy)) {
        if ($null -ne $copy) {
            try { [void]$copy.GetAwaiter().GetResult() } catch {}
        }
    }
    try {
        $message = [System.Text.Encoding]::UTF8.GetBytes("satelle-host: interactive bootstrap task failed: $($_.Exception.Message)`r`n")
        $stderr.Write($message, 0, $message.Length)
        $stderr.Flush()
    } catch {}
    if ($null -ne $controlWriter) {
        try { $controlWriter.WriteLine('1') } catch {}
    }
    $exitCode = 1
} finally {
    Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false -ErrorAction SilentlyContinue
    if ($null -ne $process) {
        $process.Dispose()
    }
    $stderr.Dispose()
    $stdout.Dispose()
    $control.Dispose()
}
exit $exitCode
"#;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bootstrap_boundary_is_removed_once_without_changing_other_arguments() {
        let arguments = vec![
            OsString::from(r"C:\Program Files\Satelle\satelle.exe"),
            OsString::from("host"),
            OsString::from("start"),
            OsString::from(INTERACTIVE_BOOTSTRAP_BOUNDARY),
            OsString::from("--bind"),
            OsString::from("127.0.0.1:3011"),
        ];

        assert_eq!(
            current_arguments_without_boundary(arguments).unwrap(),
            vec![
                OsString::from("host"),
                OsString::from("start"),
                OsString::from("--bind"),
                OsString::from("127.0.0.1:3011"),
            ]
        );
    }

    #[test]
    fn windows_arguments_preserve_spaces_quotes_and_trailing_backslashes() {
        let arguments = vec![
            OsString::from("host"),
            OsString::from("space value"),
            OsString::from("quoted\"value"),
            OsString::from(r"C:\path with space\"),
        ];

        assert_eq!(
            quoted_arguments(&arguments),
            OsString::from(r#"host "space value" "quoted\"value" "C:\path with space\\""#)
        );
    }

    #[test]
    fn generated_scripts_keep_token_out_of_persisted_task_inputs() {
        let parent = parent_script(
            "SatelleInteractiveBootstrap-test",
            "satelle-interactive-bootstrap-test",
            Path::new(r"C:\Temp\bootstrap child.ps1"),
        );
        let child = child_script(
            OsStr::new(r"C:\Satelle\satelle.exe"),
            OsStr::new(r"C:\Satelle"),
            &[OsString::from("host"), OsString::from("start")],
        );

        assert!(parent.contains("[Console]::In.ReadToEnd()"));
        assert!(parent.contains("ToBase64String($utf8.GetBytes($token))"));
        assert!(parent.contains("WTSEnumerateSessionsW"));
        assert!(parent.contains("ResolveActiveSession($identity.User.Value)"));
        assert!(parent.contains("GetFolder('\\')"));
        assert!(parent.contains("RunEx($null,4,$session.SessionId,$session.UserName)"));
        assert!(!parent.contains("Start-ScheduledTask"));
        assert!(parent.contains("AllowStartIfOnBatteries"));
        assert!(parent.contains("DontStopIfGoingOnBatteries"));
        assert!(parent.contains("$powerShellPath"));
        assert!(!parent.contains("--bootstrap-token"));
        assert!(!child.contains("--interactive-bootstrap"));
        assert!(child.contains("FromBase64String($encodedToken)"));
        assert!(child.contains("$process.StandardInput.Write($token)"));
    }
}
