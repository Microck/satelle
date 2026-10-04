use std::env;
use std::ffi::{OsStr, OsString};
use std::fs;
use std::io;
use std::os::windows::ffi::{OsStrExt, OsStringExt};
use std::os::windows::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitStatus, Stdio};

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

/// The task's hidden launcher owns the only surviving job handle. Windows
/// terminates this daemon and its children when that launcher ends, including
/// Task Scheduler stops which do not otherwise guarantee child cleanup.
pub(super) fn bind_service_lifetime_to_parent() -> io::Result<()> {
    use std::mem::{size_of, zeroed};
    use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};
    use std::ptr::{null, null_mut};
    use winapi::shared::minwindef::{FALSE, FILETIME};
    use winapi::um::handleapi::{DuplicateHandle, INVALID_HANDLE_VALUE};
    use winapi::um::jobapi2::{
        AssignProcessToJobObject, CreateJobObjectW, SetInformationJobObject,
    };
    use winapi::um::processthreadsapi::{
        GetCurrentProcess, GetCurrentProcessId, GetProcessTimes, OpenProcess,
    };
    use winapi::um::tlhelp32::{
        CreateToolhelp32Snapshot, PROCESSENTRY32W, Process32FirstW, Process32NextW,
        TH32CS_SNAPPROCESS,
    };
    use winapi::um::winnt::{
        DUPLICATE_CLOSE_SOURCE, DUPLICATE_SAME_ACCESS, JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
        JOBOBJECT_EXTENDED_LIMIT_INFORMATION, JobObjectExtendedLimitInformation,
        PROCESS_DUP_HANDLE, PROCESS_QUERY_LIMITED_INFORMATION,
    };

    // Each non-pseudo handle stays owned until Windows has accepted the transfer.
    let snapshot = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) };
    if snapshot == INVALID_HANDLE_VALUE {
        return Err(io::Error::last_os_error());
    }
    let snapshot = unsafe { OwnedHandle::from_raw_handle(snapshot.cast()) };
    let mut entry: PROCESSENTRY32W = unsafe { zeroed() };
    entry.dwSize = size_of::<PROCESSENTRY32W>() as u32;
    let current = unsafe { GetCurrentProcess() };
    let current_id = unsafe { GetCurrentProcessId() };
    let mut found =
        unsafe { Process32FirstW(snapshot.as_raw_handle().cast(), &mut entry) } != FALSE;
    while found && entry.th32ProcessID != current_id {
        found = unsafe { Process32NextW(snapshot.as_raw_handle().cast(), &mut entry) } != FALSE;
    }
    if !found || entry.th32ParentProcessID == 0 {
        return Err(io::Error::other(
            "The managed service launcher is unavailable.",
        ));
    }
    let parent = unsafe {
        OpenProcess(
            PROCESS_DUP_HANDLE | PROCESS_QUERY_LIMITED_INFORMATION,
            FALSE,
            entry.th32ParentProcessID,
        )
    };
    if parent.is_null() {
        return Err(io::Error::last_os_error());
    }
    let parent = unsafe { OwnedHandle::from_raw_handle(parent.cast()) };
    let creation_time = |process| -> io::Result<u64> {
        let mut created: FILETIME = unsafe { zeroed() };
        let mut exited: FILETIME = unsafe { zeroed() };
        let mut kernel: FILETIME = unsafe { zeroed() };
        let mut user: FILETIME = unsafe { zeroed() };
        if unsafe { GetProcessTimes(process, &mut created, &mut exited, &mut kernel, &mut user) }
            == FALSE
        {
            return Err(io::Error::last_os_error());
        }
        Ok((u64::from(created.dwHighDateTime) << 32) | u64::from(created.dwLowDateTime))
    };
    // A reused parent PID cannot acquire ownership of this daemon.
    if creation_time(parent.as_raw_handle().cast())? > creation_time(current)? {
        return Err(io::Error::other(
            "The managed service launcher identity changed.",
        ));
    }
    let job = unsafe { CreateJobObjectW(null_mut(), null()) };
    if job.is_null() {
        return Err(io::Error::last_os_error());
    }
    let job = unsafe { OwnedHandle::from_raw_handle(job.cast()) };
    let mut limits: JOBOBJECT_EXTENDED_LIMIT_INFORMATION = unsafe { zeroed() };
    limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
    if unsafe {
        SetInformationJobObject(
            job.as_raw_handle().cast(),
            JobObjectExtendedLimitInformation,
            (&mut limits as *mut JOBOBJECT_EXTENDED_LIMIT_INFORMATION).cast(),
            size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
        )
    } == FALSE
    {
        return Err(io::Error::last_os_error());
    }
    let mut parent_job = null_mut();
    if unsafe {
        DuplicateHandle(
            current,
            job.as_raw_handle().cast(),
            parent.as_raw_handle().cast(),
            &mut parent_job,
            0,
            FALSE,
            DUPLICATE_SAME_ACCESS,
        )
    } == FALSE
    {
        return Err(io::Error::last_os_error());
    }
    if unsafe { AssignProcessToJobObject(job.as_raw_handle().cast(), current) } == FALSE {
        let error = io::Error::last_os_error();
        // No child has entered this job. Undo only the handle transferred above.
        let mut returned = null_mut();
        if unsafe {
            DuplicateHandle(
                parent.as_raw_handle().cast(),
                parent_job,
                current,
                &mut returned,
                0,
                FALSE,
                DUPLICATE_SAME_ACCESS | DUPLICATE_CLOSE_SOURCE,
            )
        } != FALSE
        {
            drop(unsafe { OwnedHandle::from_raw_handle(returned.cast()) });
        }
        return Err(error);
    }
    // Closing this copy leaves the launcher's handle as the sole job owner.
    drop(job);
    Ok(())
}

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
        satelle::core::open_or_create_owner_only_directory(&script_directory)
            .map_err(|error| io::Error::other(error.to_string()))?;

    let run_result = (|| {
        write_windows_powershell_script(&child_path, &child_script)?;
        write_windows_powershell_script(&parent_path, &parent_script)?;
        Command::new(windows_powershell_path()?)
            .creation_flags(winapi::um::winbase::CREATE_NO_WINDOW)
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

/// Starts the managed local Host Daemon in the authenticated user's desktop
/// session. The scheduled task remains the daemon's process owner until the
/// daemon exits, so a short-lived controller cannot tear down detached work.
pub(super) fn launch_detached_local_daemon(
    arguments: &[OsString],
    forwarded_environment: &[String],
) -> io::Result<()> {
    let nonce = Uuid::now_v7().simple().to_string();
    let task_name = format!("SatelleLocalDaemon-{nonce}");
    let script_directory = env::temp_dir().join(format!("satelle-local-daemon-{nonce}"));
    let parent_path = script_directory.join("local-daemon-parent.ps1");
    let executable = env::current_exe()?;
    let working_directory = env::current_dir()?;
    let child = detached_local_daemon_script(
        &task_name,
        executable.as_os_str(),
        working_directory.as_os_str(),
        arguments,
        forwarded_environment,
    );
    let parent = detached_local_daemon_parent_script(&task_name, &child);
    let script_directory_guard =
        satelle::core::open_or_create_owner_only_directory(&script_directory)
            .map_err(|error| io::Error::other(error.to_string()))?;

    let run_result = (|| {
        write_windows_powershell_script(&parent_path, &parent)?;
        // Keep the launcher's diagnostics: when Task Scheduler registration or
        // the interactive-session handoff fails, its message is the only
        // evidence, so it travels with the error instead of being discarded.
        let output = Command::new(windows_powershell_path()?)
            .creation_flags(winapi::um::winbase::CREATE_NO_WINDOW)
            .args([
                "-NoProfile",
                "-NonInteractive",
                "-ExecutionPolicy",
                "Bypass",
                "-File",
            ])
            .arg(&parent_path)
            .stdin(Stdio::null())
            .output()?;
        if output.status.success() {
            return Ok(());
        }
        let stderr = String::from_utf8_lossy(&output.stderr);
        let detail = stderr
            .lines()
            .map(str::trim)
            .filter(|line| !line.is_empty())
            .take(6)
            .collect::<Vec<_>>()
            .join(" | ");
        Err(io::Error::other(format!(
            "the managed local daemon task did not start (exit {}): {detail}",
            output.status
        )))
    })();
    drop(script_directory_guard);
    if let Err(error) = fs::remove_dir_all(&script_directory) {
        eprintln!(
            "warning: failed to remove local daemon launch script at {}: {error}",
            script_directory.display()
        );
    }
    run_result
}

fn detached_local_daemon_script(
    task_name: &str,
    executable: &OsStr,
    working_directory: &OsStr,
    arguments: &[OsString],
    forwarded_environment: &[String],
) -> String {
    let mut environment_names = DAEMON_PATH_ENVIRONMENT_VARIABLES.to_vec();
    environment_names.push("SATELLE_TEST_SUPPORT_ADAPTER");
    environment_names.extend(forwarded_environment.iter().map(String::as_str));
    let environment = environment_names
        .into_iter()
        .map(|name| {
            let value = env::var_os(name)
                .map(|value| format!("'{}'", utf16_base64(&value)))
                .unwrap_or_else(|| "$null".to_owned());
            format!("    '{name}' = {value}")
        })
        .collect::<Vec<_>>()
        .join("\n");
    DETACHED_LOCAL_DAEMON_TEMPLATE
        .replace("__TASK_NAME__", task_name)
        .replace("__EXECUTABLE__", &utf16_base64(executable))
        .replace("__WORKING_DIRECTORY__", &utf16_base64(working_directory))
        .replace("__ARGUMENTS__", &utf16_base64(&quoted_arguments(arguments)))
        .replace("__ENVIRONMENT__", &environment)
}

fn detached_local_daemon_parent_script(task_name: &str, child: &str) -> String {
    let encoded_child = utf16_base64(OsStr::new(child));
    let interactive_launch = crate::transport::windows_interactive_task_launch_script(
        r"\",
        task_name,
        "$identity.User.Value",
    );
    DETACHED_LOCAL_DAEMON_PARENT_TEMPLATE
        .replace("__TASK_NAME__", task_name)
        .replace("__ENCODED_CHILD__", &encoded_child)
        .replace("__INTERACTIVE_LAUNCH__", &interactive_launch)
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

const DETACHED_LOCAL_DAEMON_PARENT_TEMPLATE: &str = r#"$ErrorActionPreference = 'Stop'
$taskName = '__TASK_NAME__'
$encodedChild = '__ENCODED_CHILD__'
$identity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction SilentlyContinue
$powerShellPath = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
$arguments = "-NoProfile -NonInteractive -WindowStyle Hidden -ExecutionPolicy Bypass -EncodedCommand $encodedChild"
$action = New-ScheduledTaskAction -Execute $powerShellPath -Argument $arguments
$principal = New-ScheduledTaskPrincipal -UserId $identity.Name -LogonType Interactive -RunLevel Limited
$settings = New-ScheduledTaskSettingsSet -Priority 4 -ExecutionTimeLimit ([TimeSpan]::Zero) -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries
Register-ScheduledTask -TaskName $taskName -Action $action -Principal $principal -Settings $settings | Out-Null
try {
    __INTERACTIVE_LAUNCH__
} catch {
    Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction SilentlyContinue
    throw
}
"#;

const DETACHED_LOCAL_DAEMON_TEMPLATE: &str = r#"$ErrorActionPreference = 'Stop'
$taskName = '__TASK_NAME__'
$decode = {
    param([string]$Value)
    [System.Text.Encoding]::Unicode.GetString([Convert]::FromBase64String($Value))
}
try {
    $environment = @{
__ENVIRONMENT__
    }
    foreach ($name in $environment.Keys) {
        if ($null -eq $environment[$name]) {
            [Environment]::SetEnvironmentVariable($name, $null, 'Process')
        } else {
            [Environment]::SetEnvironmentVariable($name, (& $decode $environment[$name]), 'Process')
        }
    }
    $start = New-Object System.Diagnostics.ProcessStartInfo
    $start.FileName = & $decode '__EXECUTABLE__'
    $start.WorkingDirectory = & $decode '__WORKING_DIRECTORY__'
    $start.Arguments = & $decode '__ARGUMENTS__'
    $start.UseShellExecute = $false
    $start.CreateNoWindow = $true
    $start.RedirectStandardInput = $false
    $start.RedirectStandardOutput = $false
    $start.RedirectStandardError = $false
    $process = New-Object System.Diagnostics.Process
    $process.StartInfo = $start
    if (-not $process.Start()) {
        throw 'The managed local daemon process did not start.'
    }
    $process.WaitForExit()
    exit $process.ExitCode
} finally {
    Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction SilentlyContinue
}
"#;

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
    $arguments = "-NoProfile -NonInteractive -WindowStyle Hidden -ExecutionPolicy Bypass -File `"$childPath`" -TaskName $taskName -ControlPipe $controlName -StdoutPipe $stdoutName -StderrPipe $stderrName"
    $powerShellPath = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
    $action = New-ScheduledTaskAction -Execute $powerShellPath -Argument $arguments
    $principal = New-ScheduledTaskPrincipal -UserId $identity.Name -LogonType Interactive -RunLevel Limited
    $settings = New-ScheduledTaskSettingsSet -Priority 4 -ExecutionTimeLimit ([TimeSpan]::Zero) -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries
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
    $start.CreateNoWindow = $true
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
    #[ignore = "real child process invoked by service_job_ends_with_hidden_launcher"]
    fn service_job_child() {
        let ready = env::var_os("SATELLE_SERVICE_JOB_TEST_READY").expect("owned job-test path");
        bind_service_lifetime_to_parent().expect("bind daemon lifetime to real parent");
        assert!(unsafe { windows_sys::Win32::System::Console::GetConsoleWindow() }.is_null());
        fs::write(ready, std::process::id().to_string()).expect("publish test child identity");
        std::thread::sleep(std::time::Duration::from_secs(60));
        panic!("The child survived its managed launcher.");
    }

    #[test]
    fn service_job_ends_with_hidden_launcher() {
        use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};
        use winapi::um::processthreadsapi::OpenProcess;
        use winapi::um::winnt::SYNCHRONIZE;
        use windows_sys::Win32::System::Threading::WaitForSingleObject;
        let directory = tempfile::tempdir().expect("owned service job fixture");
        let ready = directory.path().join("ready-pid");
        let script = directory.path().join("owner.ps1");
        let executable = env::current_exe().expect("real test executable");
        let arguments = OsString::from(
            "--exact windows_interactive_bootstrap::tests::service_job_child --ignored --nocapture",
        );
        let quoted_executable = executable.to_string_lossy().replace('\'', "''");
        let quoted_arguments = arguments.to_string_lossy().replace('\'', "''");
        let script_contents = format!(
            "$ErrorActionPreference='Stop'\n$start=New-Object System.Diagnostics.ProcessStartInfo\n$start.FileName='{}'\n$start.Arguments='{}'\n$start.UseShellExecute=$false\n$start.CreateNoWindow=$true\n$child=[System.Diagnostics.Process]::Start($start)\n$child.WaitForExit()\nexit $child.ExitCode\n",
            quoted_executable, quoted_arguments,
        );
        write_windows_powershell_script(&script, &script_contents)
            .expect("write hidden test owner");
        let mut owner = Command::new(windows_powershell_path().expect("system PowerShell"))
            .creation_flags(winapi::um::winbase::CREATE_NO_WINDOW)
            .args(["-NoProfile", "-NonInteractive", "-File"])
            .arg(&script)
            .env("SATELLE_SERVICE_JOB_TEST_READY", &ready)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("launch real hidden parent");
        let result = (|| -> io::Result<()> {
            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(20);
            while !ready.is_file() {
                if owner.try_wait()?.is_some() || std::time::Instant::now() >= deadline {
                    return Err(io::Error::other(
                        "The real service job child did not become ready.",
                    ));
                }
                std::thread::sleep(std::time::Duration::from_millis(20));
            }
            let pid: u32 = fs::read_to_string(&ready)?
                .parse()
                .map_err(io::Error::other)?;
            let child = unsafe { OpenProcess(SYNCHRONIZE, 0, pid) };
            if child.is_null() {
                return Err(io::Error::last_os_error());
            }
            let child = unsafe { OwnedHandle::from_raw_handle(child.cast()) };
            owner.kill()?;
            owner.wait()?;
            // The handle pins this exact child. A PID reuse cannot pass the proof.
            if unsafe { WaitForSingleObject(child.as_raw_handle().cast(), 5_000) } != 0 {
                return Err(io::Error::other(
                    "The daemon outlived its managed task launcher.",
                ));
            }
            Ok(())
        })();
        if result.is_err() {
            let _ = owner.kill();
            let _ = owner.wait();
        }
        let output = owner
            .wait_with_output()
            .expect("collect owned launcher output");
        assert!(
            result.is_ok(),
            "{result:?}\n{}\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }

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
        assert!(parent.contains("-WindowStyle Hidden"));
        assert!(child.contains("$start.CreateNoWindow = $true"));
        assert!(!parent.contains("--bootstrap-token"));
        assert!(!child.contains("--interactive-bootstrap"));
        assert!(child.contains("FromBase64String($encodedToken)"));
        assert!(child.contains("$process.StandardInput.Write($token)"));
    }
}
