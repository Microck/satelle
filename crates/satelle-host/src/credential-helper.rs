use crate::codex_capabilities::terminate_group;
use crate::provider_auth::{ProviderAuthResolutionError, ProviderHostPlatform};
use command_group::CommandGroup;
use satelle_core::CredentialHelper;
use serde::{Deserialize, Serialize};
use std::io::{Read, Write};
use std::process::{ChildStdout, Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};
use zeroize::Zeroizing;

const OUTPUT_LIMIT: usize = 64 * 1024;
const REQUEST_LIMIT: usize = 2048;
const POLL: Duration = Duration::from_millis(5);
const INHERITED_ENVIRONMENT: &[&str] = &[
    "HOME",
    "USERPROFILE",
    "SystemRoot",
    "WINDIR",
    "TMPDIR",
    "TMP",
    "TEMP",
    "LANG",
    "LC_ALL",
];

#[derive(Serialize)]
pub(crate) struct CredentialHelperRequest<'a> {
    schema_version: u8,
    operation: &'static str,
    provider_alias: &'a str,
    resolved_provider: &'a str,
    host_alias: &'a str,
}

impl<'a> CredentialHelperRequest<'a> {
    pub(crate) fn new(
        provider_alias: &'a str,
        resolved_provider: &'a str,
        host_alias: &'a str,
    ) -> Self {
        Self {
            schema_version: 1,
            operation: "resolve",
            provider_alias,
            resolved_provider,
            host_alias,
        }
    }
}

#[derive(Deserialize)]
#[serde(tag = "status", rename_all = "snake_case", deny_unknown_fields)]
enum HelperResponse {
    Success {
        schema_version: u8,
        #[serde(deserialize_with = "zeroizing_string")]
        secret: Zeroizing<String>,
    },
    Error {
        #[serde(rename = "schema_version")]
        _schema_version: u8,
        #[serde(rename = "code", deserialize_with = "zeroizing_string")]
        _code: Zeroizing<String>,
    },
    InteractionRequired {
        #[serde(rename = "schema_version")]
        _schema_version: u8,
        #[serde(rename = "code", deserialize_with = "zeroizing_string")]
        _code: Zeroizing<String>,
    },
}

fn zeroizing_string<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> Result<Zeroizing<String>, D::Error> {
    String::deserialize(deserializer).map(Zeroizing::new)
}

/// Runs only at the Host's explicit provider-auth boundary. Neither process
/// output nor OS errors leave this module; callers receive a secret or a closed
/// failure. Inspection uses the descriptor validator and never calls this.
pub(crate) fn resolve(
    helper: &CredentialHelper,
    request: &CredentialHelperRequest<'_>,
) -> Result<Zeroizing<String>, ProviderAuthResolutionError> {
    use ProviderAuthResolutionError::{HelperTimeout, Unresolved};
    if !helper.executable_is_absolute_for(
        ProviderHostPlatform::current() == ProviderHostPlatform::Windows,
    ) {
        return Err(ProviderAuthResolutionError::InvalidHelperArgv);
    }
    let request = serde_json::to_vec(request).map_err(|_| Unresolved)?;
    // This finite request fits in an empty anonymous stdin pipe on every Host
    // platform. The limit also bounds aliases supplied by a Controller.
    if request.len() > REQUEST_LIMIT {
        return Err(Unresolved);
    }
    let timeout = Duration::from_millis(helper.timeout().milliseconds());
    let started = Instant::now();
    let deadline = started.checked_add(timeout).ok_or(Unresolved)?;
    let mut command = Command::new(&helper.argv()[0]);
    command.args(&helper.argv()[1..]).env_clear();
    for name in INHERITED_ENVIRONMENT {
        if let Some(value) = std::env::var_os(name) {
            command.env(name, value);
        }
    }
    command.envs(helper.environment());
    let mut child = command
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .group_spawn()
        .map_err(|_| Unresolved)?;
    let mut stdin = child
        .inner()
        .stdin
        .take()
        .expect("the helper has piped stdin");
    let stdout = child
        .inner()
        .stdout
        .take()
        .expect("the helper has piped stdout");
    let request_written = stdin.write_all(&request).is_ok();
    drop(stdin);
    if !request_written {
        let _ = terminate_group(&mut child);
        return Err(Unresolved);
    }
    let reader = thread::spawn(move || read_response(stdout, deadline));
    let status = loop {
        match child.inner().try_wait() {
            Ok(Some(status)) => break Ok(status),
            Ok(None) if Instant::now() < deadline => thread::sleep(POLL),
            Ok(None) => break Err(HelperTimeout),
            Err(_) => break Err(Unresolved),
        }
    };
    let stopped = terminate_group(&mut child);
    let output = reader.join().map_err(|_| Unresolved)?;
    tracing::debug!(
        target: "satelle::provider_auth",
        helper_kind = "executable-helper",
        duration_ms = started.elapsed().as_millis() as u64,
        timeout_ms = helper.timeout().milliseconds(),
        exit_code = status.as_ref().ok().and_then(|status| status.code()),
        group_stopped = stopped,
        response_received = output.is_ok(),
        "credential helper completed"
    );
    let status = status?;
    if !stopped || !status.success() {
        return Err(Unresolved);
    }
    decode_response(&output?)
}

fn decode_response(output: &[u8]) -> Result<Zeroizing<String>, ProviderAuthResolutionError> {
    use ProviderAuthResolutionError::Unresolved;
    // from_slice consumes exactly one complete JSON value and rejects trailing
    // non-whitespace, including a second response or diagnostic output.
    match serde_json::from_slice::<HelperResponse>(output).map_err(|_| Unresolved)? {
        HelperResponse::Success {
            schema_version: 1,
            secret,
        } if !secret.is_empty() && !secret.contains('\0') => Ok(secret),
        // Failure fields are required but never become Satelle error text,
        // log fields, or state. Their contents cannot turn failure into success.
        HelperResponse::Error { .. } | HelperResponse::InteractionRequired { .. } => {
            Err(Unresolved)
        }
        _ => Err(Unresolved),
    }
}

fn read_response(
    mut stdout: ChildStdout,
    deadline: Instant,
) -> Result<Zeroizing<Vec<u8>>, ProviderAuthResolutionError> {
    use ProviderAuthResolutionError::{HelperTimeout, Unresolved};
    #[cfg(unix)]
    crate::codex_capabilities::set_nonblocking(&stdout).map_err(|_| Unresolved)?;
    let mut output = Zeroizing::new(Vec::with_capacity(OUTPUT_LIMIT));
    let mut buffer = Zeroizing::new([0_u8; 4096]);
    loop {
        if Instant::now() >= deadline {
            return Err(HelperTimeout);
        }
        #[cfg(windows)]
        let available = available_stdout(&stdout).map_err(|_| Unresolved)?;
        #[cfg(windows)]
        if available == Some(0) {
            thread::sleep(POLL);
            continue;
        }
        #[cfg(windows)]
        if available.is_none() {
            return Ok(output);
        }
        #[cfg(windows)]
        let capacity = buffer.len().min(available.unwrap_or_default() as usize);
        #[cfg(not(windows))]
        let capacity = buffer.len();
        match stdout.read(&mut buffer[..capacity]) {
            Ok(0) => return Ok(output),
            Ok(count) => {
                if output.len() + count > OUTPUT_LIMIT {
                    return Err(Unresolved);
                }
                output.extend_from_slice(&buffer[..count]);
            }
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => thread::sleep(POLL),
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {}
            Err(_) => return Err(Unresolved),
        }
    }
}

#[cfg(windows)]
fn available_stdout(stdout: &ChildStdout) -> std::io::Result<Option<u32>> {
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::System::Pipes::PeekNamedPipe;
    let mut available = 0;
    // Anonymous child pipes support PeekNamedPipe. Reading only available
    // bytes makes a retained pipe subject to the same deadline as the leader.
    let peeked = unsafe {
        PeekNamedPipe(
            stdout.as_raw_handle(),
            std::ptr::null_mut(),
            0,
            std::ptr::null_mut(),
            &mut available,
            std::ptr::null_mut(),
        )
    };
    if peeked != 0 {
        return Ok(Some(available));
    }
    let error = std::io::Error::last_os_error();
    if error.kind() == std::io::ErrorKind::BrokenPipe {
        Ok(None)
    } else {
        Err(error)
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use satelle_core::{ExplicitDuration, ProviderSecretSource};
    use std::collections::BTreeMap;

    // A real executable helper with real pipes. Python is already required by
    // the repository's CI tooling; this lookup happens only in test fixtures.
    pub(crate) fn helper(mode: &str, timeout: &str) -> (tempfile::TempDir, CredentialHelper) {
        let python = Command::new(if cfg!(windows) { "python" } else { "python3" })
            .args(["-c", "import sys; print(sys.executable)"])
            .output()
            .expect("locate the test Python executable");
        assert!(python.status.success());
        let python = String::from_utf8(python.stdout).unwrap().trim().to_string();
        let directory = tempfile::tempdir().unwrap();
        let script = directory.path().join("credential-helper.py");
        std::fs::write(&script, r#"
import json, os, subprocess, sys, time
request = json.load(sys.stdin)
assert request == {"schema_version": 1, "operation": "resolve", "provider_alias": "provider-alias", "resolved_provider": "openai", "host_alias": "host-alias"}
if os.name == "nt":
    # Windows isatty detects character devices, including the NUL stderr sink.
    # GetConsoleMode tests whether the inherited handles actually use a console.
    import ctypes, ctypes.wintypes, msvcrt
    console_mode = ctypes.windll.kernel32.GetConsoleMode
    console_mode.argtypes = [ctypes.wintypes.HANDLE, ctypes.POINTER(ctypes.wintypes.DWORD)]
    console_mode.restype = ctypes.wintypes.BOOL
    for stream in [sys.stdin, sys.stdout, sys.stderr]:
        mode = ctypes.wintypes.DWORD()
        assert not console_mode(msvcrt.get_osfhandle(stream.fileno()), ctypes.byref(mode))
else:
    assert not sys.stdin.isatty() and not sys.stdout.isatty() and not sys.stderr.isatty()
assert "PATH" not in os.environ and not any(key.startswith("SATELLE_") for key in os.environ)
assert os.environ["HELPER_ACCOUNT"] == "private-account"
assert sys.argv[2] == "literal $value with spaces"
mode = sys.argv[1]
response = {"schema_version": 1, "status": "success", "secret": "test-provider-secret"}
if mode == "sleep":
    time.sleep(30)
elif mode == "descendant":
    subprocess.Popen([sys.executable, "-c", "import time; time.sleep(30)"])
elif mode == "stderr":
    sys.stderr.write("must-not-leak-raw-diagnostics" * 8192)
elif mode == "nonzero":
    print(json.dumps(response), flush=True)
    sys.exit(3)
elif mode == "invalid":
    print("this is not JSON")
    sys.exit(0)
elif mode == "multiple":
    print(json.dumps(response))
elif mode == "oversized":
    response["secret"] = "a" * 65536
elif mode == "nul":
    response["secret"] = "bad\u0000secret"
elif mode == "missing":
    del response["secret"]
elif mode == "unknown":
    response["diagnostic"] = "must-not-leak"
elif mode == "version":
    response["schema_version"] = 2
elif mode == "error" or mode == "interaction_required":
    response = {"schema_version": 1, "status": mode, "code": "must-not-leak"}
elif mode == "nonutf8":
    sys.stdout.buffer.write(b"\xff")
    sys.exit(0)
print(json.dumps(response), flush=True)
"#).unwrap();
        let descriptor = CredentialHelper::new(
            vec![
                python,
                script.to_str().unwrap().to_string(),
                mode.to_string(),
                "literal $value with spaces".to_string(),
            ],
            ExplicitDuration::parse(timeout).unwrap(),
            BTreeMap::from([("HELPER_ACCOUNT".to_string(), "private-account".to_string())]),
        )
        .unwrap();
        (directory, descriptor)
    }

    fn request() -> CredentialHelperRequest<'static> {
        CredentialHelperRequest::new("provider-alias", "openai", "host-alias")
    }

    #[test]
    fn helper_uses_one_request_literal_arguments_and_a_private_environment() {
        for mode in ["success", "stderr", "descendant"] {
            let (_directory, helper) = helper(mode, "10s");
            let secret = crate::provider_auth::resolve_provider_secret(
                &ProviderSecretSource::ExecutableHelper(helper),
                &request(),
            )
            .unwrap_or_else(|error| panic!("resolve real JSON helper {mode}: {error:?}"));
            assert!(secret.expose_to_provider(|value| value == "test-provider-secret"));
            assert!(!format!("{secret:?}").contains("test-provider-secret"));
        }
    }

    #[test]
    fn helper_rejects_failed_interactive_and_malformed_responses() {
        for mode in [
            "nonzero",
            "invalid",
            "multiple",
            "oversized",
            "nul",
            "missing",
            "unknown",
            "version",
            "error",
            "interaction_required",
            "nonutf8",
        ] {
            let (_directory, helper) = helper(mode, "10s");
            let error = resolve(&helper, &request()).unwrap_err();
            assert_eq!(error, ProviderAuthResolutionError::Unresolved, "{mode}");
            assert!(!format!("{error:?}").contains("must-not-leak"));
        }
    }

    #[test]
    fn helper_timeout_stops_the_process_and_returns_a_typed_failure() {
        let (_directory, helper) = helper("sleep", "200ms");
        let started = Instant::now();
        assert_eq!(
            resolve(&helper, &request()).unwrap_err(),
            ProviderAuthResolutionError::HelperTimeout
        );
        assert!(started.elapsed() < Duration::from_secs(5));
    }
}
