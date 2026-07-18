use assert_cmd::{Command, assert::OutputAssertExt};
use predicates::prelude::*;
use satelle_test_contract::assert_error_process;
use serde_json::{Value, json};
use std::fs;
use std::path::{Path, PathBuf};
use tempfile::TempDir;

const MAX_GENERATED_SCRIPT_BYTES: usize = 256 * 1024;

fn assert_completion_json_error(stderr: &[u8], code: &str, suggestion: &str) {
    let report: Value = serde_json::from_slice(stderr).expect("stderr should be one JSON value");
    assert_eq!(report["schema_version"], "satelle.error.v1");
    assert_eq!(report["code"], code);
    assert_eq!(report["category"], "internal");
    assert_eq!(report["retryable"], false);
    assert_eq!(report["details"], Value::Null);
    assert_eq!(report["docs_url"], Value::Null);
    assert_eq!(report["suggested_commands"], json!([suggestion]));
    assert!(
        report["message"]
            .as_str()
            .is_some_and(|message| !message.is_empty())
    );

    let raw = String::from_utf8_lossy(stderr);
    assert!(!raw.contains('\u{1b}'), "JSON error contained ANSI escapes");
    assert!(!raw.contains("panicked"), "JSON error exposed a panic");
    assert!(!raw.contains("backtrace"), "JSON error exposed a backtrace");
}

fn satelle(home: &Path, satelle_home: &Path) -> Command {
    let mut command = Command::cargo_bin("satelle").expect("satelle binary should build");
    for name in [
        "SATELLE_CONFIG_FILE",
        "SATELLE_STATE_DIR",
        "SATELLE_CACHE_DIR",
        "SATELLE_LOG_DIR",
        "SATELLE_HOST",
        "SATELLE_PROFILE",
        "SATELLE_ERROR_FORMAT",
        "SATELLE_TEST_SUPPORT_ADAPTER",
    ] {
        command.env_remove(name);
    }
    command
        .env("HOME", home)
        .env("USERPROFILE", home)
        .env("XDG_CONFIG_HOME", home.join(".config"))
        .env("SATELLE_HOME", satelle_home);
    command
}

fn generate(shell: &str, fixture: &TempDir, namespace: &str) -> Vec<u8> {
    let home = fixture.path().join(format!("{namespace}-home"));
    let satelle_home = fixture.path().join(format!("{namespace}-satelle-home"));
    let output = satelle(&home, &satelle_home)
        .current_dir(fixture.path())
        .env("SHELL", "/bin/hostile-shell-value")
        .args(["completions", shell])
        .assert()
        .success()
        .stderr(predicate::str::is_empty())
        .get_output()
        .clone();

    assert!(
        !satelle_home.exists(),
        "{shell} generation initialized Satelle state"
    );
    output.stdout
}

fn install_with_profile(
    shell: &str,
    output_dir: &Path,
    profile: &Path,
    fixture: &TempDir,
) -> PathBuf {
    let installed_path = output_dir.join(match shell {
        "bash" => "satelle.bash",
        "powershell" => "_satelle.ps1",
        _ => panic!("unsupported evaluation shell {shell}"),
    });
    satelle(
        &fixture.path().join("home"),
        &fixture.path().join("untouched-satelle-home"),
    )
    .args(["completions", shell, "--output-dir"])
    .arg(output_dir)
    .arg("--update-profile")
    .arg(profile)
    .assert()
    .success()
    .stdout(format!("{}\n", installed_path.display()))
    .stderr(predicate::str::is_empty());
    installed_path
}

#[test]
fn generated_scripts_are_deterministic_bounded_and_side_effect_free() {
    for shell in ["bash", "zsh", "fish", "powershell"] {
        let fixture = TempDir::new().expect("test directory should be created");
        let first = generate(shell, &fixture, "first");
        let second = generate(shell, &fixture, "second");

        assert_eq!(
            first, second,
            "{shell} generation depended on environment or filesystem state"
        );
        assert!(!first.is_empty(), "{shell} generated an empty script");
        assert!(
            first.len() <= MAX_GENERATED_SCRIPT_BYTES,
            "{shell} script exceeded the automation size bound: {} bytes",
            first.len()
        );
        assert!(
            !first.contains(&0),
            "{shell} script contained a NUL byte unsafe for shell evaluation"
        );
    }
}

#[test]
fn bash_profile_activation_is_syntax_valid_and_does_not_evaluate_path_text() {
    let fixture = TempDir::new().expect("test directory should be created");
    let output_dir = fixture
        .path()
        .join("completion $(touch injected) 'quoted'; echo unsafe");
    let profile = fixture.path().join("profile.bash");
    let installed = install_with_profile("bash", &output_dir, &profile, &fixture);

    std::process::Command::new("bash")
        .args(["--noprofile", "--norc", "-n"])
        .arg(&installed)
        .assert()
        .success()
        .stdout(predicate::str::is_empty())
        .stderr(predicate::str::is_empty());
    std::process::Command::new("bash")
        .args(["--noprofile", "--norc"])
        .arg(&profile)
        .current_dir(fixture.path())
        .assert()
        .success()
        .stdout(predicate::str::is_empty())
        .stderr(predicate::str::is_empty());

    assert!(
        !fixture.path().join("injected").exists(),
        "bash evaluated completion path text as a command"
    );
}

#[test]
fn powershell_profile_activation_is_valid_and_does_not_evaluate_path_text() {
    let fixture = TempDir::new().expect("test directory should be created");
    let output_dir = fixture
        .path()
        .join("completion $(New-Item injected) 'quoted'; Write-Output unsafe");
    let profile = fixture.path().join("profile.ps1");
    install_with_profile("powershell", &output_dir, &profile, &fixture);

    std::process::Command::new("pwsh")
        .args(["-NoLogo", "-NoProfile", "-NonInteractive", "-File"])
        .arg(&profile)
        .current_dir(fixture.path())
        .assert()
        .success()
        .stdout(predicate::str::is_empty())
        .stderr(predicate::str::is_empty());

    assert!(
        !fixture.path().join("injected").exists(),
        "PowerShell evaluated completion path text as a command"
    );
}

#[cfg(unix)]
#[test]
fn installation_rejects_a_symlink_destination_without_changing_its_target() {
    use std::os::unix::fs::symlink;

    let fixture = TempDir::new().expect("test directory should be created");
    let output_dir = fixture.path().join("completions");
    let destination = output_dir.join("satelle.bash");
    let target = fixture.path().join("operator-file");
    let original = b"operator-owned bytes\n";
    fs::create_dir(&output_dir).expect("output directory should be created");
    fs::write(&target, original).expect("target file should be written");
    symlink(&target, &destination).expect("completion symlink should be created");

    let output = satelle(
        &fixture.path().join("home"),
        &fixture.path().join("untouched-satelle-home"),
    )
    .args(["completions", "bash", "--output-dir"])
    .arg(&output_dir)
    .assert()
    .code(73)
    .stdout(predicate::str::is_empty())
    .stderr(
        predicate::str::contains("completion-install-failed")
            .and(predicate::str::contains("regular file"))
            .and(predicate::str::contains("panicked").not())
            .and(predicate::str::contains("backtrace").not()),
    )
    .get_output()
    .clone();

    assert_error_process(&output);
    assert_eq!(
        fs::read(&target).expect("operator file should remain readable"),
        original
    );
    assert!(
        fs::symlink_metadata(&destination)
            .expect("completion symlink should remain")
            .file_type()
            .is_symlink(),
        "completion symlink was replaced"
    );
}

#[cfg(unix)]
#[test]
fn reinstall_atomically_replaces_a_regular_script_and_preserves_its_mode() {
    use std::os::unix::fs::PermissionsExt;

    let fixture = TempDir::new().expect("test directory should be created");
    let output_dir = fixture.path().join("completions");
    let destination = output_dir.join("satelle.bash");
    fs::create_dir(&output_dir).expect("output directory should be created");
    fs::write(&destination, "stale completion bytes\n")
        .expect("existing completion should be written");
    fs::set_permissions(&destination, fs::Permissions::from_mode(0o640))
        .expect("existing completion mode should be set");

    satelle(
        &fixture.path().join("home"),
        &fixture.path().join("untouched-satelle-home"),
    )
    .args(["completions", "bash", "--output-dir"])
    .arg(&output_dir)
    .assert()
    .success()
    .stdout(format!("{}\n", destination.display()))
    .stderr(predicate::str::is_empty());

    let installed = fs::read(&destination).expect("installed completion should be readable");
    assert!(
        installed.starts_with(b"_satelle()"),
        "existing completion was not replaced with the generated script"
    );
    assert_eq!(
        fs::metadata(&destination)
            .expect("installed metadata should be readable")
            .permissions()
            .mode()
            & 0o777,
        0o640,
        "reinstall changed the existing completion mode"
    );
}

#[test]
fn installation_rejects_line_breaks_that_would_corrupt_path_output() {
    let fixture = TempDir::new().expect("test directory should be created");
    let output_dir = fixture.path().join("completion\noutput");

    satelle(
        &fixture.path().join("home"),
        &fixture.path().join("untouched-satelle-home"),
    )
    .args(["completions", "bash", "--output-dir"])
    .arg(&output_dir)
    .assert()
    .code(73)
    .stdout(predicate::str::is_empty())
    .stderr(
        predicate::str::contains("completion-install-failed")
            .and(predicate::str::contains("single-line UTF-8 path")),
    );

    assert!(
        !output_dir.exists(),
        "rejected output path created a directory"
    );
}

#[cfg(unix)]
#[test]
fn installation_rejects_non_utf8_paths_before_creating_directories() {
    use std::ffi::OsString;
    use std::os::unix::ffi::OsStringExt;

    let fixture = TempDir::new().expect("test directory should be created");
    let output_dir = fixture
        .path()
        .join(OsString::from_vec(b"completion-\xff-output".to_vec()));

    satelle(
        &fixture.path().join("home"),
        &fixture.path().join("untouched-satelle-home"),
    )
    .args(["completions", "bash", "--output-dir"])
    .arg(&output_dir)
    .assert()
    .code(73)
    .stdout(predicate::str::is_empty())
    .stderr(predicate::str::contains("completion-install-failed"));

    assert!(
        !output_dir.exists(),
        "rejected non-UTF-8 path created a directory"
    );
}

#[test]
fn installation_and_profile_failures_keep_the_json_automation_contract() {
    let fixture = TempDir::new().expect("test directory should be created");
    let blocked_output = fixture.path().join("not-a-directory");
    fs::write(&blocked_output, "occupied").expect("blocking file should be written");

    let install = satelle(
        &fixture.path().join("home"),
        &fixture.path().join("untouched-satelle-home"),
    )
    .args([
        "--error-format",
        "json",
        "completions",
        "bash",
        "--output-dir",
    ])
    .arg(&blocked_output)
    .assert()
    .code(73)
    .get_output()
    .clone();
    assert_error_process(&install);
    assert_completion_json_error(
        &install.stderr,
        "completion-install-failed",
        "choose a writable output directory and retry",
    );

    let output_dir = fixture.path().join("output");
    let profile = fixture.path().join("profile");
    let original = b"# >>> satelle completions >>>\nunclosed\n";
    fs::write(&profile, original).expect("malformed profile should be written");
    let profile_failure = satelle(
        &fixture.path().join("home"),
        &fixture.path().join("untouched-satelle-home"),
    )
    .args([
        "--error-format",
        "json",
        "completions",
        "bash",
        "--output-dir",
    ])
    .arg(&output_dir)
    .arg("--update-profile")
    .arg(&profile)
    .assert()
    .code(73)
    .get_output()
    .clone();
    assert_error_process(&profile_failure);
    assert_completion_json_error(
        &profile_failure.stderr,
        "completion-profile-update-failed",
        "repair the profile or choose another writable regular UTF-8 profile file",
    );
    assert_eq!(
        fs::read(&profile).expect("rejected profile should remain readable"),
        original
    );
}
