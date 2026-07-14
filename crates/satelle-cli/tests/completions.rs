use assert_cmd::Command;
use predicates::prelude::*;
use std::fs;
use std::path::{Path, PathBuf};
use tempfile::TempDir;

const TEST_SUPPORT_ADAPTER_ENV: &str = "SATELLE_TEST_SUPPORT_ADAPTER";

fn satelle() -> Command {
    let mut command = Command::cargo_bin("satelle").expect("satelle binary should build");
    for name in [
        "SATELLE_HOME",
        "SATELLE_CONFIG_FILE",
        "SATELLE_STATE_DIR",
        "SATELLE_CACHE_DIR",
        "SATELLE_LOG_DIR",
        "SATELLE_HOST",
        "SATELLE_PROFILE",
        "SATELLE_ERROR_FORMAT",
        TEST_SUPPORT_ADAPTER_ENV,
    ] {
        command.env_remove(name);
    }
    command
}

fn isolated_satelle(home: &Path, satelle_home: &Path) -> Command {
    let mut command = satelle();
    command
        .env("HOME", home)
        .env("USERPROFILE", home)
        .env("XDG_CONFIG_HOME", home.join(".config"))
        .env("SATELLE_HOME", satelle_home);
    command
}

fn write_profile_sentinels(home: &Path) -> Vec<(PathBuf, Vec<u8>)> {
    let profiles = [
        home.join(".bashrc"),
        home.join(".zshrc"),
        home.join(".config").join("fish").join("config.fish"),
        home.join("Documents")
            .join("PowerShell")
            .join("Microsoft.PowerShell_profile.ps1"),
    ];

    profiles
        .into_iter()
        .enumerate()
        .map(|(index, path)| {
            fs::create_dir_all(path.parent().expect("profile should have a parent"))
                .expect("profile parent should be created");
            let contents = format!("profile sentinel {index}\n").into_bytes();
            fs::write(&path, &contents).expect("profile sentinel should be written");
            (path, contents)
        })
        .collect()
}

fn assert_profiles_unchanged(profiles: &[(PathBuf, Vec<u8>)]) {
    for (path, expected) in profiles {
        assert_eq!(
            fs::read(path).expect("profile sentinel should remain readable"),
            *expected,
            "Satelle modified {}",
            path.display()
        );
    }
}

#[test]
fn generates_scripts_for_every_supported_shell_without_initializing_state() {
    for (shell, marker) in [
        ("bash", "_satelle"),
        ("zsh", "#compdef satelle"),
        ("fish", "complete -c satelle"),
        (
            "powershell",
            "Register-ArgumentCompleter -Native -CommandName 'satelle'",
        ),
    ] {
        let fixture = TempDir::new().expect("test directory should be created");
        let satelle_home = fixture.path().join("untouched-satelle-home");
        let output = isolated_satelle(fixture.path(), &satelle_home)
            .args(["completions", shell])
            .assert()
            .success()
            .stderr(predicate::str::is_empty())
            .get_output()
            .clone();
        let stdout = String::from_utf8(output.stdout).expect("completion script should be UTF-8");

        assert!(stdout.contains(marker), "{shell} output omitted {marker:?}");
        assert!(stdout.contains("setup"), "{shell} output omitted setup");
        assert!(stdout.contains("run"), "{shell} output omitted run");
        assert!(!satelle_home.exists(), "{shell} initialized Satelle state");
    }
}

#[test]
fn rejects_unsupported_shells_at_the_cli_boundary() {
    satelle()
        .args(["completions", "nushell"])
        .assert()
        .failure()
        .stdout(predicate::str::is_empty())
        .stderr(
            predicate::str::starts_with("error: invalid-usage\n")
                .and(predicate::str::contains("invalid value 'nushell'"))
                .and(predicate::str::contains("powershell")),
        );
}

#[cfg(unix)]
#[test]
fn exits_cleanly_when_stdout_pipe_closes_early() {
    for shell in ["bash", "zsh", "fish", "powershell"] {
        let status = std::process::Command::new("bash")
            .args([
                "-o",
                "pipefail",
                "-c",
                "\"$1\" completions \"$2\" | true",
                "satelle-completions-test",
            ])
            .arg(assert_cmd::cargo::cargo_bin!("satelle"))
            .arg(shell)
            .status()
            .expect("completion pipeline should start");

        assert!(
            status.success(),
            "satelle should treat a {shell} completion reader closing the pipe as success"
        );
    }
}

#[test]
fn installs_selected_shells_in_an_explicit_directory_without_touching_profiles_or_state() {
    let fixture = TempDir::new().expect("test directory should be created");
    let home = fixture.path().join("home");
    let satelle_home = fixture.path().join("untouched-satelle-home");
    let profiles = write_profile_sentinels(&home);

    for (shell, filename) in [
        ("bash", "satelle.bash"),
        ("zsh", "_satelle"),
        ("fish", "satelle.fish"),
        ("powershell", "_satelle.ps1"),
    ] {
        let output_dir = fixture.path().join("installed").join(shell);
        let destination = output_dir.join(filename);
        isolated_satelle(&home, &satelle_home)
            .env("SHELL", "/usr/bin/elvish")
            .args(["completions", shell, "--output-dir"])
            .arg(&output_dir)
            .assert()
            .success()
            .stdout(format!("{}\n", destination.display()))
            .stderr(predicate::str::is_empty());

        let generated = isolated_satelle(&home, &satelle_home)
            .args(["completions", shell])
            .assert()
            .success()
            .get_output()
            .stdout
            .clone();
        assert_eq!(
            fs::read(&destination).expect("completion script should be installed"),
            generated,
            "{shell} install differs from generated output"
        );
    }

    assert_profiles_unchanged(&profiles);
    assert!(
        !satelle_home.exists(),
        "completion install initialized Satelle state"
    );
}

#[test]
fn detects_the_install_shell_from_shell_when_the_positional_is_omitted() {
    let fixture = TempDir::new().expect("test directory should be created");
    let output_dir = fixture.path().join("installed");
    let destination = output_dir.join("satelle.fish");

    isolated_satelle(
        fixture.path(),
        &fixture.path().join("untouched-satelle-home"),
    )
    .env("SHELL", "/usr/bin/fish")
    .args(["completions", "--output-dir"])
    .arg(&output_dir)
    .assert()
    .success()
    .stdout(format!("{}\n", destination.display()))
    .stderr(predicate::str::is_empty());

    assert!(
        destination.is_file(),
        "detected fish script was not installed"
    );
}

#[cfg(not(windows))]
#[test]
fn reports_how_to_select_a_shell_when_install_detection_is_unavailable() {
    let fixture = TempDir::new().expect("test directory should be created");

    isolated_satelle(
        fixture.path(),
        &fixture.path().join("untouched-satelle-home"),
    )
    .env_remove("SHELL")
    .args(["completions", "--output-dir"])
    .arg(fixture.path().join("installed"))
    .assert()
    .code(64)
    .stdout(predicate::str::is_empty())
    .stderr(
        predicate::str::contains("invalid-usage").and(predicate::str::contains(
            "select bash, zsh, fish, or powershell",
        )),
    );
}

#[cfg(windows)]
#[test]
fn defaults_install_detection_to_powershell_on_windows() {
    let fixture = TempDir::new().expect("test directory should be created");
    let output_dir = fixture.path().join("installed");
    let destination = output_dir.join("_satelle.ps1");

    isolated_satelle(
        fixture.path(),
        &fixture.path().join("untouched-satelle-home"),
    )
    .env_remove("SHELL")
    .args(["completions", "--output-dir"])
    .arg(&output_dir)
    .assert()
    .success()
    .stdout(format!("{}\n", destination.display()))
    .stderr(predicate::str::is_empty());

    assert!(destination.is_file(), "PowerShell script was not installed");
}

#[test]
fn reports_typed_installation_failures_without_a_panic() {
    let fixture = TempDir::new().expect("test directory should be created");
    let output_dir = fixture.path().join("not-a-directory");
    fs::write(&output_dir, "occupied").expect("blocking file should be written");

    isolated_satelle(
        fixture.path(),
        &fixture.path().join("untouched-satelle-home"),
    )
    .args(["completions", "bash", "--output-dir"])
    .arg(&output_dir)
    .assert()
    .code(73)
    .stdout(predicate::str::is_empty())
    .stderr(
        predicate::str::contains("completion-install-failed")
            .and(predicate::str::contains(output_dir.display().to_string()))
            .and(predicate::str::contains("panicked").not())
            .and(predicate::str::contains("backtrace").not()),
    );
}
