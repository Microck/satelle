use assert_cmd::Command;
use predicates::prelude::*;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::Path;
use tempfile::TempDir;

const MANAGED_BLOCK_START: &str = "# >>> satelle completions >>>";
const MANAGED_BLOCK_NOTICE: &str =
    "# Managed by Satelle. Re-run the install command to update this block.";
const MANAGED_BLOCK_END: &str = "# <<< satelle completions <<<";
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
        TEST_SUPPORT_ADAPTER_ENV,
    ] {
        command.env_remove(name);
    }
    command
}

fn update_profile_command(
    shell: &str,
    output_dir: &Path,
    profile: &Path,
    satelle_home: &Path,
) -> Command {
    let mut command = satelle();
    command
        .env("SATELLE_HOME", satelle_home)
        .arg("completions")
        .arg(shell)
        .arg("--output-dir")
        .arg(output_dir)
        .arg("--update-profile")
        .arg(profile);
    command
}

fn installed_filename(shell: &str) -> &'static str {
    match shell {
        "bash" => "satelle.bash",
        "zsh" => "_satelle",
        "fish" => "satelle.fish",
        "powershell" => "_satelle.ps1",
        _ => panic!("unsupported test shell {shell}"),
    }
}

fn utf8_path(path: &Path) -> &str {
    path.to_str().expect("test path should be UTF-8")
}

fn posix_quote(path: &Path) -> String {
    format!("'{}'", utf8_path(path).replace('\'', "'\\''"))
}

fn fish_quote(path: &Path) -> String {
    let escaped = utf8_path(path).replace('\\', "\\\\").replace('\'', "\\'");
    format!("'{escaped}'")
}

fn powershell_quote(path: &Path) -> String {
    format!("'{}'", utf8_path(path).replace('\'', "''"))
}

fn managed_block(shell: &str, destination: &Path, newline: &str) -> Vec<u8> {
    let activation = match shell {
        "bash" => format!(". {}", posix_quote(destination)),
        "zsh" => format!(
            "autoload -Uz compinit{newline}(( $+functions[compdef] )) || compinit{newline}source {}{newline}compdef _satelle satelle",
            posix_quote(destination)
        ),
        "fish" => format!("source {}", fish_quote(destination)),
        "powershell" => format!(". {}", powershell_quote(destination)),
        _ => panic!("unsupported test shell {shell}"),
    };
    format!(
        "{MANAGED_BLOCK_START}{newline}{MANAGED_BLOCK_NOTICE}{newline}{activation}{newline}{MANAGED_BLOCK_END}{newline}"
    )
    .into_bytes()
}

#[test]
fn writes_exact_idempotent_activation_blocks_without_touching_user_content() {
    for shell in ["bash", "zsh", "fish", "powershell"] {
        let fixture = TempDir::new().expect("test directory should be created");
        let output_dir = fixture.path().join(format!("completion dir's {shell}"));
        let destination = output_dir.join(installed_filename(shell));
        let profile = fixture.path().join(format!("{shell} profile"));
        let satelle_home = fixture.path().join("untouched-satelle-home");
        let original = format!("# {shell} user content\n# keep this byte-for-byte\n").into_bytes();
        fs::write(&profile, &original).expect("profile should be written");

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&profile, fs::Permissions::from_mode(0o640))
                .expect("profile permissions should be set");
        }

        update_profile_command(shell, &output_dir, &profile, &satelle_home)
            .assert()
            .success()
            .stdout(format!("{}\n", destination.display()))
            .stderr(predicate::str::is_empty());

        let mut expected = original;
        expected.extend(managed_block(shell, &destination, "\n"));
        assert_eq!(
            fs::read(&profile).expect("updated profile should be readable"),
            expected,
            "{shell} profile block differs"
        );

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                fs::metadata(&profile)
                    .expect("profile metadata should be readable")
                    .permissions()
                    .mode()
                    & 0o777,
                0o640,
                "{shell} profile permissions changed"
            );
        }

        update_profile_command(shell, &output_dir, &profile, &satelle_home)
            .assert()
            .success();
        assert_eq!(
            fs::read(&profile).expect("profile should remain readable"),
            expected,
            "{shell} repeated update was not byte-idempotent"
        );
        assert!(
            !satelle_home.exists(),
            "{shell} profile update initialized state"
        );
    }
}

#[test]
fn creates_a_missing_profile_and_parent_directory() {
    let fixture = TempDir::new().expect("test directory should be created");
    let output_dir = fixture.path().join("completion output");
    let destination = output_dir.join("satelle.fish");
    let profile = fixture
        .path()
        .join("missing")
        .join("fish")
        .join("config.fish");

    update_profile_command(
        "fish",
        &output_dir,
        &profile,
        &fixture.path().join("untouched-satelle-home"),
    )
    .assert()
    .success()
    .stdout(format!("{}\n", destination.display()))
    .stderr(predicate::str::is_empty());

    assert_eq!(
        fs::read(&profile).expect("missing profile should be created"),
        managed_block("fish", &destination, "\n")
    );
}

#[test]
fn replaces_one_existing_block_and_preserves_surrounding_crlf_bytes() {
    let fixture = TempDir::new().expect("test directory should be created");
    let first_output = fixture.path().join("first output");
    let second_output = fixture.path().join("second output");
    let first_destination = first_output.join("_satelle");
    let second_destination = second_output.join("_satelle");
    let profile = fixture.path().join(".zshrc");
    let satelle_home = fixture.path().join("untouched-satelle-home");
    let prefix = b"# before\r\n";
    let suffix = b"# after\r\n";
    fs::write(&profile, prefix).expect("profile should be written");

    update_profile_command("zsh", &first_output, &profile, &satelle_home)
        .assert()
        .success();
    OpenOptions::new()
        .append(true)
        .open(&profile)
        .expect("profile should open for append")
        .write_all(suffix)
        .expect("suffix should be appended");

    update_profile_command("zsh", &second_output, &profile, &satelle_home)
        .assert()
        .success()
        .stdout(format!("{}\n", second_destination.display()));

    let mut expected = prefix.to_vec();
    expected.extend(managed_block("zsh", &second_destination, "\r\n"));
    expected.extend(suffix);
    let updated = fs::read(&profile).expect("profile should be readable");
    assert_eq!(updated, expected);
    assert!(
        !String::from_utf8_lossy(&updated).contains(utf8_path(&first_destination)),
        "obsolete managed path remained in the profile"
    );
}

#[test]
fn update_profile_requires_an_output_directory() {
    let fixture = TempDir::new().expect("test directory should be created");

    satelle()
        .args(["completions", "bash", "--update-profile"])
        .arg(fixture.path().join(".bashrc"))
        .assert()
        .code(2)
        .stdout(predicate::str::is_empty())
        .stderr(predicate::str::contains("--output-dir"));
}

#[test]
fn rejects_malformed_or_non_utf8_profiles_without_changing_them() {
    for (case, original) in [
        (
            "missing-end",
            format!("# user\n{MANAGED_BLOCK_START}\nunfinished\n").into_bytes(),
        ),
        (
            "reversed",
            format!("{MANAGED_BLOCK_END}\n{MANAGED_BLOCK_START}\n").into_bytes(),
        ),
        (
            "duplicate-start",
            format!("{MANAGED_BLOCK_START}\n{MANAGED_BLOCK_START}\n{MANAGED_BLOCK_END}\n")
                .into_bytes(),
        ),
        ("invalid-utf8", vec![0xff, 0xfe, b'\n']),
    ] {
        let fixture = TempDir::new().expect("test directory should be created");
        let profile = fixture.path().join(format!("{case}.profile"));
        fs::write(&profile, &original).expect("profile fixture should be written");

        update_profile_command(
            "bash",
            &fixture.path().join("output"),
            &profile,
            &fixture.path().join("untouched-satelle-home"),
        )
        .assert()
        .code(73)
        .stdout(predicate::str::is_empty())
        .stderr(
            predicate::str::contains("completion-profile-update-failed")
                .and(predicate::str::contains("panicked").not())
                .and(predicate::str::contains("backtrace").not()),
        );

        assert_eq!(
            fs::read(&profile).expect("rejected profile should remain readable"),
            original,
            "{case} profile changed after rejection"
        );
    }
}

#[test]
fn rejects_a_directory_as_the_profile_without_changing_it() {
    let fixture = TempDir::new().expect("test directory should be created");
    let profile = fixture.path().join("profile-directory");
    fs::create_dir(&profile).expect("profile directory should be created");

    update_profile_command(
        "fish",
        &fixture.path().join("output"),
        &profile,
        &fixture.path().join("untouched-satelle-home"),
    )
    .assert()
    .code(73)
    .stdout(predicate::str::is_empty())
    .stderr(predicate::str::contains("completion-profile-update-failed"));

    assert!(profile.is_dir(), "profile directory was replaced");
}

#[cfg(unix)]
#[test]
fn rejects_a_symlinked_profile_without_changing_its_target() {
    use std::os::unix::fs::symlink;

    let fixture = TempDir::new().expect("test directory should be created");
    let target = fixture.path().join("real-profile");
    let profile = fixture.path().join("linked-profile");
    let original = b"# real profile\n";
    fs::write(&target, original).expect("target profile should be written");
    symlink(&target, &profile).expect("profile symlink should be created");

    update_profile_command(
        "bash",
        &fixture.path().join("output"),
        &profile,
        &fixture.path().join("untouched-satelle-home"),
    )
    .assert()
    .code(73)
    .stdout(predicate::str::is_empty())
    .stderr(predicate::str::contains("completion-profile-update-failed"));

    assert_eq!(
        fs::read(&target).expect("target should be readable"),
        original
    );
    assert!(
        fs::symlink_metadata(&profile)
            .expect("symlink should remain")
            .file_type()
            .is_symlink(),
        "profile symlink was replaced"
    );
}
