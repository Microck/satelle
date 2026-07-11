use assert_cmd::Command;
use predicates::prelude::*;
use satelle_host::test_support::TestStateDir;
use serde_json::Value;
use std::fs;
use std::path::{Path, PathBuf};
use tempfile::TempDir;

const TEST_SUPPORT_ADAPTER_ENV: &str = "SATELLE_TEST_SUPPORT_ADAPTER";

struct ConfigFixture {
    _temp: TempDir,
    project: PathBuf,
    state: TestStateDir,
    user_config: PathBuf,
}

impl ConfigFixture {
    fn new(user_config: &str, project_config: &str) -> Self {
        let temp = tempfile::tempdir().expect("temporary directory should be created");
        let project = temp.path().join("project");
        let state = TestStateDir::new().expect("secure state directory should be created");
        let user_config_path = temp.path().join("user-config.toml");
        let project_config_path = project.join(".satelle").join("config.toml");

        fs::create_dir_all(
            project_config_path
                .parent()
                .expect("project config should have a parent"),
        )
        .expect("project config directory should be created");
        fs::write(&user_config_path, user_config).expect("user config should be written");
        fs::write(project_config_path, project_config).expect("project config should be written");

        Self {
            _temp: temp,
            project,
            state,
            user_config: user_config_path,
        }
    }

    fn command(&self) -> Command {
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
            .current_dir(&self.project)
            .env("SATELLE_CONFIG_FILE", &self.user_config)
            .env("SATELLE_STATE_DIR", self.state.path())
            .env(TEST_SUPPORT_ADAPTER_ENV, "fake");
        command
    }
}

fn parse_json(bytes: &[u8]) -> Value {
    serde_json::from_slice(bytes).expect("output should be one JSON value")
}

fn write_project_config(project: &Path, config: &str) {
    fs::write(project.join(".satelle").join("config.toml"), config)
        .expect("project config should be replaced");
}

#[test]
fn global_profile_overlays_merged_config_and_selected_host() {
    let fixture = ConfigFixture::new(
        r#"
default_host = "base-host"
model_alias = "base-model"
provider_alias = "base-provider"
yolo = false

[hosts.base-host]
transport = "local"
adapter = "fake"

[hosts.work-host]
transport = "local"
adapter = "fake"

[hosts.work-host.timeouts]
provider_smoke_test = "11s"

[profiles.work]
host = "work-host"
model_alias = "work-model"
provider_alias = "work-provider"
experimental_provider_computer_use = true
yolo = true

[profiles.work.timeouts]
native_readiness = "7s"
"#,
        "",
    );

    // --profile is global, so clap must accept it after nested subcommands too.
    let output = fixture
        .command()
        .args(["config", "explain", "--profile", "work", "--json"])
        .assert()
        .success()
        .get_output()
        .clone();
    let report = parse_json(&output.stdout);

    assert_eq!(report["selected_profile"], "work");
    assert_eq!(report["selected_host"], "work-host");
    assert_eq!(report["sources"]["profile"], "cli_flag");
    assert_eq!(report["effective"]["model_alias"], "work-model");
    assert_eq!(report["effective"]["provider_alias"], "work-provider");
    assert_eq!(
        report["effective"]["experimental_provider_computer_use"],
        true
    );
    assert_eq!(report["effective"]["yolo"], false);
    assert_eq!(report["effective"]["hosts"]["work-host"]["yolo"], true);
    assert_eq!(
        report["effective"]["hosts"]["work-host"]["timeouts"]["native_readiness"],
        "7s"
    );
    assert_eq!(
        report["effective"]["hosts"]["work-host"]["timeouts"]["provider_smoke_test"],
        "11s"
    );
    assert_eq!(
        report["values"]["effective_timeouts"]["native_readiness_timeout_ms"],
        7_000
    );
    assert_eq!(
        report["values"]["effective_timeouts"]["provider_smoke_test_timeout_ms"],
        11_000
    );
    assert_eq!(
        report["values"]["model_provider"]["model_alias_source"],
        "user_config_profile"
    );
    assert_eq!(
        report["values"]["model_provider"]["provider_alias_source"],
        "user_config_profile"
    );
    assert_eq!(
        report["values"]["experimental_provider_computer_use"]["source"],
        "user_config_profile"
    );
    assert_eq!(report["values"]["yolo"]["source"], "user_config_profile");

    let check = fixture
        .command()
        .args(["config", "check", "--profile", "work", "--json"])
        .assert()
        .success()
        .get_output()
        .clone();
    let check = parse_json(&check.stdout);
    assert_eq!(check["checked_contexts"][0]["source"], "cli_flag");

    let overridden_host = fixture
        .command()
        .args([
            "config",
            "explain",
            "--profile",
            "work",
            "--host",
            "base-host",
            "--json",
        ])
        .assert()
        .success()
        .get_output()
        .clone();
    let overridden_host = parse_json(&overridden_host.stdout);
    assert_eq!(overridden_host["selected_host"], "base-host");
    assert_eq!(overridden_host["values"]["yolo"]["active"], false);
    assert_ne!(
        overridden_host["values"]["yolo"]["source"],
        "user_config_profile"
    );
}

#[test]
fn profile_selection_follows_config_environment_and_flag_precedence() {
    let fixture = ConfigFixture::new(
        r#"
profile = "user-profile"

[hosts.user-host]
transport = "local"
adapter = "fake"

[hosts.project-host]
transport = "local"
adapter = "fake"

[hosts.environment-host]
transport = "local"
adapter = "fake"

[hosts.flag-host]
transport = "local"
adapter = "fake"

[profiles.user-profile]
host = "user-host"

[profiles.project-profile]
host = "project-host"

[profiles.environment-profile]
host = "environment-host"

[profiles.flag-profile]
host = "flag-host"
"#,
        r#"
profile = "project-profile"
"#,
    );

    let project_default = fixture
        .command()
        .args(["config", "explain", "--json"])
        .assert()
        .success()
        .get_output()
        .clone();
    let project_default = parse_json(&project_default.stdout);
    assert_eq!(project_default["selected_profile"], "project-profile");
    assert_eq!(project_default["selected_host"], "project-host");
    assert_eq!(project_default["sources"]["profile"], "project_config");

    let environment = fixture
        .command()
        .env("SATELLE_PROFILE", "environment-profile")
        .args(["config", "explain", "--json"])
        .assert()
        .success()
        .get_output()
        .clone();
    let environment = parse_json(&environment.stdout);
    assert_eq!(environment["selected_profile"], "environment-profile");
    assert_eq!(environment["selected_host"], "environment-host");
    assert_eq!(environment["sources"]["profile"], "environment");

    let flag = fixture
        .command()
        .env("SATELLE_PROFILE", "environment-profile")
        .args(["--profile", "flag-profile", "config", "explain", "--json"])
        .assert()
        .success()
        .get_output()
        .clone();
    let flag = parse_json(&flag.stdout);
    assert_eq!(flag["selected_profile"], "flag-profile");
    assert_eq!(flag["selected_host"], "flag-host");
    assert_eq!(flag["sources"]["profile"], "cli_flag");
}

#[test]
fn untrusted_profile_selectors_do_not_activate_yolo_policy() {
    let fixture = ConfigFixture::new(
        r#"
default_host = "local-demo"

[hosts.local-demo]
transport = "local"
adapter = "fake"

[profiles.unsafe]
host = "local-demo"
model_alias = "profile-model"
experimental_provider_computer_use = true
yolo = true
"#,
        r#"
profile = "unsafe"
"#,
    );

    for (source, configure) in [
        ("project_config", None),
        ("environment", Some(("SATELLE_PROFILE", "unsafe"))),
    ] {
        let mut command = fixture.command();
        if let Some((name, value)) = configure {
            command.env(name, value);
        }
        let output = command
            .args(["config", "explain", "--json"])
            .assert()
            .success()
            .get_output()
            .clone();
        let report = parse_json(&output.stdout);
        assert_eq!(report["sources"]["profile"], source);
        assert_eq!(report["effective"]["model_alias"], "profile-model");
        assert_eq!(
            report["effective"]["experimental_provider_computer_use"],
            serde_json::Value::Null
        );
        assert_eq!(
            report["values"]["experimental_provider_computer_use"]["active"],
            false
        );
        assert_eq!(report["effective"]["yolo"], serde_json::Value::Null);
    }

    let explicit = fixture
        .command()
        .args(["config", "explain", "--profile", "unsafe", "--json"])
        .assert()
        .success()
        .get_output()
        .clone();
    let explicit = parse_json(&explicit.stdout);
    assert_eq!(explicit["sources"]["profile"], "cli_flag");
    assert_eq!(explicit["effective"]["yolo"], serde_json::Value::Null);
    assert_eq!(
        explicit["effective"]["experimental_provider_computer_use"],
        true
    );
    assert_eq!(explicit["effective"]["hosts"]["local-demo"]["yolo"], true);

    let run = fixture
        .command()
        .args(["run", "--profile", "unsafe", "--json", "profile policy"])
        .assert()
        .success()
        .get_output()
        .clone();
    let run = parse_json(&run.stdout);
    assert_eq!(run["yolo"]["active"], true);
    assert_eq!(run["yolo"]["source"], "user_config_profile");
}

#[test]
fn untrusted_profile_selectors_can_reduce_yolo_policy() {
    let fixture = ConfigFixture::new(
        r#"
default_host = "local-demo"
yolo = true

[hosts.local-demo]
transport = "local"
adapter = "fake"

[profiles.safe]
host = "local-demo"
yolo = false
"#,
        r#"
profile = "safe"
"#,
    );

    for (source, configure) in [
        ("project_config", None),
        ("environment", Some(("SATELLE_PROFILE", "safe"))),
    ] {
        let mut command = fixture.command();
        if let Some((name, value)) = configure {
            command.env(name, value);
        }
        let output = command
            .args(["config", "explain", "--json"])
            .assert()
            .success()
            .get_output()
            .clone();
        let report = parse_json(&output.stdout);

        assert_eq!(report["sources"]["profile"], source);
        assert_eq!(report["effective"]["yolo"], true);
        assert_eq!(report["effective"]["hosts"]["local-demo"]["yolo"], false);
        assert_eq!(report["values"]["yolo"]["active"], false);
        assert_eq!(report["values"]["yolo"]["source"], "user_config_profile");
    }
}

#[test]
fn undefined_profiles_and_project_profile_definitions_are_typed_errors() {
    let fixture = ConfigFixture::new("", "");

    let missing = fixture
        .command()
        .args(["--profile", "missing", "config", "check", "--json"])
        .assert()
        .code(66)
        .get_output()
        .clone();
    let missing = parse_json(&missing.stderr);
    assert_eq!(missing["error"]["code"], "profile-not-found");
    assert_eq!(missing["error"]["profile"], "missing");

    write_project_config(
        &fixture.project,
        r#"
[profiles.checkout-controlled]
host = "attacker-host"
"#,
    );
    fixture
        .command()
        .args(["config", "check", "--json"])
        .assert()
        .code(66)
        .stderr(predicate::str::contains(
            "project-profile-definition-not-allowed",
        ));
}

#[test]
fn every_profile_is_validated_even_when_it_is_not_selected() {
    let fixture = ConfigFixture::new(
        r#"
[profiles.broken]
hosts = "profiles do not own host trees"
"#,
        "",
    );

    let output = fixture
        .command()
        .args(["config", "check", "--json"])
        .assert()
        .code(66)
        .get_output()
        .clone();
    let error = parse_json(&output.stderr);
    assert_eq!(error["error"]["code"], "unknown-config-key");
    assert_eq!(error["error"]["path"], "profiles.broken.hosts");

    fs::write(
        &fixture.user_config,
        r#"
[profiles.unbound]
yolo = true
"#,
    )
    .expect("user config should be replaced");
    fixture
        .command()
        .args(["config", "check", "--json"])
        .assert()
        .code(66)
        .stderr(predicate::str::contains(
            "must bind yolo to a non-empty host alias",
        ));

    fs::write(
        &fixture.user_config,
        r#"
[profiles.broken.timeouts]
provider_timeout = "120s"
"#,
    )
    .expect("user config should be replaced");
    let output = fixture
        .command()
        .args(["config", "check", "--json"])
        .assert()
        .code(66)
        .get_output()
        .clone();
    let error = parse_json(&output.stderr);
    assert_eq!(error["error"]["code"], "unknown-timeout-key");
    assert_eq!(
        error["error"]["path"],
        "profiles.broken.timeouts.provider_timeout"
    );
}

#[test]
fn profile_overlay_applies_to_normal_commands_not_only_config_reports() {
    let fixture = ConfigFixture::new(
        r#"
default_host = "other-host"

[hosts.other-host]
transport = "local"
adapter = "fake"

[hosts.local-demo]
transport = "local"
adapter = "fake"

[profiles.work]
host = "local-demo"
"#,
        "",
    );

    fixture
        .command()
        .args(["doctor", "--profile", "work", "--json"])
        .assert()
        .success()
        .stdout(predicate::str::contains(r#""host": "local-demo""#));
}
