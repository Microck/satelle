use assert_cmd::Command;
use predicates::prelude::*;
use std::fs;

#[path = "support/config-fixture.rs"]
mod config_fixture;

use config_fixture::{ConfigFixture, assert_same_file, parse_json};

#[test]
fn api_rate_limits_are_user_owned_and_nonzero() {
    let fixture = ConfigFixture::new(
        r#"
[api_rate_limits]
failed_auth_attempts_per_minute = 7
authenticated_requests_per_minute = 321
control_requests_per_minute = 45
websocket_inbound_messages_per_minute = 67
"#,
        "",
    );
    fixture
        .command()
        .args(["config", "check", "--json"])
        .assert()
        .success();

    fixture.write_user_config(
        r#"
[api_rate_limits]
control_requests_per_minute = 0
"#,
    );
    let zero = fixture
        .command()
        .args(["config", "check", "--json"])
        .assert()
        .code(66)
        .get_output()
        .clone();
    let zero = parse_json(&zero.stderr);
    assert_eq!(zero["code"], "configuration-error");
    fixture
        .command()
        .args([
            "host",
            "start",
            "--foreground",
            "--bind",
            "127.0.0.1:0",
            "--json",
        ])
        .assert()
        .code(66);

    fixture.write_user_config(
        r#"
[api_rate_limits]
failed_auth_attempts_per_minute = 50
authenticated_requests_per_minute = 1000
control_requests_per_minute = 200
websocket_inbound_messages_per_minute = 200
"#,
    );
    fixture.write_project_config(
        r#"
[api_rate_limits]
failed_auth_attempts_per_minute = 1
"#,
    );
    let project = fixture
        .command()
        .args(["config", "check", "--json"])
        .assert()
        .code(66)
        .get_output()
        .clone();
    let project = parse_json(&project.stderr);
    assert_eq!(project["code"], "unknown-config-key");
    assert_eq!(project["details"]["path"], "api_rate_limits");

    fixture.write_project_config("default_host = \"missing\"\n");
    let foreground = fixture
        .command()
        .args([
            "host",
            "start",
            "--foreground",
            "--bind",
            "192.0.2.1:0",
            "--json",
        ])
        .assert()
        .code(64)
        .get_output()
        .clone();
    let foreground = parse_json(&foreground.stderr);
    assert_eq!(foreground["code"], "invalid-usage");
}

#[test]
fn config_check_validates_files_before_enumerating_only_selectable_contexts() {
    let fixture = ConfigFixture::new(
        r#"
default_host = "base-host"

[hosts.base-host]
transport = "local"
adapter = "fake"
allow_project_selection = true

[hosts.profile-host]
transport = "local"
adapter = "fake"
allow_project_selection = true

[profiles.work]
host = "profile-host"

[profiles.audit]
"#,
        r#"
default_host = "base-host"
profile = "work"
"#,
    );

    // An unselected profile is still part of file-level validation. Context
    // enumeration must never become a way to hide a malformed config value.
    fixture.write_user_config(
        r#"
[hosts.base-host]
transport = "local"
adapter = "fake"

[profiles.unselected.timeouts]
provider_timeout = "15s"
"#,
    );
    let invalid = fixture
        .command()
        .args([
            "config",
            "check",
            "--host",
            "base-host",
            "--profile",
            "missing-profile",
            "--json",
        ])
        .assert()
        .code(66)
        .get_output()
        .clone();
    let invalid = parse_json(&invalid.stderr);
    assert_eq!(invalid["code"], "unknown-timeout-key");
    assert_eq!(
        invalid["details"]["path"],
        "profiles.unselected.timeouts.provider_timeout"
    );
    assert_same_file(&invalid["details"]["file"], fixture.user_config_path());

    fixture.write_user_config(
        r#"
default_host = "base-host"

[hosts.base-host]
transport = "local"
adapter = "fake"
allow_project_selection = true

[hosts.profile-host]
transport = "local"
adapter = "fake"
allow_project_selection = true

[profiles.work]
host = "profile-host"

[profiles.audit]
"#,
    );
    fixture.write_project_config("unknown_project_key = true\n");
    let invalid_project = fixture
        .command()
        .args(["config", "check", "--host", "base-host", "--json"])
        .assert()
        .code(66)
        .get_output()
        .clone();
    let invalid_project = parse_json(&invalid_project.stderr);
    assert_eq!(invalid_project["code"], "unknown-config-key");
    assert_eq!(invalid_project["details"]["path"], "unknown_project_key");
    assert_same_file(
        &invalid_project["details"]["file"],
        &fixture.resolved_project_config(),
    );

    fixture.write_project_config(
        r#"
default_host = "base-host"
profile = "work"
"#,
    );
    let output = fixture
        .command()
        .args(["config", "check", "--all", "--json"])
        .assert()
        .success()
        .get_output()
        .clone();
    let report = parse_json(&output.stdout);
    let contexts = report["checked_contexts"]
        .as_array()
        .expect("checked_contexts should be an array");

    let contains = |host: &str, profile: Option<&str>, source: &str| {
        contexts.iter().any(|context| {
            context["host"] == host
                && context["profile"].as_str() == profile
                && context["source"] == source
        })
    };
    assert!(contains("profile-host", Some("work"), "default_context"));
    assert!(contains("local-demo", None, "configured_host"));
    assert!(contains("base-host", None, "configured_host"));
    assert!(contains("profile-host", None, "configured_host"));
    assert!(contains("profile-host", Some("work"), "configured_profile"));
    assert!(contains("base-host", Some("audit"), "configured_profile"));
    assert!(contains("profile-host", Some("work"), "project_defaults"));
    assert_eq!(
        contexts.len(),
        7,
        "config check --all emitted unexpected or duplicate contexts"
    );
    assert!(
        !contexts
            .iter()
            .any(|context| { context["host"] == "profile-host" && context["profile"] == "audit" })
    );
}

#[test]
fn path_environment_has_one_absolute_precedence_chain() {
    let fixture = tempfile::tempdir().expect("create path environment fixture");
    let project = fixture.path().join("project");
    fs::create_dir_all(&project).expect("create project directory");
    let home = fixture.path().join("portable");

    let derived = clean_satelle_command()
        .current_dir(&project)
        .env("SATELLE_HOME", &home)
        .args(["paths", "--json"])
        .assert()
        .success()
        .get_output()
        .clone();
    let derived = parse_json(&derived.stdout);
    assert_eq!(
        derived["config_file"],
        serde_json::json!(home.join("config").join("config.toml"))
    );
    assert_eq!(derived["state_root"], serde_json::json!(home.join("state")));
    assert_eq!(derived["cache_root"], serde_json::json!(home.join("cache")));
    assert_eq!(
        derived["operator_log_root"],
        serde_json::json!(home.join("logs"))
    );
    assert_eq!(
        derived["recording_root"],
        serde_json::json!(home.join("state").join("recordings"))
    );
    for key in [
        "config_file",
        "state_root",
        "cache_root",
        "operator_log_root",
        "recording_root",
    ] {
        assert_eq!(derived["sources"][key], "satelle_home");
    }

    let explicit_config = fixture.path().join("explicit").join("config.toml");
    let explicit_state = fixture.path().join("explicit").join("state");
    let explicit_cache = fixture.path().join("explicit").join("cache");
    let explicit_logs = fixture.path().join("explicit").join("logs");
    let explicit = clean_satelle_command()
        .current_dir(&project)
        .env("SATELLE_HOME", &home)
        .env("SATELLE_CONFIG_FILE", &explicit_config)
        .env("SATELLE_STATE_DIR", &explicit_state)
        .env("SATELLE_CACHE_DIR", &explicit_cache)
        .env("SATELLE_LOG_DIR", &explicit_logs)
        .args(["paths", "--json"])
        .assert()
        .success()
        .get_output()
        .clone();
    let explicit = parse_json(&explicit.stdout);
    assert_eq!(explicit["config_file"], serde_json::json!(explicit_config));
    assert_eq!(explicit["state_root"], serde_json::json!(explicit_state));
    assert_eq!(explicit["cache_root"], serde_json::json!(explicit_cache));
    assert_eq!(
        explicit["operator_log_root"],
        serde_json::json!(explicit_logs)
    );
    assert_eq!(
        explicit["recording_root"],
        serde_json::json!(home.join("state").join("recordings"))
    );
    assert_eq!(explicit["sources"]["recording_root"], "satelle_home");
    for key in [
        "config_file",
        "state_root",
        "cache_root",
        "operator_log_root",
    ] {
        assert_eq!(explicit["sources"][key], "explicit_environment");
    }

    for name in [
        "SATELLE_HOME",
        "SATELLE_CONFIG_FILE",
        "SATELLE_STATE_DIR",
        "SATELLE_CACHE_DIR",
        "SATELLE_LOG_DIR",
    ] {
        clean_satelle_command()
            .current_dir(&project)
            .env(name, "relative-path")
            .args(["paths", "--json"])
            .assert()
            .code(66)
            .stderr(predicate::str::contains("path-override-not-absolute"));
    }

    // These tempting aliases are deliberately not part of the config grammar.
    let ambiguous = clean_satelle_command()
        .current_dir(&project)
        .env("SATELLE_HOME", &home)
        .env("SATELLE_CONFIG", fixture.path().join("ignored-config"))
        .env("SATELLE_STATE", fixture.path().join("ignored-state"))
        .env("SATELLE_CACHE", fixture.path().join("ignored-cache"))
        .env("SATELLE_LOG", fixture.path().join("ignored-log"))
        .args(["paths", "--json"])
        .assert()
        .success()
        .get_output()
        .clone();
    let ambiguous = parse_json(&ambiguous.stdout);
    assert_eq!(
        ambiguous["config_file"],
        serde_json::json!(home.join("config").join("config.toml"))
    );
    assert_eq!(
        ambiguous["state_root"],
        serde_json::json!(home.join("state"))
    );
    assert_eq!(
        ambiguous["cache_root"],
        serde_json::json!(home.join("cache"))
    );
    assert_eq!(
        ambiguous["operator_log_root"],
        serde_json::json!(home.join("logs"))
    );
}

#[test]
fn host_environment_selection_is_between_config_and_cli_precedence() {
    let fixture = ConfigFixture::new(
        r#"
default_host = "config-host"

[hosts.config-host]
transport = "local"
adapter = "fake"

[hosts.environment-host]
transport = "local"
adapter = "fake"

[hosts.flag-host]
transport = "local"
adapter = "fake"
"#,
        "",
    );

    let config = fixture
        .command()
        .args(["config", "check", "--json"])
        .assert()
        .success()
        .get_output()
        .clone();
    assert_eq!(parse_json(&config.stdout)["selected_host"], "config-host");

    let environment = fixture
        .command()
        .env("SATELLE_HOST", "environment-host")
        .args(["config", "check", "--json"])
        .assert()
        .success()
        .get_output()
        .clone();
    assert_eq!(
        parse_json(&environment.stdout)["selected_host"],
        "environment-host"
    );

    let flag = fixture
        .command()
        .env("SATELLE_HOST", "environment-host")
        .args(["config", "check", "--host", "flag-host", "--json"])
        .assert()
        .success()
        .get_output()
        .clone();
    assert_eq!(parse_json(&flag.stdout)["selected_host"], "flag-host");
}

#[test]
fn secret_source_validation_never_resolves_or_executes_descriptors() {
    let fixture = tempfile::tempdir().expect("create secret source fixture");
    let absent_secret = fixture.path().join("secret-must-remain-absent");
    let command_canary = fixture.path().join("command-must-not-run");
    let config = ConfigFixture::new(
        &format!(
            r#"
default_host = "local-demo"

[hosts.local-demo]
transport = "local"
adapter = "fake"

[hosts.local-demo.provider_auth.file]
kind = "file"
path = '{}'

[hosts.local-demo.provider_auth.environment]
kind = "environment"
variable = "SATELLE_TEST_SECRET_CANARY"

[hosts.local-demo.provider_auth.credential]
kind = "credential-store"
service = "satelle-test"
account = "missing"

[hosts.local-demo.provider_auth.host]
kind = "host-store"
name = "missing"
"#,
            absent_secret.display()
        ),
        "",
    );

    // Validation must accept an unresolved environment descriptor even when
    // its named variable does not exist in the validating process.
    config
        .command()
        .env_remove("SATELLE_TEST_SECRET_CANARY")
        .args(["config", "check", "--json"])
        .assert()
        .success();

    // Supplying the variable separately proves config validation neither
    // resolves its value nor leaks it into config-owned diagnostics.
    config
        .command()
        .env("SATELLE_TEST_SECRET_CANARY", "raw-secret-must-not-be-read")
        .args(["config", "check", "--json"])
        .assert()
        .success()
        .stdout(predicate::str::contains("raw-secret-must-not-be-read").not())
        .stderr(predicate::str::contains("raw-secret-must-not-be-read").not());
    assert!(
        !absent_secret.exists(),
        "config check resolved a file secret"
    );

    let test_executable = toml::Value::String(
        std::env::current_exe()
            .expect("resolve cross-platform canary executable")
            .display()
            .to_string(),
    )
    .to_string();
    config.write_user_config(&format!(
        r#"
[hosts.local-demo]
transport = "local"
adapter = "fake"

[hosts.local-demo.provider_auth.openai]
kind = "command"
argv = [{}, "--exact", "secret_source_command_canary_child", "--nocapture"]
"#,
        test_executable
    ));
    let rejected = config
        .command()
        .env("SATELLE_TEST_COMMAND_CANARY_PATH", &command_canary)
        .args(["config", "check", "--json"])
        .assert()
        .code(66)
        .get_output()
        .clone();
    let rejected = parse_json(&rejected.stderr);
    assert_eq!(rejected["code"], "unsupported-secret-source-kind");
    assert_eq!(
        rejected["details"]["path"],
        "hosts.local-demo.provider_auth.openai.kind"
    );
    assert!(
        !command_canary.exists(),
        "config validation executed a command"
    );
}

#[cfg(unix)]
#[test]
fn user_security_config_rejects_group_or_other_posix_writers() {
    use std::os::unix::fs::PermissionsExt;

    for mode in [0o660, 0o602] {
        let fixture = ConfigFixture::new(
            r#"
[hosts.local-demo]
transport = "local"
adapter = "fake"
yolo = true
"#,
            "",
        );
        fs::set_permissions(fixture.user_config_path(), fs::Permissions::from_mode(mode))
            .expect("make user security config writable by unrelated users");

        fixture
            .command()
            .args(["config", "check", "--json"])
            .assert()
            .code(66)
            .stderr(predicate::str::contains("owner security policy"));
    }
}

#[test]
fn secret_source_command_canary_child() {
    if let Some(path) = std::env::var_os("SATELLE_TEST_COMMAND_CANARY_PATH") {
        fs::write(path, b"executed").expect("write command execution canary");
    }
}

fn clean_satelle_command() -> Command {
    let mut command = Command::cargo_bin("satelle").expect("satelle binary should build");
    for name in [
        "SATELLE_HOME",
        "SATELLE_CONFIG_FILE",
        "SATELLE_STATE_DIR",
        "SATELLE_CACHE_DIR",
        "SATELLE_LOG_DIR",
        "SATELLE_CONFIG",
        "SATELLE_STATE",
        "SATELLE_CACHE",
        "SATELLE_LOG",
        "SATELLE_HOST",
        "SATELLE_PROFILE",
        "SATELLE_ERROR_FORMAT",
        "SATELLE_TEST_SUPPORT_ADAPTER",
    ] {
        command.env_remove(name);
    }
    command.env("SATELLE_TEST_SUPPORT_ADAPTER", "fake");
    command
}

#[test]
fn project_model_and_provider_intent_requires_one_exact_host_binding() {
    let fixture = ConfigFixture::new(
        r#"
default_host = "local"

[hosts.local]
transport = "local"
adapter = "fake"
allow_project_selection = true

[hosts.local.provider_bindings.openai.review]
model = "gpt-5.2"
model_provider = "openai"
"#,
        r#"
default_host = "local"
model_alias = "review"
provider_alias = "openai"
"#,
    );

    fixture
        .command()
        .args(["config", "check", "--json"])
        .assert()
        .success();

    for (model_alias, provider_alias) in
        [("missing-model", "openai"), ("review", "missing-provider")]
    {
        fixture.write_project_config(&format!(
            r#"
default_host = "local"
model_alias = "{model_alias}"
provider_alias = "{provider_alias}"
"#,
        ));
        let output = fixture
            .command()
            .args(["config", "check", "--json"])
            .assert()
            .code(66)
            .get_output()
            .clone();
        let error = parse_json(&output.stderr);

        assert_eq!(error["code"], "model-provider-binding-missing");
        assert_eq!(error["details"]["host"], "local");
        assert_eq!(error["details"]["requested_model_alias"], model_alias);
        assert_eq!(error["details"]["requested_provider_alias"], provider_alias);
        assert!(
            error["suggested_commands"]
                .as_array()
                .is_some_and(|commands| !commands.is_empty())
        );
    }
}

#[cfg(feature = "test-support")]
#[test]
fn non_openai_project_binding_requires_provider_scoped_user_opt_in() {
    let fixture = ConfigFixture::new(
        r#"
default_host = "local"

[hosts.local]
transport = "local"
adapter = "fake"
allow_project_selection = true

[hosts.local.provider_bindings.anthropic.vision]
model = "claude-computer-use"
model_provider = "anthropic"
auth_source = "anthropic"

[hosts.local.provider_auth.anthropic]
kind = "environment"
variable = "SATELLE_TEST_ANTHROPIC_TOKEN"
"#,
        r#"
default_host = "local"
model_alias = "vision"
provider_alias = "anthropic"
        "#,
    );

    let output = fixture
        .command()
        .args([
            "setup",
            "--host",
            "local",
            "--component",
            "provider-auth",
            "--no-input",
            "--yes",
            "--json",
        ])
        .assert()
        .code(64)
        .get_output()
        .clone();
    let error = parse_json(&output.stderr);
    assert_eq!(error["code"], "experimental-provider-opt-in-required");

    fixture.write_user_config(
        r#"
default_host = "local"

[hosts.local]
transport = "local"
adapter = "fake"
allow_project_selection = true

[hosts.local.experimental_provider_computer_use_by_provider]
anthropic = true

[hosts.local.provider_bindings.anthropic.vision]
model = "claude-computer-use"
model_provider = "anthropic"
auth_source = "anthropic"

[hosts.local.provider_auth.anthropic]
kind = "environment"
variable = "SATELLE_TEST_ANTHROPIC_TOKEN"
"#,
    );
    fixture
        .command()
        .args([
            "setup",
            "--host",
            "local",
            "--component",
            "provider-auth",
            "--no-input",
            "--yes",
            "--json",
        ])
        .assert()
        .success();
    fixture
        .command()
        .args(["host", "release-state"])
        .assert()
        .success();
    fixture
        .command()
        .args(["run", "--json", "test non-openai opt-in"])
        .assert()
        .success();
}

#[test]
fn provider_auth_config_accepts_descriptors_but_rejects_raw_secret_values() {
    let fixture = ConfigFixture::new(
        r#"
default_host = "local"

[hosts.local]
transport = "local"
adapter = "fake"
allow_project_selection = true

[hosts.local.provider_auth.openai]
kind = "environment"
variable = "OPENAI_API_KEY"

[hosts.local.provider_bindings.openai.review]
model = "gpt-5.2"
model_provider = "openai"
auth_source = "openai"
"#,
        r#"
default_host = "local"
model_alias = "review"
provider_alias = "openai"
"#,
    );

    fixture
        .command()
        .args(["config", "check", "--json"])
        .assert()
        .success();

    let raw_secret = "sk-raw-provider-secret-must-not-enter-config";
    fixture.write_user_config(&format!(
        r#"
default_host = "local"

[hosts.local]
transport = "local"
adapter = "fake"
allow_project_selection = true

[hosts.local.provider_auth.openai]
kind = "environment"
variable = "OPENAI_API_KEY"
value = "{raw_secret}"

[hosts.local.provider_bindings.openai.review]
model = "gpt-5.2"
model_provider = "openai"
auth_source = "openai"
"#,
    ));
    let output = fixture
        .command()
        .args(["config", "check", "--json"])
        .assert()
        .code(66)
        .get_output()
        .clone();
    let error = parse_json(&output.stderr);

    assert_eq!(error["code"], "unknown-config-key");
    assert!(!String::from_utf8_lossy(&output.stdout).contains(raw_secret));
    assert!(!String::from_utf8_lossy(&output.stderr).contains(raw_secret));
}
