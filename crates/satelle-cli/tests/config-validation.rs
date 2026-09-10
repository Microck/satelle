use assert_cmd::Command;
use predicates::prelude::*;
use std::fs;

#[path = "support/config-fixture.rs"]
mod config_fixture;

use config_fixture::{ConfigFixture, assert_same_file, parse_json};

#[test]
fn config_repair_preview_and_apply_preserve_comments_redact_references_and_back_up_exact_bytes() {
    let original = r#"
command_history = false
# comment-secret-canary
default-host = "local"
[hosts.local]
transport = "local"
adapter = "fake"
[hosts.local.provider_auth.unused]
kind = "environment"
variable = "REFERENCE_SECRET_CANARY"
"#;
    let fixture = ConfigFixture::new(original, "");
    let private_root = satelle_host::test_support::TestStateDir::new().unwrap();
    let state = private_root.path().join("repair-state");
    let preview = fixture
        .command()
        .env("SATELLE_STATE_DIR", &state)
        .args(["config", "repair", "--dry-run", "--json"])
        .assert()
        .success()
        .get_output()
        .clone();
    let report = parse_json(&preview.stdout);
    assert_eq!(report["schema_version"], "satelle.config.repair.v1");
    assert_eq!(report["changed"], false);
    assert_eq!(report["status"], "planned");
    assert!(
        !state.exists(),
        "dry-run must not initialize state or backup directories"
    );
    let preview_text = String::from_utf8(preview.stdout).unwrap();
    assert!(!preview_text.contains("comment-secret-canary"));
    assert!(!preview_text.contains("REFERENCE_SECRET_CANARY"));
    assert!(preview_text.contains("default-host"));
    assert!(preview_text.contains("default_host"));
    assert_eq!(
        fs::read_to_string(fixture.user_config_path()).unwrap(),
        original
    );

    let no_consent = fixture
        .command()
        .env("SATELLE_STATE_DIR", &state)
        .args(["config", "repair", "--no-input", "--json"])
        .assert()
        .code(64)
        .get_output()
        .clone();
    assert_eq!(
        parse_json(&no_consent.stderr)["code"],
        "config-repair-consent-required"
    );
    assert!(!state.exists());
    let applied = fixture
        .command()
        .env("SATELLE_STATE_DIR", &state)
        .args(["config", "repair", "--no-input", "--yes", "--json"])
        .assert()
        .success()
        .get_output()
        .clone();
    let applied = parse_json(&applied.stdout);
    assert_eq!(applied["changed"], true);
    assert_eq!(applied["files"][0]["backup_created"], true);
    let backup = std::path::Path::new(applied["files"][0]["backup_path"].as_str().unwrap());
    assert_eq!(fs::read_to_string(backup).unwrap(), original);
    assert!(backup.starts_with(&state));
    let repaired = fs::read_to_string(fixture.user_config_path()).unwrap();
    assert!(repaired.contains("# comment-secret-canary"));
    assert!(repaired.contains("REFERENCE_SECRET_CANARY"));
    assert!(repaired.contains("default_host = \"local\""));
    assert!(!repaired.contains("default-host"));
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            fs::metadata(backup).unwrap().permissions().mode() & 0o777,
            0o600
        );
        assert_eq!(
            fs::metadata(fixture.user_config_path())
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
    }
    let unchanged = fixture
        .command()
        .env("SATELLE_STATE_DIR", &state)
        .args(["config", "repair", "--yes", "--json"])
        .assert()
        .success()
        .get_output()
        .clone();
    assert_eq!(parse_json(&unchanged.stdout)["changed"], false);
    assert_eq!(
        fs::read_dir(state.join("config-repair")).unwrap().count(),
        1
    );
}

#[test]
fn config_repair_requires_explicit_selection_for_project_and_included_files() {
    let user = "command_history=false\ndefault_host='local'\n[hosts.local]\ntransport='local'\nadapter='fake'\nallow_project_selection=true\n";
    let fixture = ConfigFixture::new(user, "default-host='local'\n");
    let project = fixture.resolved_project_config();
    config_fixture::test_file::write_user_controlled(&project, "default-host='local'\n").unwrap();
    fixture
        .command()
        .args(["config", "repair", "--yes", "--json"])
        .assert()
        .code(66)
        .stderr(predicate::str::contains(
            "config-repair-manual-action-required",
        ));
    assert_eq!(
        fs::read_to_string(&project).unwrap(),
        "default-host='local'\n"
    );
    let applied = fixture
        .command()
        .args(["config", "repair", "--file"])
        .arg(&project)
        .args(["--yes", "--json"])
        .assert()
        .success()
        .get_output()
        .clone();
    assert_eq!(
        parse_json(&applied.stdout)["files"][0]["source"],
        "project_config"
    );
    assert_eq!(
        fs::read_to_string(fixture.user_config_path()).unwrap(),
        user
    );

    fixture.write_project_config("");
    fixture.write_user_config("command_history=false\ninclude=['host.toml']\n");
    let included = fixture
        .user_config_path()
        .parent()
        .unwrap()
        .join("host.toml");
    config_fixture::test_file::write_user_controlled(
        &included,
        user.replace("default_host", "default-host"),
    )
    .unwrap();
    fixture
        .command()
        .args(["config", "repair", "--yes", "--json"])
        .assert()
        .code(66);
    fixture
        .command()
        .args(["config", "repair", "--file"])
        .arg(&included)
        .args(["--yes", "--json"])
        .assert()
        .success();
    assert_eq!(fs::read_to_string(&included).unwrap(), user);
    assert_eq!(
        fs::read_to_string(fixture.user_config_path()).unwrap(),
        "command_history=false\ninclude=['host.toml']\n"
    );
}

#[test]
fn config_repair_refuses_manual_choices_and_failed_backups_without_config_writes() {
    for original in [
        "default-host='one'\ndefault_host='two'",
        "defalt_host='one'",
        "[hosts.local]\ntransport='local'\nadapter='fake'\ndaemon_idle_timeout=30",
        "broken=[",
    ] {
        let fixture = ConfigFixture::new(original, "");
        fixture
            .command()
            .args(["config", "repair", "--yes", "--json"])
            .assert()
            .code(66)
            .stderr(predicate::str::contains(
                "config-repair-manual-action-required",
            ));
        assert_eq!(
            fs::read_to_string(fixture.user_config_path()).unwrap(),
            original
        );
    }
    let original = "command_history=false\ndefault-host='local-demo'\n";
    let fixture = ConfigFixture::new(original, "");
    let blocked_state = fixture
        .user_config_path()
        .parent()
        .unwrap()
        .join("blocked-state");
    fs::write(&blocked_state, "an existing file").unwrap();
    fixture
        .command()
        .env("SATELLE_STATE_DIR", &blocked_state)
        .args(["config", "repair", "--yes", "--json"])
        .assert()
        .code(66);
    assert_eq!(
        fs::read_to_string(fixture.user_config_path()).unwrap(),
        original
    );
    assert_eq!(
        fs::read_to_string(blocked_state).unwrap(),
        "an existing file"
    );
}

#[test]
fn config_repair_trusted_consent_is_user_owned_and_limited_to_the_selected_host() {
    let original = r#"
command_history = false
default_host = "local"
profile = "maintenance"
[profiles.maintenance]
trusted_profile = "local-maintenance"
[trusted_profiles.local-maintenance]
hosts = ["local"]
command_families = ["config_repair"]
[hosts.local]
transport = "local"
adapter = "fake"
daemon-idle-timeout = "5m"
"#;
    let fixture = ConfigFixture::new(original, "");
    fixture
        .command()
        .args(["config", "repair", "--no-input", "--json"])
        .assert()
        .code(64);
    let applied = fixture
        .command()
        .args([
            "config",
            "repair",
            "--host",
            "local",
            "--no-input",
            "--json",
        ])
        .assert()
        .success()
        .get_output()
        .clone();
    assert_eq!(parse_json(&applied.stdout)["changed"], true);
    for denied in [
        original.replace("default_host", "default-host"),
        original.replace("profile = \"maintenance\"", ""),
    ] {
        fixture.write_user_config(&denied);
        fixture.write_project_config("profile='maintenance'\n");
        fixture
            .command()
            .args([
                "config",
                "repair",
                "--host",
                "local",
                "--no-input",
                "--json",
            ])
            .assert()
            .code(64);
        assert_eq!(
            fs::read_to_string(fixture.user_config_path()).unwrap(),
            denied
        );
    }
}

#[test]
fn config_check_rejects_invalid_provider_binding_table_aliases() {
    let fixture = ConfigFixture::new(
        r#"
default_host = "local"

[hosts.local]
transport = "local"
adapter = "fake"

[hosts.local.provider_bindings."invalid provider".model]
model = "provider-model"
model_provider = "custom"
"#,
        "",
    );
    let invalid_provider = fixture
        .command()
        .args(["config", "check", "--json"])
        .assert()
        .code(66)
        .get_output()
        .clone();
    let invalid_provider = parse_json(&invalid_provider.stderr);
    assert_eq!(invalid_provider["code"], "configuration-error");
    assert!(
        invalid_provider["message"].as_str().is_some_and(
            |message| message.contains("hosts.local.provider_bindings.invalid provider")
        )
    );

    fixture.write_user_config(
        r#"
default_host = "local"

[hosts.local]
transport = "local"
adapter = "fake"

[hosts.local.provider_bindings.custom."invalid model"]
model = "provider-model"
model_provider = "custom"
"#,
    );
    let invalid_model = fixture
        .command()
        .args(["config", "check", "--json"])
        .assert()
        .code(66)
        .get_output()
        .clone();
    let invalid_model = parse_json(&invalid_model.stderr);
    assert_eq!(invalid_model["code"], "configuration-error");
    assert!(invalid_model["message"].as_str().is_some_and(|message| {
        message.contains("hosts.local.provider_bindings.custom.invalid model")
    }));

    for config in [
        r#"
default_host = "local"

[hosts.local]
transport = "local"
adapter = "fake"

[hosts.local.provider_bindings.".".model]
model = "provider-model"
model_provider = "custom"
"#,
        r#"
default_host = "local"

[hosts.local]
transport = "local"
adapter = "fake"

[hosts.local.provider_bindings.custom.".."]
model = "provider-model"
model_provider = "custom"
"#,
    ] {
        fixture.write_user_config(config);
        let invalid_dot_segment = fixture
            .command()
            .args(["config", "check", "--json"])
            .assert()
            .code(66)
            .get_output()
            .clone();
        let invalid_dot_segment = parse_json(&invalid_dot_segment.stderr);
        assert_eq!(invalid_dot_segment["code"], "configuration-error");
    }
}

#[test]
fn config_check_rejects_explicit_codex_default_alias_pair() {
    let fixture = ConfigFixture::new(
        r#"
default_host = "local"
model_alias = "codex-default"
provider_alias = "codex-default"

[hosts.local]
transport = "local"
adapter = "fake"
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

    assert_eq!(error["code"], "configuration-error");
    assert!(
        error["message"]
            .as_str()
            .is_some_and(|message| message.contains("reserved for implicit Codex defaults"))
    );
}

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

#[test]
fn credential_helpers_are_validated_and_redacted_without_execution() {
    let executable =
        toml::Value::String(std::env::current_exe().unwrap().display().to_string()).to_string();
    let fixture = ConfigFixture::new(
        &format!(
            r#"
[hosts.local-demo]
transport = "local"
adapter = "fake"

[hosts.local-demo.provider_auth.openai]
kind = "executable-helper"
argv = [{executable}, "--exact", "secret_source_command_canary_child", "--nocapture"]
environment = {{ PRIVATE_HELPER_ACCOUNT = "private-account" }}
"#
        ),
        "",
    );
    let canary = fixture.user_config_path().with_extension("executed");
    fixture
        .command()
        .env("SATELLE_TEST_COMMAND_CANARY_PATH", &canary)
        .args(["config", "check", "--json"])
        .assert()
        .success();
    for options in [
        vec!["config", "explain", "--json"],
        vec!["config", "explain", "--show-secret-references", "--json"],
    ] {
        let output = fixture
            .command()
            .env("SATELLE_TEST_COMMAND_CANARY_PATH", &canary)
            .args(options)
            .assert()
            .success()
            .get_output()
            .clone();
        let report = parse_json(&output.stdout);
        let source = &report["effective"]["hosts"]["local-demo"]["provider_auth"]["openai"];
        assert_eq!(source["kind"], "executable-helper");
        assert_eq!(source["timeout"], "10s");
        assert_eq!(source["redacted"], true);
        let encoded = String::from_utf8(output.stdout).unwrap();
        for private in [
            "secret_source_command_canary_child",
            "PRIVATE_HELPER_ACCOUNT",
            "private-account",
        ] {
            assert!(!encoded.contains(private), "explain revealed {private}");
        }
    }
    assert!(!canary.exists(), "config inspection executed the helper");
}

#[test]
fn credential_helper_invalid_argv_timeout_and_placement_are_typed_errors() {
    let fixture = ConfigFixture::new("", "");
    for (descriptor, expected) in [
        ("argv = []", "credential-helper-argv-invalid"),
        ("argv = 'helper --token'", "credential-helper-argv-invalid"),
        ("argv = ['helper']", "credential-helper-argv-invalid"),
        (
            "argv = ['/bin/sh', '-c', 'private-inline-script']",
            "credential-helper-argv-invalid",
        ),
        (
            "argv = ['/absolute/helper']\ntimeout = 10",
            "duration-unit-required",
        ),
        (
            "argv = ['/absolute/helper']\nenvironment = { 'BAD-KEY' = 'private-value' }",
            "configuration-error",
        ),
        (
            "argv = ['/absolute/helper']\nenvironment = { 'VALID_KEY' = ['private-value'] }",
            "configuration-error",
        ),
    ] {
        fixture.write_user_config(&format!("[hosts.local-demo]\ntransport = 'local'\nadapter = 'fake'\n[hosts.local-demo.provider_auth.openai]\nkind = 'executable-helper'\n{descriptor}\n"));
        let output = fixture
            .command()
            .args(["config", "check", "--json"])
            .assert()
            .code(66)
            .get_output()
            .clone();
        assert_eq!(parse_json(&output.stderr)["code"], expected, "{descriptor}");
        assert!(
            !String::from_utf8(output.stderr)
                .unwrap()
                .contains("private-")
        );
    }
    fixture.write_user_config("");
    for prefix in ["hosts.local-demo.", ""] {
        fixture.write_project_config(&format!("[{prefix}provider_auth.openai]\nkind = 'executable-helper'\nargv = ['/absolute/helper']\n"));
        let output = fixture
            .command()
            .args(["config", "check", "--json"])
            .assert()
            .code(66)
            .get_output()
            .clone();
        assert_eq!(
            parse_json(&output.stderr)["code"],
            "project-credential-helper-not-allowed"
        );
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
fn project_model_and_provider_intent_defers_missing_host_bindings() {
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
allow_project_selection = true
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
            .success()
            .get_output()
            .clone();
        let report = parse_json(&output.stdout);

        assert_eq!(report["status"], "ok");
        assert!(
            report["not_checked"]
                .as_array()
                .is_some_and(|checks| checks.iter().any(|check| check == "provider_auth"))
        );
    }
}

#[test]
fn config_check_rejects_project_aliases_without_exact_provider_binding_consent() {
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

    let output = fixture
        .command()
        .args(["config", "check", "--json"])
        .assert()
        .code(66)
        .get_output()
        .clone();
    let error = parse_json(&output.stderr);

    assert_eq!(error["code"], "project-provider-selection-not-allowed");
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
endpoint = "https://anthropic.invalid/v1"
auth_source = "anthropic"
allow_project_selection = true

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
endpoint = "https://anthropic.invalid/v1"
auth_source = "anthropic"
allow_project_selection = true

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
allow_project_selection = true
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
allow_project_selection = true
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

#[test]
fn secret_file_home_inspection_uses_the_local_account_and_defers_remote_accounts() {
    let fixture = ConfigFixture::new(
        r#"
default_host = "local"
[hosts.local]
transport = "local"
adapter = "fake"
[hosts.local.provider_auth.work]
kind = "file"
path = "~/satelle-home-inspection-missing/token"
[hosts.remote]
transport = "ssh"
adapter = "codex"
address = "unused.invalid"
[hosts.remote.provider_auth.work]
kind = "file"
path = "~/satelle-home-inspection-missing/token"
"#,
        "",
    );
    fixture
        .command()
        .args(["config", "check", "--all", "--json"])
        .assert()
        .success();
    let hidden = fixture
        .command()
        .args(["config", "explain", "--json"])
        .assert()
        .success()
        .get_output()
        .clone();
    assert!(!String::from_utf8_lossy(&hidden.stdout).contains("satelle-home-inspection-missing"));
    let home = satelle_core::resolver_account_home().expect("test account has a home");
    let overridden_home = fixture.user_config_path().parent().unwrap();
    // Windows discovers application directories before loading configuration.
    // Keep that discovery valid while proving the account home ignores overrides.
    std::fs::create_dir_all(overridden_home.join("AppData/Local")).unwrap();
    std::fs::create_dir_all(overridden_home.join("AppData/Roaming")).unwrap();
    let shown = fixture
        .command()
        .env("HOME", overridden_home)
        .env("USERPROFILE", overridden_home)
        .args(["config", "explain", "--show-secret-references", "--json"])
        .assert()
        .success()
        .get_output()
        .clone();
    let report = parse_json(&shown.stdout);
    let local = &report["effective"]["hosts"]["local"]["provider_auth"]["work"];
    assert_eq!(
        local["path"],
        serde_json::json!(home.join("satelle-home-inspection-missing").join("token"))
    );
    assert_eq!(local["normalization_status"], "expanded");
    let remote = &report["effective"]["hosts"]["remote"]["provider_auth"]["work"];
    assert_eq!(remote["path"], serde_json::Value::Null);
    assert_eq!(remote["normalization_status"], "remote_home_not_checked");
}

#[test]
fn secret_file_home_syntax_errors_have_typed_redacted_source_details() {
    let fixture = ConfigFixture::new("", "");
    for path in [
        "~another/token",
        r"~domain\user",
        "~~/token",
        "/private/~/token",
        "~/$PRIVATE_NAME",
        "~/%PRIVATE_NAME%",
        "~/$(private-command)",
        "~/`private-command`",
    ] {
        let source = serde_json::json!({"hosts":{"local":{"transport":"local","adapter":"fake","provider_auth":{"work":{"kind":"file","path":path}}}}});
        fixture.write_user_config(&toml::to_string(&source).unwrap());
        let output = fixture
            .command()
            .args(["config", "check", "--host", "local", "--json"])
            .assert()
            .code(66)
            .get_output()
            .clone();
        let error = parse_json(&output.stderr);
        assert_eq!(
            error["code"], "secret-file-tilde-form-unsupported",
            "{path}"
        );
        assert_eq!(error["details"]["host"], "local");
        assert_eq!(
            error["details"]["toml_path"],
            "hosts.local.provider_auth.work.path"
        );
        assert_eq!(error["details"]["secret_source_kind"], "file");
        assert!(error["details"]["config_file"].is_string());
        assert!(error["details"]["supported_forms"].is_array());
        assert!(error["suggested_commands"].is_array());
        assert!(!String::from_utf8_lossy(&output.stderr).contains(path));
    }
}

#[test]
fn secret_file_home_shorthand_does_not_authorize_project_secret_sources() {
    let fixture = ConfigFixture::new(
        "",
        r#"
[hosts.local.provider_auth.work]
kind = "file"
path = "~/private-token"
"#,
    );
    let output = fixture
        .command()
        .args(["config", "check", "--json"])
        .assert()
        .code(66)
        .get_output()
        .clone();
    assert_eq!(
        parse_json(&output.stderr)["code"],
        "project-secret-source-not-allowed"
    );
    assert!(!String::from_utf8_lossy(&output.stderr).contains("private-token"));
}
