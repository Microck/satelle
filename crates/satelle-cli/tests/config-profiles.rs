use predicates::prelude::*;

#[path = "support/config-fixture.rs"]
mod config_fixture;

use config_fixture::{ConfigFixture, assert_same_file, parse_json};

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
allow_project_selection = true

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
fn config_check_all_enumerates_only_selectable_contexts() {
    let fixture = ConfigFixture::new(
        r#"
default_host = "user-host"

[hosts.user-host]
transport = "local"
adapter = "fake"
allow_project_selection = true

[hosts.work-host]
transport = "local"
adapter = "fake"
allow_project_selection = true

[profiles.work]
host = "work-host"

[profiles.audit]
model_alias = "audit-model"
"#,
        r#"
default_host = "user-host"
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
        .expect("checked contexts should be an array");

    let context = |host: &str, profile: Option<&str>, source: &str| {
        contexts.iter().any(|context| {
            context["host"] == host
                && context["profile"].as_str() == profile
                && context["source"] == source
        })
    };

    assert!(context("work-host", Some("work"), "default_context"));
    assert!(context("user-host", None, "configured_host"));
    assert!(context("work-host", None, "configured_host"));
    assert!(context("work-host", Some("work"), "configured_profile"));
    assert!(context("user-host", Some("audit"), "configured_profile"));
    assert!(context("work-host", Some("work"), "project_defaults"));

    // `audit` defaults to user-host. `work-host` + `audit` would exist only in a synthesized
    // host/profile cross product, so all-context validation must not invent it.
    assert!(
        !contexts
            .iter()
            .any(|context| { context["host"] == "work-host" && context["profile"] == "audit" })
    );
}

#[test]
fn untrusted_profile_selectors_do_not_activate_yolo_policy() {
    let fixture = ConfigFixture::new(
        r#"
default_host = "local-demo"

[hosts.local-demo]
transport = "local"
adapter = "fake"
allow_project_selection = true

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
allow_project_selection = true

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
    assert_eq!(missing["code"], "profile-not-found");
    assert_eq!(missing["details"]["profile"], "missing");

    fixture.write_project_config(
        r#"
[profiles.checkout-controlled]
host = "attacker-host"
"#,
    );
    let project_profile = fixture
        .command()
        .args(["config", "check", "--json"])
        .assert()
        .code(66)
        .get_output()
        .clone();
    let project_profile = parse_json(&project_profile.stderr);
    assert_eq!(
        project_profile["code"],
        "project-profile-definition-not-allowed"
    );
    assert_same_file(
        &project_profile["details"]["file"],
        &fixture.resolved_project_config(),
    );
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
    assert_eq!(error["code"], "unknown-config-key");
    assert_eq!(error["details"]["path"], "profiles.broken.hosts");
    assert_same_file(&error["details"]["file"], fixture.user_config_path());

    fixture.write_user_config(
        r#"
[profiles.unbound]
yolo = true
"#,
    );
    fixture
        .command()
        .args(["config", "check", "--json"])
        .assert()
        .code(66)
        .stderr(predicate::str::contains(
            "must bind yolo to a non-empty host alias",
        ));

    fixture.write_user_config(
        r#"
[profiles.broken.timeouts]
provider_timeout = "120s"
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
    assert_eq!(error["code"], "unknown-timeout-key");
    assert_eq!(
        error["details"]["path"],
        "profiles.broken.timeouts.provider_timeout"
    );

    fixture.write_user_config(
        r#"
[profiles.missing-host]
host = "not-configured"
"#,
    );
    fixture
        .command()
        .args(["config", "check", "--json"])
        .assert()
        .success();
    let output = fixture
        .command()
        .args(["config", "check", "--all", "--json"])
        .assert()
        .code(66)
        .get_output()
        .clone();
    let error = parse_json(&output.stderr);
    assert_eq!(error["code"], "host-not-found");
    assert_eq!(error["message"], "host 'not-configured' is not configured");
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

#[test]
fn direct_host_binding_accepts_only_an_external_absolute_token_file_reference() {
    let token_path = std::env::temp_dir().join("satelle-token-reference");
    let token_path_literal =
        toml::Value::String(token_path.to_string_lossy().into_owned()).to_string();
    let ca_bundle_path = std::env::temp_dir().join("satelle-ca-bundle.pem");
    let ca_bundle_path_literal =
        toml::Value::String(ca_bundle_path.to_string_lossy().into_owned()).to_string();
    let user_config = format!(
        r#"
default_host = "remote"

[hosts.remote]
transport = "direct"
adapter = "codex"
address = "https://windows.example.test"
expected_host_id = "host-windows-11"
api_token = {{ kind = "file", path = {token_path_literal} }}
ca_bundle = {ca_bundle_path_literal}
"#
    );
    let fixture = ConfigFixture::new(&user_config, "");

    let hidden = fixture
        .command()
        .args(["config", "explain", "--json"])
        .assert()
        .success()
        .get_output()
        .clone();
    let hidden = parse_json(&hidden.stdout);
    assert_eq!(
        hidden["effective"]["hosts"]["remote"]["api_token"],
        serde_json::json!({
            "kind": "file",
            "value": null,
            "redacted": true,
            "redaction_reason": "secret_source_reference",
            "source": "user_config",
        })
    );

    let revealed = fixture
        .command()
        .args(["config", "explain", "--show-secret-references", "--json"])
        .assert()
        .success()
        .get_output()
        .clone();
    let revealed = parse_json(&revealed.stdout);
    assert_eq!(
        revealed["effective"]["hosts"]["remote"]["api_token"],
        serde_json::json!({
            "kind": "file",
            "path": token_path.to_string_lossy(),
            "redacted": false,
            "source": "user_config",
        })
    );
    assert_eq!(
        revealed["effective"]["hosts"]["remote"]["ca_bundle"],
        serde_json::json!(ca_bundle_path)
    );

    fixture.write_user_config(
        r#"
[hosts.remote]
transport = "direct"
adapter = "codex"
address = "https://windows.example.test"
expected_host_id = "host-windows-11"
api_token = { kind = "file", path = "relative.token" }
"#,
    );
    let invalid = fixture
        .command()
        .args(["config", "check", "--json"])
        .assert()
        .code(66)
        .get_output()
        .clone();
    let invalid = parse_json(&invalid.stderr);
    assert_eq!(invalid["code"], "secret-file-path-not-absolute");
    assert_eq!(invalid["details"]["path"], "hosts.remote.api_token.path");

    fixture.write_user_config(&format!(
        r#"
[hosts.remote]
transport = "direct"
adapter = "codex"
address = "https://windows.example.test"
expected_host_id = "host-windows-11"
api_token = {{ kind = "file", path = {token_path_literal} }}
ca_bundle = "relative-ca.pem"
"#
    ));
    let invalid = fixture
        .command()
        .args(["config", "check", "--json"])
        .assert()
        .code(66)
        .get_output()
        .clone();
    let invalid = parse_json(&invalid.stderr);
    assert_eq!(invalid["code"], "secret-file-path-not-absolute");
    assert_eq!(invalid["details"]["path"], "hosts.remote.ca_bundle");
}
