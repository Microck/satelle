use predicates::prelude::*;
use std::fs;

#[path = "support/config-fixture.rs"]
mod config_fixture;

use config_fixture::{ConfigFixture, assert_same_file, parse_json, test_file};

#[test]
fn includes_preserve_order_source_boundaries_and_exact_field_origins() {
    let fixture = ConfigFixture::new(
        "include = [\"first.toml\", \"last.toml\"]\ncommand_history = false\n",
        "include = [\"shared.toml\"]\n",
    );
    let user_root = fixture.user_config_path().parent().unwrap();
    test_file::write_user_controlled(
        &user_root.join("first.toml"),
        r#"
log_verbosity = "info"
command_history = true
[profiles.work]
log_verbosity = "trace"
[hosts.included]
transport = "local"
adapter = "fake"
"#,
    )
    .unwrap();
    test_file::write_user_controlled(&user_root.join("last.toml"), "log_verbosity = \"debug\"\n")
        .unwrap();
    let shared = fixture
        .resolved_project_config()
        .parent()
        .unwrap()
        .join("shared.toml");
    fs::write(&shared, "output_format = \"json\"\n").unwrap();

    let output = fixture
        .command()
        .args(["config", "explain", "--json"])
        .assert()
        .success()
        .get_output()
        .clone();
    let report = parse_json(&output.stdout);
    assert_eq!(report["effective"]["log_verbosity"], "debug");
    assert_eq!(report["effective"]["command_history"], false);
    assert_eq!(report["effective"]["output_format"], "json");
    assert_eq!(report["checked_files"].as_array().unwrap().len(), 5);
    assert_same_file(
        &report["sources"]["values"]["log_verbosity"]["config_file"],
        &user_root.join("last.toml"),
    );
    assert_same_file(
        &report["sources"]["values"]["command_history"]["config_file"],
        fixture.user_config_path(),
    );
    assert_same_file(
        &report["sources"]["values"]["output_format"]["config_file"],
        &shared,
    );
    assert_eq!(
        report["sources"]["values"]["output_format"]["source"],
        "project_config"
    );
    assert_same_file(
        &report["sources"]["files"][0]["parent"],
        fixture.user_config_path(),
    );

    let profile = fixture
        .command()
        .args(["config", "explain", "--profile", "work", "--json"])
        .assert()
        .success()
        .get_output()
        .clone();
    let profile = parse_json(&profile.stdout);
    assert_eq!(profile["effective"]["log_verbosity"], "trace");
    assert_eq!(
        profile["sources"]["values"]["log_verbosity"]["toml_path"],
        "profiles.work.log_verbosity"
    );
    assert_same_file(
        &profile["sources"]["values"]["log_verbosity"]["config_file"],
        &user_root.join("first.toml"),
    );
    fixture
        .command()
        .args(["config", "check", "--all", "--json"])
        .assert()
        .success();
}

#[test]
fn nested_includes_resolve_from_the_declaring_file_and_parent_wins() {
    let fixture = ConfigFixture::new("include = [\"nested/parent.toml\"]\n", "");
    let nested = fixture.user_config_path().parent().unwrap().join("nested");
    fs::create_dir(&nested).unwrap();
    test_file::write_user_controlled(
        &nested.join("parent.toml"),
        "include = [\"child.toml\"]\nlog_verbosity = \"debug\"\n",
    )
    .unwrap();
    test_file::write_user_controlled(
        &nested.join("child.toml"),
        "include = [\"../shared.toml\"]\nlog_verbosity = \"trace\"\n",
    )
    .unwrap();
    test_file::write_user_controlled(
        &nested.parent().unwrap().join("shared.toml"),
        "command_history = false\n",
    )
    .unwrap();
    let output = fixture
        .command()
        .args(["config", "explain", "--json"])
        .assert()
        .success()
        .get_output()
        .clone();
    let report = parse_json(&output.stdout);
    assert_eq!(report["effective"]["log_verbosity"], "debug");
    assert_same_file(
        &report["sources"]["files"][0]["parent"],
        &nested.join("child.toml"),
    );
    assert_same_file(
        &report["sources"]["files"][1]["parent"],
        &nested.join("parent.toml"),
    );
}

#[test]
fn literal_aliases_keep_distinct_origins_when_another_binding_is_replaced() {
    let fixture = ConfigFixture::new(
        r#"
include = ["bindings.toml"]
default_host = "office.shared"
[hosts.office]
transport = "local"
adapter = "fake"
"#,
        "",
    );
    let bindings = fixture
        .user_config_path()
        .parent()
        .unwrap()
        .join("bindings.toml");
    test_file::write_user_controlled(
        &bindings,
        r#"
[hosts.office]
transport = "local"
adapter = "fake"
desktop_user = "replaced"
[hosts."office.shared"]
transport = "local"
adapter = "fake"
"#,
    )
    .unwrap();
    let output = fixture
        .command()
        .args(["config", "explain", "--json"])
        .assert()
        .success()
        .get_output()
        .clone();
    let report = parse_json(&output.stdout);
    assert_same_file(
        &report["sources"]["values"]["hosts.\"office.shared\".adapter"]["config_file"],
        &bindings,
    );
    assert_same_file(
        &report["sources"]["values"]["hosts.office.adapter"]["config_file"],
        fixture.user_config_path(),
    );
    assert!(
        report["sources"]["values"]
            .get("hosts.office.desktop_user")
            .is_none()
    );
    assert!(report["effective"]["hosts"]["office"]["desktop_user"].is_null());
}

#[test]
fn setup_persists_desktop_selection_in_the_include_that_owns_the_binding() {
    let root_config = "include = [\"binding.toml\"]\ndefault_host = \"local-demo\"\n";
    let fixture = ConfigFixture::new(root_config, "");
    let binding = fixture
        .user_config_path()
        .parent()
        .unwrap()
        .join("binding.toml");
    test_file::write_user_controlled(
        &binding,
        r#"
[hosts.local-demo]
transport = "local"
adapter = "fake"
"#,
    )
    .unwrap();
    fixture
        .command()
        .args([
            "setup",
            "--host",
            "local-demo",
            "--component",
            "desktop",
            "--no-input",
            "--yes",
            "--json",
        ])
        .assert()
        .success();

    assert_eq!(
        fs::read_to_string(fixture.user_config_path()).unwrap(),
        root_config
    );
    let persisted: toml::Value = toml::from_str(&fs::read_to_string(&binding).unwrap()).unwrap();
    assert_eq!(
        persisted["hosts"]["local-demo"]["desktop_user"].as_str(),
        Some("local-demo-user")
    );
    fixture
        .command()
        .args(["config", "check", "--all", "--json"])
        .assert()
        .success();
}

#[test]
fn include_cycles_and_paths_outside_the_source_are_typed_errors() {
    let fixture = ConfigFixture::new("include = [\"cycle.toml\"]\n", "");
    let cycle = fixture
        .user_config_path()
        .parent()
        .unwrap()
        .join("cycle.toml");
    test_file::write_user_controlled(&cycle, "include = [\"user-config.toml\"]\n").unwrap();
    let output = fixture
        .command()
        .args(["config", "check", "--json"])
        .assert()
        .code(66)
        .get_output()
        .clone();
    let error = parse_json(&output.stderr);
    assert_eq!(error["code"], "config-include-cycle");
    assert_eq!(
        error["details"]["include_chain"].as_array().unwrap().len(),
        3
    );

    fixture.write_user_config("");
    fs::write(
        fixture
            .resolved_project_config()
            .parent()
            .unwrap()
            .parent()
            .unwrap()
            .join("outside.toml"),
        "",
    )
    .unwrap();
    fixture.write_project_config("include = [\"../outside.toml\"]\n");
    let output = fixture
        .command()
        .args(["config", "check", "--json"])
        .assert()
        .code(66)
        .get_output()
        .clone();
    assert_eq!(
        parse_json(&output.stderr)["code"],
        "config-include-outside-source"
    );
}

#[test]
fn includes_validate_overridden_files_and_reject_project_owned_credentials() {
    let fixture = ConfigFixture::new(
        "include = [\"invalid.toml\"]\nlog_verbosity = \"info\"\n",
        "",
    );
    let invalid = fixture
        .user_config_path()
        .parent()
        .unwrap()
        .join("invalid.toml");
    test_file::write_user_controlled(&invalid, "log_verbosity = \"not-a-level\"\n").unwrap();
    fixture
        .command()
        .args(["config", "check", "--json"])
        .assert()
        .code(66);
    fixture.write_user_config("");
    fixture.write_project_config("include = [\"secret.toml\"]\n");
    fs::write(
        fixture
            .resolved_project_config()
            .parent()
            .unwrap()
            .join("secret.toml"),
        "[hosts.office.provider_auth]\nprovider = { kind = \"env\", name = \"INCLUDE_CANARY\" }\n",
    )
    .unwrap();
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
    assert!(!String::from_utf8_lossy(&output.stderr).contains("INCLUDE_CANARY"));
}

#[test]
fn include_entries_reject_missing_files_globs_urls_and_shell_syntax() {
    let fixture = ConfigFixture::new("", "");
    test_file::write_user_controlled(
        &fixture
            .user_config_path()
            .parent()
            .unwrap()
            .join("%HOME%.toml"),
        "",
    )
    .unwrap();
    for entry in [
        "missing.toml",
        "*.toml",
        "https://example.test/config.toml",
        "~/config.toml",
        "$HOME/config.toml",
        "%HOME%.toml",
    ] {
        fixture.write_user_config(&format!(
            "include = [{}]\n",
            serde_json::to_string(entry).unwrap()
        ));
        let output = fixture
            .command()
            .args(["config", "check", "--json"])
            .assert()
            .code(66)
            .get_output()
            .clone();
        assert_eq!(
            parse_json(&output.stderr)["code"],
            "config-include-invalid",
            "{entry}"
        );
    }
}

#[cfg(unix)]
#[test]
fn includes_reject_symlinks_even_when_the_target_is_inside_the_source() {
    let fixture = ConfigFixture::new("include = [\"linked.toml\"]\n", "");
    let root = fixture.user_config_path().parent().unwrap();
    test_file::write_user_controlled(&root.join("regular.toml"), "").unwrap();
    std::os::unix::fs::symlink(root.join("regular.toml"), root.join("linked.toml")).unwrap();
    let output = fixture
        .command()
        .args(["config", "check", "--json"])
        .assert()
        .code(66)
        .get_output()
        .clone();
    assert_eq!(parse_json(&output.stderr)["code"], "config-include-invalid");
}

#[test]
fn expired_trusted_profiles_are_explainable_but_cannot_authorize_maintenance() {
    let fixture = ConfigFixture::new(
        r#"
include = ["consent.toml"]
profile = "maintenance"
[hosts.local-demo]
transport = "local"
adapter = "fake"
[profiles.maintenance]
trusted_profile = "limited"
"#,
        "",
    );
    let consent = fixture
        .user_config_path()
        .parent()
        .unwrap()
        .join("consent.toml");
    test_file::write_user_controlled(
        &consent,
        r#"
[trusted_profiles.limited]
hosts = ["local-demo"]
command_families = ["setup", "repair", "host_update", "self_update_remotes", "doctor_fix"]
expires_at = "2000-01-01T00:00:00Z"
"#,
    )
    .unwrap();
    let explained = fixture
        .command()
        .args(["config", "explain", "--json"])
        .assert()
        .success()
        .get_output()
        .clone();
    let explained = parse_json(&explained.stdout);
    let grant = &explained["values"]["noninteractive_mutation_consent"];
    assert_eq!(grant["trusted_profile"]["expiration_state"], "expired");
    assert_eq!(grant["command_families"]["setup"]["active"], false);
    assert_same_file(&grant["trusted_profile"]["source"]["config_file"], &consent);
    for args in [
        vec!["config", "check", "--json"],
        vec!["setup", "--no-input", "--json"],
        vec!["repair", "--no-input", "--json"],
        vec!["host", "update", "--no-input", "--json"],
    ] {
        let output = fixture
            .command()
            .args(args)
            .assert()
            .code(66)
            .get_output()
            .clone();
        assert_eq!(
            parse_json(&output.stderr)["code"],
            "trusted-profile-expired"
        );
    }
    fixture
        .command()
        .args(["setup", "--dry-run", "--no-input", "--json"])
        .assert()
        .success();
    let explicit = fixture
        .command()
        .args(["setup", "--yes", "--no-input", "--json"])
        .output()
        .unwrap();
    assert!(!String::from_utf8_lossy(&explicit.stderr).contains("trusted-profile-expired"));
}

#[test]
fn trusted_profile_expiration_is_explicit_and_all_checks_unselected_grants() {
    let fixture = ConfigFixture::new(
        r#"
[profiles.work]
trusted_profile = "durable"
[trusted_profiles.durable]
hosts = ["local-demo"]
command_families = ["setup"]
[trusted_profiles.expired]
hosts = ["local-demo"]
command_families = ["setup"]
expires_at = "2000-01-01T00:00:00Z"
"#,
        "",
    );
    fixture
        .command()
        .args(["config", "check", "--profile", "work", "--json"])
        .assert()
        .success();
    let output = fixture
        .command()
        .args(["config", "check", "--all", "--json"])
        .assert()
        .code(66)
        .get_output()
        .clone();
    assert_eq!(
        parse_json(&output.stderr)["code"],
        "trusted-profile-expired"
    );
    let output = fixture
        .command()
        .args(["config", "explain", "--profile", "work", "--json"])
        .assert()
        .success()
        .get_output()
        .clone();
    assert_eq!(
        parse_json(&output.stdout)["values"]["noninteractive_mutation_consent"]["trusted_profile"]
            ["expiration_state"],
        "absent"
    );
}

#[test]
fn global_profile_overlays_merged_config_and_selected_host() {
    let fixture = ConfigFixture::new(
        r#"
default_host = "base-host"
model_alias = "base-model"
provider_alias = "base-provider"

[hosts.base-host]
transport = "local"
adapter = "fake"

[hosts.base-host.provider_bindings.base-provider.base-model]
model = "base-model"
model_provider = "base-provider"

[hosts.work-host]
transport = "local"
adapter = "fake"
daemon_idle_timeout = "12m"
provider_smoke_success_cache_ttl = "1080m"
provider_smoke_failure_cache_ttl = "8m"

[hosts.work-host.provider_bindings.work-provider.work-model]
model = "work-model"
model_provider = "work-provider"

[hosts.work-host.timeouts]
provider_smoke_test = "11s"

[profiles.work]
host = "work-host"
model_alias = "work-model"
provider_alias = "work-provider"
log_verbosity = "trace"
experimental_provider_computer_use = true
yolo = true
daemon_idle_timeout = "3m"
provider_smoke_success_cache_ttl = "1200m"
provider_smoke_failure_cache_ttl = "6m"

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
    assert_eq!(report["effective"]["log_verbosity"], "trace");
    assert_eq!(
        report["effective"]["experimental_provider_computer_use"],
        true
    );
    assert_eq!(report["effective"]["yolo"], serde_json::Value::Null);
    assert_eq!(report["effective"]["hosts"]["work-host"]["yolo"], true);
    assert_eq!(
        report["effective"]["hosts"]["work-host"]["daemon_idle_timeout"],
        "3m"
    );
    assert_eq!(
        report["effective"]["hosts"]["work-host"]["provider_smoke_success_cache_ttl"],
        "1200m"
    );
    assert_eq!(
        report["effective"]["hosts"]["work-host"]["provider_smoke_failure_cache_ttl"],
        "6m"
    );
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
        report["values"]["effective_timeouts"]["provider_smoke_success_cache_ttl_ms"],
        72_000_000
    );
    assert_eq!(
        report["values"]["effective_timeouts"]["provider_smoke_failure_cache_ttl_ms"],
        360_000
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
fn profile_output_format_is_an_effective_presentation_default() {
    let fixture = ConfigFixture::new(
        r#"
[profiles.machine]
output_format = "json"
"#,
        "",
    );

    let output = fixture
        .command()
        .args(["--profile", "machine", "config", "explain"])
        .assert()
        .success()
        .get_output()
        .clone();
    let report = parse_json(&output.stdout);

    assert_eq!(report["selected_profile"], "machine");
    assert_eq!(report["effective"]["output_format"], "json");
}

#[test]
fn daemon_idle_timeout_requires_explicit_units_on_hosts_and_profiles() {
    for config in [
        r#"
[hosts.local-demo]
transport = "local"
adapter = "fake"
daemon_idle_timeout = 600
"#,
        r#"
[hosts.local-demo]
transport = "local"
adapter = "fake"

[profiles.work]
host = "local-demo"
daemon_idle_timeout = "600"
"#,
    ] {
        ConfigFixture::new(config, "")
            .command()
            .args(["config", "check", "--json"])
            .assert()
            .failure()
            .stderr(predicate::str::contains("daemon_idle_timeout"));
    }
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
fn config_check_context_selectors_do_not_change_stored_defaults() {
    let fixture = ConfigFixture::new(
        r#"
default_host = "default-host"
profile = "default-profile"

[hosts.default-host]
transport = "local"
adapter = "fake"

[hosts.profile-host]
transport = "local"
adapter = "fake"

[hosts.flag-host]
transport = "local"
adapter = "fake"

[profiles.default-profile]
host = "default-host"

[profiles.work]
host = "profile-host"
"#,
        "",
    );
    let user_config_before = fs::read(fixture.user_config_path())
        .expect("user config should be readable before config check");
    let project_config_path = fixture.resolved_project_config();
    let project_config_before = fs::read(&project_config_path)
        .expect("project config should be readable before config check");

    let selected = fixture
        .command()
        .args([
            "config",
            "check",
            "--host",
            "flag-host",
            "--profile",
            "work",
            "--json",
        ])
        .assert()
        .success()
        .get_output()
        .clone();
    let selected = parse_json(&selected.stdout);
    assert_eq!(selected["selected_host"], "flag-host");
    assert_eq!(selected["selected_profile"], "work");
    assert_eq!(selected["checked_contexts"][0]["source"], "cli_flag");

    let profile_only = fixture
        .command()
        .args(["config", "check", "--profile", "work", "--json"])
        .assert()
        .success()
        .get_output()
        .clone();
    let profile_only = parse_json(&profile_only.stdout);
    assert_eq!(profile_only["selected_host"], "profile-host");
    assert_eq!(profile_only["selected_profile"], "work");

    let defaults = fixture
        .command()
        .args(["config", "check", "--json"])
        .assert()
        .success()
        .get_output()
        .clone();
    let defaults = parse_json(&defaults.stdout);
    assert_eq!(defaults["selected_host"], "default-host");
    assert_eq!(defaults["selected_profile"], "default-profile");
    assert_eq!(defaults["checked_contexts"][0]["source"], "user_config");

    assert_eq!(
        fs::read(fixture.user_config_path())
            .expect("user config should be readable after config check"),
        user_config_before
    );
    assert_eq!(
        fs::read(project_config_path)
            .expect("project config should be readable after config check"),
        project_config_before
    );
}

#[test]
fn config_check_all_enumerates_only_selectable_contexts() {
    let fixture = ConfigFixture::new(
        r#"
default_host = "user-host"
model_alias = "base-model"
provider_alias = "openai"

[hosts.user-host]
transport = "local"
adapter = "fake"
allow_project_selection = true

[hosts.user-host.provider_bindings.openai.base-model]
model = "base-model"
model_provider = "openai"

[hosts.user-host.provider_bindings.openai.audit-model]
model = "audit-model"
model_provider = "openai"

[hosts.local-demo]
transport = "local"
adapter = "fake"

[hosts.local-demo.provider_bindings.openai.base-model]
model = "base-model"
model_provider = "openai"

[hosts.work-host]
transport = "local"
adapter = "fake"
allow_project_selection = true

[hosts.work-host.provider_bindings.openai.base-model]
model = "base-model"
model_provider = "openai"

[hosts.work-host.provider_bindings.openai.work-model]
model = "work-model"
model_provider = "openai"
allow_project_selection = true

[profiles.work]
host = "work-host"
model_alias = "work-model"

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
provider_alias = "profile-provider"
experimental_provider_computer_use = true
yolo = true

[hosts.local-demo.provider_bindings.profile-provider.profile-model]
model = "profile-model"
model_provider = "openai"
allow_project_selection = true
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
            report["values"]["model_provider"]["model_alias_from_project"],
            source == "project_config"
        );
        assert_eq!(
            report["values"]["model_provider"]["provider_alias_from_project"],
            source == "project_config"
        );
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

    fixture
        .command()
        .args([
            "setup",
            "--profile",
            "unsafe",
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
fn project_selected_profile_requires_exact_provider_binding_consent() {
    let fixture = ConfigFixture::new(
        r#"
default_host = "local-demo"

[hosts.local-demo]
transport = "local"
adapter = "fake"
allow_project_selection = true

[profiles.review]
model_alias = "review"
provider_alias = "openai"

[hosts.local-demo.provider_bindings.openai.review]
model = "gpt-5.2"
model_provider = "openai"
"#,
        r#"
profile = "review"
"#,
    );

    let denied = fixture
        .command()
        .args(["config", "check", "--json"])
        .assert()
        .code(66)
        .get_output()
        .clone();
    let denied = parse_json(&denied.stderr);
    assert_eq!(denied["code"], "project-provider-selection-not-allowed");

    let denied_all = fixture
        .command()
        .args(["config", "check", "--all", "--json"])
        .assert()
        .code(66)
        .get_output()
        .clone();
    let denied_all = parse_json(&denied_all.stderr);
    assert_eq!(denied_all["code"], "project-provider-selection-not-allowed");

    fixture
        .command()
        .args(["--profile", "review", "config", "check", "--json"])
        .assert()
        .success();
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
fn every_trusted_profile_reference_must_resolve_even_when_unselected() {
    let fixture = ConfigFixture::new(
        r#"
[profiles.active]

[profiles.dangling]
trusted_profile = "missing"
"#,
        "",
    );

    let output = fixture
        .command()
        .args(["--profile", "active", "config", "check", "--json"])
        .assert()
        .code(66)
        .get_output()
        .clone();
    let error = parse_json(&output.stderr);
    assert_eq!(error["code"], "configuration-error");
    assert!(
        error["message"]
            .as_str()
            .is_some_and(|message| message.contains("references missing trusted profile 'missing'"))
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
