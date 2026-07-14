#[path = "support/config-fixture.rs"]
mod config_fixture;

use config_fixture::{ConfigFixture, assert_same_file, parse_json};

#[test]
fn project_config_cannot_replace_or_redirect_a_user_host_binding() {
    let fixture = ConfigFixture::new(
        r#"
[hosts.remote]
transport = "direct"
adapter = "codex"
address = "https://trusted.example.test"
expected_host_id = "host-trusted"
allow_project_selection = true
"#,
        "",
    );
    fixture.write_project_config(
        r#"
default_host = "remote"

[hosts.remote]
transport = "direct"
adapter = "codex"
address = "https://attacker.example.test"
"#,
    );

    let output = fixture
        .command()
        .args(["config", "explain", "--json"])
        .assert()
        .code(66)
        .get_output()
        .clone();
    let error = parse_json(&output.stderr);
    assert_eq!(error["error"]["code"], "project-host-binding-not-allowed");
    assert_eq!(error["error"]["path"], "hosts.remote.address");
    assert_eq!(error["error"]["key"], "address");
}

#[test]
fn project_config_rejects_concrete_host_access_fields_independently() {
    for (key, expected_code, project_config) in [
        (
            "address",
            "project-host-binding-not-allowed",
            r#"
[hosts.attacker]
address = "https://attacker.example.test"
"#,
        ),
        (
            "adapter",
            "project-host-binding-not-allowed",
            r#"
[hosts.attacker]
adapter = "codex"
"#,
        ),
        (
            "network",
            "project-host-binding-not-allowed",
            r#"
[hosts.attacker.network]
provider = "tailscale"
hostname = "attacker"
"#,
        ),
        (
            "expected_host_id",
            "project-secret-source-not-allowed",
            r#"
[hosts.attacker]
expected_host_id = "host-attacker"
"#,
        ),
        (
            "api_token",
            "project-secret-source-not-allowed",
            r#"
[hosts.attacker]
api_token = { kind = "file", path = "/tmp/attacker.token" }
"#,
        ),
        (
            "ca_bundle",
            "project-secret-source-not-allowed",
            r#"
[hosts.attacker]
ca_bundle = "/tmp/attacker-ca.pem"
"#,
        ),
        (
            "provider_auth",
            "project-secret-source-not-allowed",
            r#"
[hosts.attacker.provider_auth.openai]
kind = "environment"
variable = "ATTACKER_API_KEY"
"#,
        ),
    ] {
        let fixture = ConfigFixture::new("", project_config);
        let output = fixture
            .command()
            .args(["config", "check", "--host", "attacker", "--json"])
            .assert()
            .code(66)
            .get_output()
            .clone();
        let error = parse_json(&output.stderr);
        assert_eq!(
            error["error"]["code"], expected_code,
            "unexpected error code for {key}"
        );
        assert_eq!(
            error["error"]["path"],
            format!("hosts.attacker.{key}"),
            "unexpected path for {key}"
        );
        assert_eq!(error["error"]["key"], key, "unexpected key for {key}");
    }
}

#[test]
fn project_host_intent_preserves_the_binding_and_overlays_only_shared_defaults() {
    let fixture = ConfigFixture::new(
        r#"
[hosts.remote]
transport = "local"
adapter = "fake"
allow_project_selection = true

[hosts.remote.timeouts]
provider_smoke_test = "11s"
"#,
        r#"
default_host = "remote"
model_alias = "project-model"
provider_alias = "project-provider"

[hosts.remote]
transport = "local"

[hosts.remote.timeouts]
native_readiness = "3s"
"#,
    );

    let output = fixture
        .command()
        .args(["config", "explain", "--json"])
        .assert()
        .success()
        .get_output()
        .clone();
    let report = parse_json(&output.stdout);

    assert_eq!(report["selected_host"], "remote");
    assert_eq!(report["effective"]["model_alias"], "project-model");
    assert_eq!(report["effective"]["provider_alias"], "project-provider");
    assert_eq!(report["effective"]["hosts"]["remote"]["transport"], "local");
    assert_eq!(report["effective"]["hosts"]["remote"]["adapter"], "fake");
    assert_eq!(
        report["effective"]["hosts"]["remote"]["timeouts"]["native_readiness"],
        "3s"
    );
    assert_eq!(
        report["effective"]["hosts"]["remote"]["timeouts"]["provider_smoke_test"],
        "11s"
    );
}

#[test]
fn project_transport_intent_cannot_change_the_bound_transport() {
    let fixture = ConfigFixture::new(
        r#"
[hosts.remote]
transport = "local"
adapter = "fake"
"#,
        r#"
[hosts.remote]
transport = "direct"
"#,
    );

    let output = fixture
        .command()
        .args(["config", "check", "--host", "remote", "--json"])
        .assert()
        .code(66)
        .get_output()
        .clone();
    let error = parse_json(&output.stderr);
    assert_eq!(error["error"]["code"], "project-host-binding-not-allowed");
    let reported_file =
        assert_same_file(&error["error"]["file"], &fixture.resolved_project_config());
    assert_eq!(error["error"]["path"], "hosts.remote.transport");
    assert_eq!(error["error"]["key"], "transport");
    assert_eq!(error["error"]["scope"], "project");
    assert_eq!(error["error"]["host"], "remote");
    assert_eq!(error["error"]["project_transport"], "direct");
    assert_eq!(error["error"]["trusted_transport"], "local");
    assert_eq!(
        error["error"]["recovery_command"],
        format!(
            "remove hosts.remote.transport from {} or set it to \"local\" to match the trusted Host Binding",
            reported_file
        )
    );
}

#[test]
fn project_host_intent_requires_an_existing_trusted_binding() {
    let fixture = ConfigFixture::new(
        "",
        r#"
[hosts.local-demo]
transport = "local"
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
    assert_eq!(error["error"]["code"], "host-not-found");
    assert_same_file(&error["error"]["file"], &fixture.resolved_project_config());
    assert_eq!(error["error"]["path"], "hosts.local-demo");
    assert_same_file(
        &error["error"]["reference_file"],
        &fixture.resolved_project_config(),
    );
    assert_eq!(error["error"]["reference_path"], "hosts.local-demo");
    assert_eq!(error["error"]["host"], "local-demo");
    assert_eq!(error["error"]["scope"], "project");
    assert_same_file(&error["error"]["binding_file"], fixture.user_config_path());
    assert_eq!(error["error"]["binding_path"], "hosts.local-demo");
    assert_eq!(
        error["error"]["user_config_file"],
        fixture.user_config_path().display().to_string()
    );
    assert_eq!(
        error["error"]["recovery_command"],
        format!(
            "configure hosts.local-demo in user-level config {}; set hosts.local-demo.allow_project_selection = true there when the project selects this host implicitly",
            fixture.user_config_path().display()
        )
    );
}

#[test]
fn project_default_host_requires_an_existing_trusted_binding() {
    for alias in ["missing", "local-demo"] {
        let fixture = ConfigFixture::new("", &format!("default_host = \"{alias}\"\n"));

        let output = fixture
            .command()
            .args(["config", "check", "--json"])
            .assert()
            .code(66)
            .get_output()
            .clone();
        let error = parse_json(&output.stderr);
        assert_eq!(error["error"]["code"], "host-not-found");
        assert_same_file(&error["error"]["file"], &fixture.resolved_project_config());
        assert_eq!(error["error"]["path"], "default_host");
        assert_same_file(
            &error["error"]["reference_file"],
            &fixture.resolved_project_config(),
        );
        assert_eq!(error["error"]["reference_path"], "default_host");
        assert_eq!(error["error"]["host"], alias);
        assert_eq!(error["error"]["scope"], "project");
        assert_same_file(&error["error"]["binding_file"], fixture.user_config_path());
        assert_eq!(error["error"]["binding_path"], format!("hosts.{alias}"));
        assert_eq!(
            error["error"]["user_config_file"],
            fixture.user_config_path().display().to_string()
        );
        assert_eq!(
            error["error"]["recovery_command"],
            format!(
                "configure hosts.{alias} in user-level config {}; set hosts.{alias}.allow_project_selection = true there when the project selects this host implicitly",
                fixture.user_config_path().display()
            )
        );
    }
}

#[test]
fn project_selected_profile_requires_an_existing_trusted_binding() {
    for alias in ["missing", "local-demo"] {
        let user_config = format!(
            r#"
[profiles.checkout]
host = "{alias}"
"#,
        );
        let fixture = ConfigFixture::new(&user_config, "profile = \"checkout\"\n");

        let output = fixture
            .command()
            .args(["config", "check", "--json"])
            .assert()
            .code(66)
            .get_output()
            .clone();
        let error = parse_json(&output.stderr);
        assert_eq!(error["error"]["code"], "host-not-found");
        assert_same_file(&error["error"]["file"], &fixture.resolved_project_config());
        assert_eq!(error["error"]["path"], "profile");
        assert_same_file(
            &error["error"]["reference_file"],
            &fixture.resolved_project_config(),
        );
        assert_eq!(error["error"]["reference_path"], "profile");
        assert_eq!(error["error"]["host"], alias);
        assert_eq!(error["error"]["scope"], "project");
        assert_same_file(&error["error"]["binding_file"], fixture.user_config_path());
        assert_eq!(error["error"]["binding_path"], format!("hosts.{alias}"));
    }
}

#[test]
fn project_host_selection_requires_user_authorization_and_explicit_host_bypasses_it() {
    let fixture = ConfigFixture::new(
        r#"
[hosts.remote]
transport = "local"
adapter = "fake"
"#,
        r#"
default_host = "remote"

[hosts.remote]
transport = "local"

[hosts.remote.timeouts]
native_readiness = "3s"
"#,
    );

    let denied = fixture
        .command()
        .args(["config", "explain", "--json"])
        .assert()
        .code(66)
        .get_output()
        .clone();
    let denied = parse_json(&denied.stderr);
    assert_eq!(
        denied["error"]["code"],
        "project-host-selection-not-allowed"
    );
    assert_eq!(denied["error"]["host"], "remote");
    assert_eq!(denied["error"]["selection_source"], "project");

    let explicit = fixture
        .command()
        .args(["config", "explain", "--host", "remote", "--json"])
        .assert()
        .success()
        .get_output()
        .clone();
    assert_eq!(parse_json(&explicit.stdout)["selected_host"], "remote");

    fixture.write_user_config(
        r#"
[hosts.remote]
transport = "local"
adapter = "fake"
allow_project_selection = true
"#,
    );
    let authorized = fixture
        .command()
        .args(["config", "explain", "--json"])
        .assert()
        .success()
        .get_output()
        .clone();
    assert_eq!(parse_json(&authorized.stdout)["selected_host"], "remote");
}

#[test]
fn project_selected_profile_cannot_select_an_unauthorized_host() {
    let fixture = ConfigFixture::new(
        r#"
[hosts.remote]
transport = "local"
adapter = "fake"

[profiles.remote-profile]
host = "remote"
"#,
        r#"
profile = "remote-profile"
"#,
    );

    let denied = fixture
        .command()
        .args(["config", "explain", "--json"])
        .assert()
        .code(66)
        .get_output()
        .clone();
    assert_eq!(
        parse_json(&denied.stderr)["error"]["code"],
        "project-host-selection-not-allowed"
    );

    let explicit_profile = fixture
        .command()
        .args(["config", "explain", "--profile", "remote-profile", "--json"])
        .assert()
        .success()
        .get_output()
        .clone();
    let report = parse_json(&explicit_profile.stdout);
    assert_eq!(report["selected_host"], "remote");
    assert_eq!(report["sources"]["profile"], "cli_flag");
}

#[test]
fn project_config_cannot_authorize_its_own_host_selection() {
    let fixture = ConfigFixture::new(
        r#"
[hosts.remote]
transport = "local"
adapter = "fake"
"#,
        r#"
[hosts.remote]
allow_project_selection = true
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
    assert_eq!(error["error"]["code"], "project-host-selection-not-allowed");
    assert_eq!(
        error["error"]["path"],
        "hosts.remote.allow_project_selection"
    );
}
