use std::fs;
use std::path::{Path, PathBuf};

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("satelle-test-contract should live two levels below the repo root")
        .to_path_buf()
}

fn read_repo(path: &str) -> String {
    fs::read_to_string(repo_root().join(path))
        .unwrap_or_else(|error| panic!("read {path}: {error}"))
}

fn assert_contains(path: &str, needle: &str) {
    let source = read_repo(path);
    assert!(
        source.contains(needle),
        "{path} should contain architectural marker {needle:?}"
    );
}

fn tag_value_is_ci(tag: &str) -> bool {
    tag.trim().trim_matches(['"', '\'']) == "ci"
}

fn block_has_ci_tag(block: &str) -> bool {
    block.contains("@ci")
        || block.lines().any(|entry| {
            entry
                .trim_start()
                .strip_prefix("tags:")
                .is_some_and(|tags| {
                    tags.trim()
                        .trim_start_matches('[')
                        .trim_end_matches(']')
                        .split(',')
                        .any(tag_value_is_ci)
                })
        })
}

#[test]
fn workspace_crates_match_the_frozen_pr02_ownership_boundaries() {
    let cargo = read_repo("Cargo.toml");
    for member in [
        "\"crates/satelle-cli\"",
        "\"crates/satelle-core\"",
        "\"crates/satelle-host\"",
        "\"crates/satelle-test-contract\"",
        "\"crates/satelle-transport\"",
    ] {
        assert!(cargo.contains(member), "workspace missing {member}");
    }

    let crate_manifests = fs::read_dir(repo_root().join("crates"))
        .expect("read crates directory")
        .filter_map(Result::ok)
        .filter(|entry| entry.path().join("Cargo.toml").is_file())
        .map(|entry| entry.file_name().to_string_lossy().into_owned())
        .collect::<Vec<_>>();
    assert_eq!(
        crate_manifests.len(),
        5,
        "PR 02 should not introduce extra crates: {crate_manifests:?}"
    );
}

#[test]
fn command_entrypoints_delegate_to_separate_typed_boundaries() {
    for (path, marker) in [
        ("crates/satelle-cli/src/main.rs", "mod transport;"),
        ("crates/satelle-cli/src/main.rs", "mod error_output;"),
        ("crates/satelle-cli/src/main.rs", "HostService"),
        ("crates/satelle-cli/src/main.rs", "transport_for_setup"),
        (
            "crates/satelle-cli/src/transport.rs",
            "trait TransportClient",
        ),
        (
            "crates/satelle-transport/src/server/sessions.rs",
            "create_session",
        ),
        (
            "crates/satelle-host/src/runtime-codex.rs",
            "ControlPlaneAdmission",
        ),
        (
            "crates/satelle-host/src/codex_capabilities.rs",
            "RequiredCapability",
        ),
        ("crates/satelle-host/src/provider-probe.rs", "ProviderProbe"),
        ("crates/satelle-core/src/session.rs", "pub enum TurnState"),
    ] {
        assert_contains(path, marker);
    }
}

#[test]
fn mode_and_readiness_models_are_typed_not_stringly_nullable_flags() {
    for (path, marker) in [
        ("crates/satelle-core/src/lib.rs", "pub enum TransportKind"),
        (
            "crates/satelle-core/src/session.rs",
            "pub enum SessionActivity",
        ),
        (
            "crates/satelle-core/src/session.rs",
            "#[serde(deny_unknown_fields, tag = \"state\"",
        ),
        (
            "crates/satelle-core/src/lib.rs",
            "pub struct AdapterReadiness",
        ),
        (
            "crates/satelle-host/src/runtime-adapter.rs",
            "pub struct ProviderComputerUseIntent",
        ),
        (
            "crates/satelle-host/src/runtime-adapter.rs",
            "pub struct AdapterReadiness",
        ),
        (
            "crates/satelle-host/src/codex_capabilities.rs",
            "pub(crate) enum HostPlatform",
        ),
        (
            "crates/satelle-host/src/codex_capabilities.rs",
            "supports_native_computer_use",
        ),
    ] {
        assert_contains(path, marker);
    }
}

#[test]
fn public_persistence_and_upstream_data_boundaries_do_not_collapse() {
    let lib = read_repo("crates/satelle-core/src/lib.rs");
    assert!(lib.contains("mod authority;"));
    assert!(!lib.contains("pub mod authority;"));
    for private_type in [
        "SessionInternalMapping",
        "UpstreamThreadRef",
        "GoalMetadata",
        "GoalAttachment",
    ] {
        assert!(
            !lib.contains(private_type),
            "{private_type} must not be re-exported from satelle-core"
        );
    }

    for (path, marker) in [
        (
            "crates/satelle-core/src/session.rs",
            "pub struct SessionSnapshot",
        ),
        (
            "crates/satelle-core/src/session.rs",
            "pub struct PublicSession",
        ),
        (
            "crates/satelle-core/src/session-public.rs",
            "validate_session",
        ),
        (
            "crates/satelle-core/src/control-plane.rs",
            "Upstream method spellings never cross this",
        ),
        (
            "crates/satelle-host/src/storage/codec.rs",
            "SessionSnapshot",
        ),
        (
            "crates/satelle-host/src/runtime-codex.rs",
            "IncompatibleControlPlaneDetails",
        ),
    ] {
        assert_contains(path, marker);
    }
}

#[test]
fn diagnostics_use_tracing_without_corrupting_user_output_contracts() {
    for (path, marker) in [
        ("crates/satelle-cli/src/main.rs", "SATELLE_LOG"),
        ("crates/satelle-cli/src/main.rs", "with_writer(io::stderr)"),
        ("crates/satelle-host/src/daemon.rs", "tracing::info!"),
        (
            "crates/satelle-host/src/runtime-codex-adapter.rs",
            "tracing::",
        ),
        (
            "crates/satelle-transport/src/server/events.rs",
            "tracing::warn!",
        ),
        (
            "crates/satelle-transport/src/server/mod.rs",
            "tracing::debug!",
        ),
    ] {
        assert_contains(path, marker);
    }
}

#[test]
fn ci_fact_tags_require_an_executable_command_mapping() {
    let facts = read_repo(".facts");
    let mut current = Vec::new();
    let mut violations = Vec::new();

    for line in facts.lines().chain(std::iter::once("# end")) {
        let begins_fact = line.starts_with("- ") || line.starts_with("# ");
        if begins_fact && !current.is_empty() {
            let block = current.join("\n");
            let has_ci = block_has_ci_tag(&block);
            let has_command = block
                .lines()
                .any(|entry| entry.trim_start().starts_with("command:"));
            if has_ci && !has_command {
                violations.push(block.lines().next().unwrap_or_default().to_string());
            }
            current.clear();
        }
        if line.starts_with("- ") || !current.is_empty() {
            current.push(line.to_string());
        }
    }

    assert!(
        violations.is_empty(),
        "ci-tagged facts without commands: {violations:?}"
    );
}

#[test]
fn ci_fact_tag_parser_matches_only_exact_ci_tokens() {
    assert!(block_has_ci_tag("- inline fact @ci"));
    assert!(block_has_ci_tag(
        "- id: exact\n  label: exact structured tag\n  command: true\n  tags: [spec, ci, mvp]"
    ));

    for block in [
        "- label: decides quickly\n  tags: [spec, mvp]",
        "- label: docs mention ci but are manual\n  tags: [spec, verification]",
        "- label: command name has ci\n  command: echo city\n  tags: [spec, mvp]",
        "- label: structured substring\n  tags: [spec, clinic, mvp]",
    ] {
        assert!(!block_has_ci_tag(block), "false CI match for {block:?}");
    }
}
