use serde_json::Value;
use std::path::{Path, PathBuf};
use std::process::Command;

const SATELLE_ENVIRONMENT: &[&str] = &[
    "SATELLE_CONFIG_FILE",
    "SATELLE_STATE_DIR",
    "SATELLE_CACHE_DIR",
    "SATELLE_LOG_DIR",
    "SATELLE_HOST",
    "SATELLE_PROFILE",
    "SATELLE_TEST_SUPPORT_ADAPTER",
];

fn release_binary() -> PathBuf {
    if let Some(binary) = std::env::var_os("SATELLE_RELEASE_BINARY") {
        return PathBuf::from(binary);
    }

    let workspace_root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let cargo = std::env::var_os("CARGO").unwrap_or_else(|| "cargo".into());
    let metadata = Command::new(cargo)
        .current_dir(&workspace_root)
        .args([
            "metadata",
            "--format-version",
            "1",
            "--no-deps",
            "--locked",
            "--offline",
        ])
        .output()
        .expect("cargo metadata should locate the configured target directory");
    assert!(metadata.status.success());
    let metadata = serde_json::from_slice::<Value>(&metadata.stdout)
        .expect("cargo metadata should emit one JSON value");
    let target_dir = metadata["target_directory"]
        .as_str()
        .map(PathBuf::from)
        .expect("cargo metadata should report target_directory");
    let executable = format!("satelle{}", std::env::consts::EXE_SUFFIX);
    target_dir.join("release").join(executable)
}

fn release_command(binary: &Path, home: &Path) -> Command {
    let mut command = Command::new(binary);
    for name in SATELLE_ENVIRONMENT {
        command.env_remove(name);
    }
    command.env("SATELLE_HOME", home);
    command
}

#[test]
#[ignore = "requires cargo build --workspace --release --locked first"]
fn release_binary_satisfies_offline_contract() {
    let binary = release_binary();
    assert!(
        binary.is_file(),
        "release binary should exist at {}",
        binary.display()
    );
    let temp = tempfile::tempdir().expect("temporary release-smoke directory should be created");
    let home = temp.path().join("satelle-home");

    let version = release_command(&binary, &home)
        .arg("--version")
        .output()
        .expect("release binary should report its version");
    assert!(version.status.success());
    assert_eq!(
        version.stdout,
        format!("satelle {}\n", env!("CARGO_PKG_VERSION")).as_bytes()
    );
    assert!(version.stderr.is_empty());
    assert!(!home.exists());

    let paths = release_command(&binary, &home)
        .args(["paths", "--json"])
        .output()
        .expect("release binary should report its offline paths contract");
    assert!(paths.status.success());
    assert!(paths.stderr.is_empty());
    assert!(paths.stdout.ends_with(b"\n"));
    let report = serde_json::from_slice::<Value>(&paths.stdout)
        .expect("release paths output should be one JSON value");
    assert_eq!(report["schema_version"], "satelle.paths.v1");
    assert!(!home.exists());
}
