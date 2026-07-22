use satelle_core::{
    ErrorCode, SatelleError, SatellePathSet, read_owner_only_secret_config_file, resolve_path_set,
};
use serde::Deserialize;
use serde_json::json;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::fs::{self, File};
use std::io::Read;
use std::path::{Component, Path, PathBuf};
use std::process::Command;
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

const RECEIPT_FILE_NAME: &str = "codex-install-receipt.json";
const RECEIPT_SCHEMA: &str = "satelle.codex-install-receipt.v1";
const RECEIPT_MANAGER: &str = "satelle";
const CODEX_VERSION: &str = "0.144.0";
const CODEX_RELEASE_TAG: &str = "rust-v0.144.0";
const SUPPORTED_TARGETS: [&str; 4] = [
    "aarch64-apple-darwin",
    "x86_64-apple-darwin",
    "aarch64-pc-windows-msvc",
    "x86_64-pc-windows-msvc",
];

fn official_artifact_sha256(target: &str) -> Option<&'static str> {
    match target {
        "aarch64-apple-darwin" => {
            Some("4584a243ff8a671250bc716f89c5a50ed59917a98390acfdffa3ecb6cfe5bb34")
        }
        "x86_64-apple-darwin" => {
            Some("1056c80958863b13debd5daee5eb7b9bd6f86236a1171d21b009e2dceea8763e")
        }
        "aarch64-pc-windows-msvc" => {
            Some("a83d449d0a277af4ce1cf5fbb29376db707538266b993eab2560e3eaa42509eb")
        }
        "x86_64-pc-windows-msvc" => {
            Some("4046964ac24104bb79217077a86c96b20edae5a5f548a71442a164d3f9598a35")
        }
        _ => None,
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ManagedCodexReceipt {
    schema: String,
    manager: String,
    version: String,
    target: String,
    release_tag: String,
    artifact_url: String,
    artifact_sha256: String,
    codex_home: PathBuf,
    immutable_package_root: PathBuf,
    immutable_binary_path: PathBuf,
    immutable_binary_sha256: String,
    installed_at: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct VerifiedCodexRuntime {
    binary_path: PathBuf,
    codex_home: PathBuf,
    package_root: PathBuf,
    binary_sha256: String,
}

impl VerifiedCodexRuntime {
    #[cfg(test)]
    pub(crate) fn binary_path(&self) -> &Path {
        &self.binary_path
    }

    #[cfg(test)]
    pub(crate) fn codex_home(&self) -> &Path {
        &self.codex_home
    }

    pub(crate) fn command(&self) -> Result<Command, SatelleError> {
        verify_runtime_identity(
            &self.codex_home,
            &self.package_root,
            &self.binary_path,
            &self.binary_sha256,
        )?;
        let mut command = Command::new(&self.binary_path);
        command.env("CODEX_HOME", &self.codex_home);
        Ok(command)
    }
}

pub(crate) fn admit_managed_codex(
    paths: &SatellePathSet,
) -> Result<VerifiedCodexRuntime, SatelleError> {
    admit_managed_codex_from_state_root_for_target(&paths.state_root, current_target()?)
}

pub(crate) fn admit_managed_codex_for_current_process() -> Result<VerifiedCodexRuntime, SatelleError>
{
    let current_directory =
        std::env::current_dir().map_err(|_| invalid_receipt("current_directory_unavailable"))?;
    let paths = resolve_path_set(&current_directory)?;
    admit_managed_codex(&paths)
}

fn admit_managed_codex_from_state_root_for_target(
    state_root: &Path,
    expected_target: &str,
) -> Result<VerifiedCodexRuntime, SatelleError> {
    let receipt_path = state_root.join(RECEIPT_FILE_NAME);
    let receipt_text = read_owner_only_secret_config_file(&receipt_path)
        .map_err(|_| invalid_receipt("receipt_missing_or_not_owner_only"))?;
    let receipt: ManagedCodexReceipt = serde_json::from_str(receipt_text.as_str())
        .map_err(|_| invalid_receipt("receipt_schema_invalid"))?;

    validate_receipt_metadata(&receipt, expected_target)?;
    let codex_home = canonical_directory(&receipt.codex_home, "codex_home_invalid")?;
    let releases_root = canonical_directory(
        &codex_home
            .join("packages")
            .join("standalone")
            .join("releases"),
        "releases_root_invalid",
    )?;
    let package_root = canonical_directory(
        &receipt.immutable_package_root,
        "immutable_package_root_invalid",
    )?;
    let expected_package_root =
        releases_root.join(format!("{}-{}", receipt.version, receipt.target));
    if !same_path_identity(&package_root, &receipt.immutable_package_root)
        || !same_path_identity(&package_root, &expected_package_root)
        || has_mutable_component(&package_root)
    {
        return Err(invalid_receipt("immutable_package_root_invalid"));
    }

    let expected_binary_path = package_root
        .join("bin")
        .join(binary_name_for_target(&receipt.target));
    if !same_path_identity(&receipt.immutable_binary_path, &expected_binary_path) {
        return Err(invalid_receipt("immutable_binary_path_invalid"));
    }
    let binary_path = verify_binary_identity(
        &receipt.immutable_binary_path,
        &package_root,
        &receipt.immutable_binary_sha256,
    )?;

    Ok(VerifiedCodexRuntime {
        binary_path,
        codex_home,
        package_root,
        binary_sha256: receipt.immutable_binary_sha256,
    })
}

fn validate_receipt_metadata(
    receipt: &ManagedCodexReceipt,
    expected_target: &str,
) -> Result<(), SatelleError> {
    if receipt.schema != RECEIPT_SCHEMA
        || receipt.manager != RECEIPT_MANAGER
        || receipt.version != CODEX_VERSION
        || receipt.release_tag != CODEX_RELEASE_TAG
        || receipt.target != expected_target
        || !SUPPORTED_TARGETS.contains(&receipt.target.as_str())
        || !is_sha256(&receipt.immutable_binary_sha256)
        || OffsetDateTime::parse(&receipt.installed_at, &Rfc3339).is_err()
    {
        return Err(invalid_receipt("receipt_metadata_invalid"));
    }
    let expected_url = format!(
        "https://github.com/openai/codex/releases/download/{CODEX_RELEASE_TAG}/codex-package-{}.tar.gz",
        receipt.target
    );
    if receipt.artifact_url != expected_url {
        return Err(invalid_receipt("artifact_url_invalid"));
    }
    if official_artifact_sha256(&receipt.target) != Some(receipt.artifact_sha256.as_str()) {
        return Err(invalid_receipt("artifact_digest_invalid"));
    }
    Ok(())
}

fn canonical_directory(path: &Path, reason: &'static str) -> Result<PathBuf, SatelleError> {
    if !path.is_absolute() {
        return Err(invalid_receipt(reason));
    }
    let canonical = fs::canonicalize(path).map_err(|_| invalid_receipt(reason))?;
    if !same_path_identity(&canonical, path)
        || !fs::metadata(&canonical).is_ok_and(|metadata| metadata.is_dir())
    {
        return Err(invalid_receipt(reason));
    }
    Ok(canonical)
}

fn verify_binary_identity(
    receipt_path: &Path,
    package_root: &Path,
    expected_sha256: &str,
) -> Result<PathBuf, SatelleError> {
    let binary_path =
        fs::canonicalize(receipt_path).map_err(|_| invalid_receipt("immutable_binary_missing"))?;
    let binary_metadata =
        fs::metadata(&binary_path).map_err(|_| invalid_receipt("immutable_binary_missing"))?;
    if !same_path_identity(&binary_path, receipt_path)
        || !binary_metadata.is_file()
        || !binary_path.starts_with(package_root)
        || has_mutable_component(&binary_path)
    {
        return Err(invalid_receipt("immutable_binary_path_invalid"));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if binary_metadata.permissions().mode() & 0o111 == 0 {
            return Err(invalid_receipt("immutable_binary_not_executable"));
        }
    }
    #[cfg(windows)]
    if binary_path
        .extension()
        .is_none_or(|extension| !extension.eq_ignore_ascii_case("exe"))
    {
        return Err(invalid_receipt("immutable_binary_not_executable"));
    }
    let binary_digest =
        sha256_file(&binary_path).map_err(|_| invalid_receipt("immutable_binary_unreadable"))?;
    if !binary_digest.eq_ignore_ascii_case(expected_sha256) {
        return Err(invalid_receipt("immutable_binary_digest_mismatch"));
    }
    Ok(binary_path)
}

fn verify_runtime_identity(
    codex_home: &Path,
    package_root: &Path,
    binary_path: &Path,
    expected_sha256: &str,
) -> Result<(), SatelleError> {
    canonical_directory(codex_home, "codex_home_invalid")?;
    canonical_directory(package_root, "immutable_package_root_invalid")?;
    verify_binary_identity(binary_path, package_root, expected_sha256)?;
    Ok(())
}

fn binary_name_for_target(target: &str) -> &'static str {
    if target.ends_with("-pc-windows-msvc") {
        "codex.exe"
    } else {
        "codex"
    }
}

#[cfg(windows)]
fn same_path_identity(left: &Path, right: &Path) -> bool {
    normalize_windows_path(&left.to_string_lossy())
        .eq_ignore_ascii_case(&normalize_windows_path(&right.to_string_lossy()))
}

#[cfg(not(windows))]
fn same_path_identity(left: &Path, right: &Path) -> bool {
    left == right
}

#[cfg(any(windows, test))]
fn normalize_windows_path(value: &str) -> String {
    let normalized = value.replace('/', "\\");
    normalized
        .strip_prefix(r"\\?\UNC\")
        .map(|path| format!(r"\\{path}"))
        .or_else(|| normalized.strip_prefix(r"\\?\").map(str::to_string))
        .unwrap_or(normalized)
        .trim_end_matches('\\')
        .to_string()
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
fn current_target() -> Result<&'static str, SatelleError> {
    Ok("aarch64-apple-darwin")
}

#[cfg(all(target_os = "macos", target_arch = "x86_64"))]
fn current_target() -> Result<&'static str, SatelleError> {
    Ok("x86_64-apple-darwin")
}

#[cfg(all(target_os = "windows", target_arch = "aarch64"))]
fn current_target() -> Result<&'static str, SatelleError> {
    Ok("aarch64-pc-windows-msvc")
}

#[cfg(all(target_os = "windows", target_arch = "x86_64"))]
fn current_target() -> Result<&'static str, SatelleError> {
    Ok("x86_64-pc-windows-msvc")
}

#[cfg(not(any(
    all(target_os = "macos", target_arch = "aarch64"),
    all(target_os = "macos", target_arch = "x86_64"),
    all(target_os = "windows", target_arch = "aarch64"),
    all(target_os = "windows", target_arch = "x86_64")
)))]
fn current_target() -> Result<&'static str, SatelleError> {
    Err(invalid_receipt("unsupported_host_target"))
}

fn has_mutable_component(path: &Path) -> bool {
    path.components().any(|component| {
        matches!(component, Component::Normal(value) if value.eq_ignore_ascii_case("current"))
    })
}

fn is_sha256(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn sha256_file(path: &Path) -> std::io::Result<String> {
    let mut file = File::open(path)?;
    let mut digest = Sha256::new();
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let count = file.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        digest.update(&buffer[..count]);
    }
    Ok(digest
        .finalize()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect())
}

fn invalid_receipt(reason: &'static str) -> SatelleError {
    SatelleError {
        code: ErrorCode::StorageIntegrityFailed,
        message: "the managed Codex installation receipt is missing, unsafe, or inconsistent"
            .to_string(),
        recovery_command: None,
        source_detail: None,
        details: BTreeMap::from([("reason".to_string(), json!(reason))]),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use satelle_core::open_or_create_owner_only_file;
    use serde_json::{Map, Value};
    use std::io::Write;
    use tempfile::TempDir;

    #[cfg(windows)]
    const BINARY_NAME: &str = "codex.exe";
    #[cfg(not(windows))]
    const BINARY_NAME: &str = "codex";

    #[cfg(windows)]
    const FIXTURE_TARGET: &str = "x86_64-pc-windows-msvc";
    #[cfg(not(windows))]
    const FIXTURE_TARGET: &str = "x86_64-apple-darwin";

    #[cfg(windows)]
    const FIXTURE_OTHER_TARGET: &str = "aarch64-pc-windows-msvc";
    #[cfg(not(windows))]
    const FIXTURE_OTHER_TARGET: &str = "aarch64-apple-darwin";

    #[cfg(windows)]
    const FIXTURE_ARTIFACT_SHA256: &str =
        "4046964ac24104bb79217077a86c96b20edae5a5f548a71442a164d3f9598a35";
    #[cfg(not(windows))]
    const FIXTURE_ARTIFACT_SHA256: &str =
        "1056c80958863b13debd5daee5eb7b9bd6f86236a1171d21b009e2dceea8763e";

    struct ReceiptFixture {
        _root: TempDir,
        state_root: PathBuf,
        codex_home: PathBuf,
        package_root: PathBuf,
        binary_path: PathBuf,
        receipt_path: PathBuf,
        receipt: Value,
    }

    impl ReceiptFixture {
        fn new() -> Self {
            let root = tempfile::tempdir().expect("temporary receipt root");
            let canonical_root =
                fs::canonicalize(root.path()).expect("canonical temporary receipt root");
            let state_root = canonical_root.join("state");
            let codex_home = canonical_root.join("codex-home");
            let package_root = codex_home
                .join("packages")
                .join("standalone")
                .join("releases")
                .join(format!("{CODEX_VERSION}-{FIXTURE_TARGET}"));
            let binary_path = package_root.join("bin").join(BINARY_NAME);
            fs::create_dir_all(binary_path.parent().expect("binary parent"))
                .expect("create package");
            fs::create_dir_all(&state_root).expect("create state root");
            fs::write(&binary_path, b"verified standalone codex binary").expect("write binary");
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                fs::set_permissions(&binary_path, fs::Permissions::from_mode(0o700))
                    .expect("make binary executable");
            }
            let binary_sha256 = sha256_file(&binary_path).expect("binary digest");
            let receipt = json!({
                "schema": RECEIPT_SCHEMA,
                "manager": RECEIPT_MANAGER,
                "version": CODEX_VERSION,
                "target": FIXTURE_TARGET,
                "release_tag": CODEX_RELEASE_TAG,
                "artifact_url": format!(
                    "https://github.com/openai/codex/releases/download/{CODEX_RELEASE_TAG}/codex-package-{FIXTURE_TARGET}.tar.gz"
                ),
                "artifact_sha256": FIXTURE_ARTIFACT_SHA256,
                "codex_home": codex_home,
                "immutable_package_root": package_root,
                "immutable_binary_path": binary_path,
                "immutable_binary_sha256": binary_sha256,
                "installed_at": "2026-07-22T00:00:00Z",
            });
            let receipt_path = state_root.join(RECEIPT_FILE_NAME);
            let mut fixture = Self {
                _root: root,
                state_root,
                codex_home,
                package_root,
                binary_path,
                receipt_path,
                receipt,
            };
            fixture.write_receipt();
            fixture
        }

        fn receipt_object_mut(&mut self) -> &mut Map<String, Value> {
            self.receipt.as_object_mut().expect("receipt object")
        }

        fn write_receipt(&mut self) {
            let bytes = serde_json::to_vec_pretty(&self.receipt).expect("serialize receipt");
            let mut file = open_or_create_owner_only_file(&self.receipt_path)
                .expect("open owner-only receipt");
            file.set_len(0).expect("truncate receipt");
            file.write_all(&bytes).expect("write receipt");
        }
    }

    #[test]
    fn verified_receipt_returns_exact_immutable_binary_and_codex_home() {
        let fixture = ReceiptFixture::new();
        let runtime =
            admit_managed_codex_from_state_root_for_target(&fixture.state_root, FIXTURE_TARGET)
                .expect("admit managed Codex");
        assert_eq!(runtime.binary_path(), fixture.binary_path);
        assert_eq!(runtime.codex_home(), fixture.codex_home);
        let command = runtime.command().expect("verified command");
        assert_eq!(command.get_program(), fixture.binary_path);
        assert!(command.get_envs().any(|(key, value)| {
            key == "CODEX_HOME" && value == Some(fixture.codex_home.as_os_str())
        }));
    }

    #[test]
    fn receipt_admission_rejects_missing_or_non_owner_only_receipt() {
        let mut fixture = ReceiptFixture::new();
        fs::remove_file(&fixture.receipt_path).expect("remove receipt");
        assert!(
            admit_managed_codex_from_state_root_for_target(&fixture.state_root, FIXTURE_TARGET)
                .is_err()
        );
        fixture.write_receipt();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&fixture.receipt_path, fs::Permissions::from_mode(0o644))
                .expect("make receipt unsafe");
            assert!(
                admit_managed_codex_from_state_root_for_target(&fixture.state_root, FIXTURE_TARGET)
                    .is_err()
            );
        }
    }

    #[test]
    fn receipt_admission_rejects_wrong_schema_manager_version_target_or_release() {
        for field in ["schema", "manager", "version", "target", "release_tag"] {
            let mut fixture = ReceiptFixture::new();
            fixture
                .receipt_object_mut()
                .insert(field.to_string(), json!("wrong"));
            fixture.write_receipt();
            assert!(
                admit_managed_codex_from_state_root_for_target(&fixture.state_root, FIXTURE_TARGET)
                    .is_err(),
                "accepted wrong {field}"
            );
        }
    }

    #[cfg(unix)]
    #[test]
    fn receipt_admission_rejects_mutable_package_or_binary_paths() {
        use std::os::unix::fs::symlink;

        let mut fixture = ReceiptFixture::new();
        let current = fixture
            .codex_home
            .join("packages")
            .join("standalone")
            .join("current");
        symlink(&fixture.package_root, &current).expect("create mutable alias");
        fixture
            .receipt_object_mut()
            .insert("immutable_package_root".to_string(), json!(current));
        fixture.write_receipt();
        assert!(
            admit_managed_codex_from_state_root_for_target(&fixture.state_root, FIXTURE_TARGET)
                .is_err()
        );
    }

    #[test]
    fn receipt_admission_rejects_binary_digest_drift() {
        let fixture = ReceiptFixture::new();
        fs::write(&fixture.binary_path, b"drifted binary").expect("replace binary bytes");
        assert!(
            admit_managed_codex_from_state_root_for_target(&fixture.state_root, FIXTURE_TARGET)
                .is_err()
        );
    }

    #[test]
    fn admitted_runtime_rechecks_binary_before_every_child_command() {
        let fixture = ReceiptFixture::new();
        let runtime =
            admit_managed_codex_from_state_root_for_target(&fixture.state_root, FIXTURE_TARGET)
                .expect("admit managed Codex");

        fs::write(&fixture.binary_path, b"mutated after admission")
            .expect("mutate admitted binary");
        let error = runtime
            .command()
            .expect_err("mutated binary must never produce a spawnable command");

        assert_eq!(error.code, ErrorCode::StorageIntegrityFailed);
        assert_eq!(
            error.details["reason"],
            json!("immutable_binary_digest_mismatch")
        );
    }

    #[test]
    fn receipt_admission_requires_exact_versioned_package_and_binary_locations() {
        let mut wrong_package = ReceiptFixture::new();
        let alias_root = wrong_package
            .codex_home
            .join("packages")
            .join("standalone")
            .join("releases")
            .join("another-package");
        let alias_binary = alias_root.join("bin").join(BINARY_NAME);
        fs::create_dir_all(alias_binary.parent().expect("alias binary parent"))
            .expect("create alias package");
        fs::copy(&wrong_package.binary_path, &alias_binary).expect("copy alias binary");
        wrong_package
            .receipt_object_mut()
            .insert("immutable_package_root".to_string(), json!(alias_root));
        wrong_package
            .receipt_object_mut()
            .insert("immutable_binary_path".to_string(), json!(alias_binary));
        wrong_package.write_receipt();
        let package_error = admit_managed_codex_from_state_root_for_target(
            &wrong_package.state_root,
            FIXTURE_TARGET,
        )
        .expect_err("a receipt cannot relabel an arbitrary package as version 0.144.0");
        assert_eq!(
            package_error.details["reason"],
            json!("immutable_package_root_invalid")
        );

        let mut wrong_binary = ReceiptFixture::new();
        let alternate_binary = wrong_binary.package_root.join("bin").join("codex-copy");
        fs::copy(&wrong_binary.binary_path, &alternate_binary).expect("copy alternate binary");
        wrong_binary
            .receipt_object_mut()
            .insert("immutable_binary_path".to_string(), json!(alternate_binary));
        wrong_binary.write_receipt();
        let binary_error = admit_managed_codex_from_state_root_for_target(
            &wrong_binary.state_root,
            FIXTURE_TARGET,
        )
        .expect_err("a receipt cannot select a second executable from the package");
        assert_eq!(
            binary_error.details["reason"],
            json!("immutable_binary_path_invalid")
        );
    }

    #[test]
    fn receipt_admission_ignores_path_npm_shims_and_mutable_aliases() {
        let fixture = ReceiptFixture::new();
        let npm_shim = fixture.state_root.join("node_modules").join(".bin");
        fs::create_dir_all(&npm_shim).expect("create npm shim directory");
        fs::write(npm_shim.join(BINARY_NAME), b"npm shim").expect("write npm shim");
        let runtime =
            admit_managed_codex_from_state_root_for_target(&fixture.state_root, FIXTURE_TARGET)
                .expect("receipt identity wins");
        assert_eq!(runtime.binary_path(), fixture.binary_path);
    }

    #[test]
    fn receipt_admission_requires_the_current_target_and_official_artifact_digest() {
        let mut fixture = ReceiptFixture::new();
        assert!(
            admit_managed_codex_from_state_root_for_target(
                &fixture.state_root,
                FIXTURE_OTHER_TARGET
            )
            .is_err()
        );

        fixture
            .receipt_object_mut()
            .insert("artifact_sha256".to_string(), json!("11".repeat(32)));
        fixture.write_receipt();
        assert!(
            admit_managed_codex_from_state_root_for_target(&fixture.state_root, FIXTURE_TARGET)
                .is_err()
        );
    }

    #[test]
    fn windows_path_identity_accepts_verbatim_prefixes_but_not_aliases() {
        assert_eq!(
            normalize_windows_path(r"\\?\C:\Codex\releases\0.144.0"),
            r"C:\Codex\releases\0.144.0"
        );
        assert_eq!(
            normalize_windows_path(r"\\?\UNC\server\share\Codex"),
            r"\\server\share\Codex"
        );
        assert_ne!(
            normalize_windows_path(r"C:\Codex\current"),
            normalize_windows_path(r"C:\Codex\releases\0.144.0")
        );
    }
}
