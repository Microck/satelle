use std::{
    collections::{BTreeMap, BTreeSet},
    fmt::Debug,
    fs,
    path::{Path, PathBuf},
    process::Output,
    sync::{
        atomic::{AtomicU64, Ordering},
        mpsc::{self, RecvTimeoutError},
    },
    time::{Duration, Instant},
};

#[cfg(unix)]
use std::os::unix::fs::MetadataExt;
#[cfg(windows)]
use std::os::windows::fs::MetadataExt;

use notify::{
    Config, Event, EventKind, RecommendedWatcher, RecursiveMode, Watcher,
    event::{MetadataKind, ModifyKind},
};
use serde_json::{Value, json};

const ERROR_KEYS: [&str; 8] = [
    "category",
    "code",
    "details",
    "docs_url",
    "message",
    "retryable",
    "schema_version",
    "suggested_commands",
];

pub fn assert_error_process(output: &Output) {
    assert!(!output.status.success(), "errors must exit nonzero");
    assert!(output.stdout.is_empty(), "errors must not use stdout");
}

pub fn assert_json_error(
    stderr: &[u8],
    expected_code: &str,
    expected_suggestions: &[&str],
) -> Value {
    let report: Value = serde_json::from_slice(stderr).expect("stderr should be one JSON value");
    let object = report
        .as_object()
        .expect("the JSON error envelope should be an object");
    let mut keys = object.keys().map(String::as_str).collect::<Vec<_>>();
    keys.sort_unstable();
    assert_eq!(keys, ERROR_KEYS);
    assert_eq!(report["schema_version"], "satelle.error.v1");
    assert_eq!(report["code"], expected_code);
    assert_eq!(report["category"], "invalid_request");
    assert_eq!(report["retryable"], false);
    assert!(
        report["message"]
            .as_str()
            .is_some_and(|value| !value.is_empty())
    );
    assert_eq!(report["details"], Value::Null);
    assert_eq!(report["docs_url"], Value::Null);
    assert_eq!(report["suggested_commands"], json!(expected_suggestions));

    let raw = String::from_utf8_lossy(stderr);
    assert!(
        !raw.contains('\u{1b}'),
        "JSON errors must not contain ANSI escapes"
    );
    assert!(
        !raw.starts_with("error:"),
        "JSON errors must not use human framing"
    );
    report
}

pub fn assert_human_error(stderr: &[u8], expected_code: &str) {
    let raw = String::from_utf8_lossy(stderr);
    let lines = raw.lines().collect::<Vec<_>>();
    assert!(
        lines
            .first()
            .is_some_and(|line| line.starts_with("error: ") && line.len() > "error: ".len()),
        "human errors must lead with a user-visible outcome: {raw}"
    );
    let expected_cause_suffix = format!(" [{expected_code}]");
    assert!(
        lines.get(1).is_some_and(|line| {
            line.starts_with("cause: ")
                && line.ends_with(&expected_cause_suffix)
                && line.len() > "cause: ".len() + expected_cause_suffix.len()
        }),
        "human errors must identify the typed cause after the outcome: {raw}"
    );
    assert!(
        matches!(lines.len(), 3 | 4),
        "human errors may contain only outcome, cause, optional state, and recovery: {raw}"
    );
    if lines.len() == 4 {
        assert!(
            lines[2].starts_with("state: ") && lines[2].len() > "state: ".len(),
            "human error state must follow the cause and be non-empty: {raw}"
        );
    }
    assert!(
        lines
            .last()
            .is_some_and(|line| line.starts_with("next: ") && line.len() > "next: ".len()),
        "human errors must include a recovery step: {raw}"
    );
    assert!(
        !raw.trim_start().starts_with('{'),
        "human errors must not use JSON framing"
    );
}

/// Asserts that raw output from a named public boundary contains none of its private canaries.
pub fn assert_privacy_canaries_absent(surface: &str, observed: &[u8], canaries: &[&str]) {
    assert!(
        !canaries.is_empty(),
        "{surface} requires at least one private canary"
    );
    for canary in canaries {
        let canary_bytes = canary.as_bytes();
        assert!(
            !canary_bytes.is_empty(),
            "{surface} requires non-empty private canaries"
        );
        assert!(
            !observed
                .windows(canary_bytes.len())
                .any(|window| window == canary_bytes),
            "{surface} leaked private canary {canary:?}"
        );
    }
}

#[derive(Debug, Eq, PartialEq)]
enum DirectoryTreeEntryKind {
    Directory,
    RegularFile(Vec<u8>),
    Symlink(PathBuf),
    Other,
}

#[derive(Debug, Eq, PartialEq)]
struct StableAccessMetadata {
    readonly: bool,
    #[cfg(unix)]
    mode: u32,
    #[cfg(unix)]
    uid: u32,
    #[cfg(unix)]
    gid: u32,
    #[cfg(windows)]
    file_attributes: u32,
}

#[derive(Debug, Eq, PartialEq)]
struct DirectoryTreeEntry {
    kind: DirectoryTreeEntryKind,
    access: StableAccessMetadata,
}

const MUTATION_BARRIER_TIMEOUT: Duration = Duration::from_secs(5);
static MUTATION_BARRIER_SEQUENCE: AtomicU64 = AtomicU64::new(0);

struct MutationBarrier {
    path: PathBuf,
    armed: bool,
}

impl MutationBarrier {
    fn create(operation: &str, root: &Path) -> Self {
        let sequence = MUTATION_BARRIER_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        let path = root.join(format!(
            ".satelle-mutation-barrier-{}-{sequence}",
            std::process::id()
        ));
        fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)
            .unwrap_or_else(|error| {
                panic!(
                    "{operation} could not create mutation watcher barrier {}: {error}",
                    path.display()
                )
            });
        Self { path, armed: true }
    }

    fn path(&self) -> &Path {
        &self.path
    }

    fn remove(mut self, operation: &str) {
        fs::remove_file(&self.path).unwrap_or_else(|error| {
            panic!(
                "{operation} could not remove mutation watcher barrier {}: {error}",
                self.path.display()
            )
        });
        self.armed = false;
    }
}

impl Drop for MutationBarrier {
    fn drop(&mut self) {
        if self.armed {
            // Cleanup during unwinding must not replace the original watcher failure.
            let _ = fs::remove_file(&self.path);
        }
    }
}

fn snapshot_directory_tree(root: &Path) -> std::io::Result<BTreeMap<PathBuf, DirectoryTreeEntry>> {
    fn visit(
        root: &Path,
        path: &Path,
        entries: &mut BTreeMap<PathBuf, DirectoryTreeEntry>,
    ) -> std::io::Result<()> {
        let metadata = fs::symlink_metadata(path)?;
        let relative_path = path
            .strip_prefix(root)
            .expect("snapshot paths should remain beneath the requested root")
            .to_path_buf();
        let file_type = metadata.file_type();
        let kind = if file_type.is_dir() {
            DirectoryTreeEntryKind::Directory
        } else if file_type.is_file() {
            DirectoryTreeEntryKind::RegularFile(fs::read(path)?)
        } else if file_type.is_symlink() {
            DirectoryTreeEntryKind::Symlink(fs::read_link(path)?)
        } else {
            DirectoryTreeEntryKind::Other
        };
        let access = StableAccessMetadata {
            readonly: metadata.permissions().readonly(),
            #[cfg(unix)]
            mode: metadata.mode(),
            #[cfg(unix)]
            uid: metadata.uid(),
            #[cfg(unix)]
            gid: metadata.gid(),
            #[cfg(windows)]
            file_attributes: metadata.file_attributes(),
        };
        entries.insert(relative_path, DirectoryTreeEntry { kind, access });

        if file_type.is_dir() {
            for child in fs::read_dir(path)? {
                visit(root, &child?.path(), entries)?;
            }
        }
        Ok(())
    }

    let mut entries = BTreeMap::new();
    visit(root, root, &mut entries)?;
    Ok(entries)
}

fn is_ignored_filesystem_event(kind: EventKind) -> bool {
    matches!(
        kind,
        EventKind::Access(_) | EventKind::Modify(ModifyKind::Metadata(MetadataKind::AccessTime))
    )
}

fn observe_transient_mutations(
    operation: &str,
    root: &Path,
    barrier_path: &Path,
    events: &mpsc::Receiver<notify::Result<Event>>,
) -> BTreeSet<PathBuf> {
    let deadline = Instant::now() + MUTATION_BARRIER_TIMEOUT;
    let mut changed_paths = BTreeSet::new();
    let mut barrier_observed = false;

    while !barrier_observed {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            panic!(
                "{operation} mutation watcher did not observe its barrier for {}",
                root.display()
            );
        }
        match events.recv_timeout(remaining) {
            Ok(Ok(event)) => {
                if event.need_rescan() {
                    panic!(
                        "{operation} mutation watcher lost events for {}",
                        root.display()
                    );
                }
                let ignored = is_ignored_filesystem_event(event.kind);
                barrier_observed = !ignored && event.paths.iter().any(|path| path == barrier_path);
                if ignored {
                    continue;
                }
                let mut event_path_observed = false;
                for path in event.paths.iter().filter(|path| *path != barrier_path) {
                    if let Ok(relative_path) = path.strip_prefix(root) {
                        changed_paths.insert(relative_path.to_path_buf());
                        event_path_observed = true;
                    }
                }
                if !barrier_observed && !event_path_observed {
                    changed_paths.insert(PathBuf::from("."));
                }
            }
            Ok(Err(error)) => panic!(
                "{operation} mutation watcher failed for {}: {error}",
                root.display()
            ),
            Err(RecvTimeoutError::Timeout) => panic!(
                "{operation} mutation watcher did not observe its barrier for {}",
                root.display()
            ),
            Err(RecvTimeoutError::Disconnected) => panic!(
                "{operation} mutation watcher disconnected for {}",
                root.display()
            ),
        }
    }
    changed_paths
}

/// Runs an operation and asserts that its directory tree remains byte-for-byte unchanged.
///
/// Native filesystem events detect transient writes while final snapshots record relative paths,
/// entry kinds, regular-file bytes, symlink targets, and the stable access metadata exposed by the
/// standard library. Symlinks are never followed, and volatile timestamps are intentionally
/// ignored.
pub fn assert_directory_tree_unchanged<T>(
    operation: &str,
    root: impl AsRef<Path>,
    run: impl FnOnce() -> T,
) -> T {
    let root = fs::canonicalize(root.as_ref()).unwrap_or_else(|error| {
        panic!(
            "{operation} could not resolve directory tree {}: {error}",
            root.as_ref().display()
        )
    });
    let snapshot = || {
        snapshot_directory_tree(&root).unwrap_or_else(|error| {
            panic!(
                "{operation} could not snapshot directory tree {}: {error}",
                root.display()
            )
        })
    };
    let before = snapshot();
    let (event_sender, event_receiver) = mpsc::channel();
    let mut watcher =
        RecommendedWatcher::new(event_sender, Config::default().with_follow_symlinks(false))
            .unwrap_or_else(|error| {
                panic!(
                    "{operation} could not start mutation watcher for {}: {error}",
                    root.display()
                )
            });
    watcher
        .watch(&root, RecursiveMode::Recursive)
        .unwrap_or_else(|error| {
            panic!(
                "{operation} could not watch directory tree {}: {error}",
                root.display()
            )
        });
    let result = run();
    let barrier = MutationBarrier::create(operation, &root);
    let mut changed_paths =
        observe_transient_mutations(operation, &root, barrier.path(), &event_receiver);
    watcher.unwatch(&root).unwrap_or_else(|error| {
        panic!(
            "{operation} could not stop mutation watcher for {}: {error}",
            root.display()
        )
    });
    barrier.remove(operation);
    let after = snapshot();
    changed_paths.extend(
        before
            .keys()
            .chain(after.keys())
            .filter(|path| before.get(*path) != after.get(*path))
            .cloned(),
    );

    assert!(
        changed_paths.is_empty(),
        "{operation} mutated directory tree {}; changed paths: {changed_paths:#?}",
        root.display(),
    );
    result
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReleaseArchiveContainer {
    TarGz,
    Zip,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReleaseBinaryFormat {
    Elf,
    MachO,
    Pe,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReleaseBinaryArchitecture {
    Arm64,
    X86_64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReleaseLibc {
    Glibc,
    Musl,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReleaseExecutableFixture {
    pub path: &'static str,
    pub binary_format: ReleaseBinaryFormat,
    pub architecture: ReleaseBinaryArchitecture,
    pub libc: Option<ReleaseLibc>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReleaseArchiveFixture {
    pub filename: &'static str,
    pub container: ReleaseArchiveContainer,
    pub executables: &'static [ReleaseExecutableFixture],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReleaseArchiveValidation {
    Accepted,
    Rejected,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ExpectedOutcome {
    Accept,
    Reject,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ReleaseArchiveContractCase {
    name: &'static str,
    fixture: ReleaseArchiveFixture,
    expected: ExpectedOutcome,
}

const fn case(
    name: &'static str,
    fixture: ReleaseArchiveFixture,
    expected: ExpectedOutcome,
) -> ReleaseArchiveContractCase {
    ReleaseArchiveContractCase {
        name,
        fixture,
        expected,
    }
}

const fn archive(
    filename: &'static str,
    container: ReleaseArchiveContainer,
    executables: &'static [ReleaseExecutableFixture],
) -> ReleaseArchiveFixture {
    ReleaseArchiveFixture {
        filename,
        container,
        executables,
    }
}

const fn executable(
    path: &'static str,
    binary_format: ReleaseBinaryFormat,
    architecture: ReleaseBinaryArchitecture,
    libc: Option<ReleaseLibc>,
) -> ReleaseExecutableFixture {
    ReleaseExecutableFixture {
        path,
        binary_format,
        architecture,
        libc,
    }
}

use ExpectedOutcome::{Accept, Reject};
use ReleaseArchiveContainer::{TarGz, Zip};
use ReleaseArchiveValidation::{Accepted, Rejected};
use ReleaseBinaryArchitecture::{Arm64, X86_64};
use ReleaseBinaryFormat::{Elf, MachO, Pe};
use ReleaseLibc::{Glibc, Musl};

#[rustfmt::skip]
const ROOT_CASES: [ReleaseArchiveContractCase; 10] = [
    case("Unix root executable", archive("satelle-v0.1.0-linux-x64-gnu.tar.gz", TarGz,
        &[executable("satelle", Elf, X86_64, Some(Glibc))]), Accept),
    case("Windows root executable", archive("satelle-v0.1.0-win32-x64-msvc.zip", Zip,
        &[executable("satelle.exe", Pe, X86_64, None)]), Accept),
    case("Unix missing root executable", archive("satelle-v0.1.0-linux-x64-gnu.tar.gz", TarGz,
        &[]), Reject),
    case("Unix wrong root executable name", archive("satelle-v0.1.0-linux-x64-gnu.tar.gz", TarGz,
        &[executable("satelle-wrong", Elf, X86_64, Some(Glibc))]), Reject),
    case("Unix nested executable only", archive("satelle-v0.1.0-linux-x64-gnu.tar.gz", TarGz,
        &[executable("bin/satelle", Elf, X86_64, Some(Glibc))]), Reject),
    case("Unix additional root executable", archive("satelle-v0.1.0-linux-x64-gnu.tar.gz", TarGz,
        &[
            executable("satelle", Elf, X86_64, Some(Glibc)),
            executable("satelle-helper", Elf, X86_64, Some(Glibc)),
        ]), Reject),
    case("Windows missing root executable", archive("satelle-v0.1.0-win32-x64-msvc.zip", Zip,
        &[]), Reject),
    case("Windows wrong root executable name", archive("satelle-v0.1.0-win32-x64-msvc.zip", Zip,
        &[executable("satelle-wrong.exe", Pe, X86_64, None)]), Reject),
    case("Windows nested executable only", archive("satelle-v0.1.0-win32-x64-msvc.zip", Zip,
        &[executable("bin/satelle.exe", Pe, X86_64, None)]), Reject),
    case("Windows additional root executable", archive("satelle-v0.1.0-win32-x64-msvc.zip", Zip,
        &[
            executable("satelle.exe", Pe, X86_64, None),
            executable("satelle-helper.exe", Pe, X86_64, None),
        ]), Reject),
];

#[rustfmt::skip]
const TARGET_CASES: [ReleaseArchiveContractCase; 12] = [
    case("linux-arm64-gnu", archive("satelle-v0.1.0-linux-arm64-gnu.tar.gz", TarGz,
        &[executable("satelle", Elf, Arm64, Some(Glibc))]), Accept),
    case("linux-x64-gnu", archive("satelle-v0.1.0-linux-x64-gnu.tar.gz", TarGz,
        &[executable("satelle", Elf, X86_64, Some(Glibc))]), Accept),
    case("darwin-arm64", archive("satelle-v0.1.0-darwin-arm64.tar.gz", TarGz,
        &[executable("satelle", MachO, Arm64, None)]), Accept),
    case("darwin-x64", archive("satelle-v0.1.0-darwin-x64.tar.gz", TarGz,
        &[executable("satelle", MachO, X86_64, None)]), Accept),
    case("win32-arm64-msvc", archive("satelle-v0.1.0-win32-arm64-msvc.zip", Zip,
        &[executable("satelle.exe", Pe, Arm64, None)]), Accept),
    case("win32-x64-msvc", archive("satelle-v0.1.0-win32-x64-msvc.zip", Zip,
        &[executable("satelle.exe", Pe, X86_64, None)]), Accept),
    case("name and architecture mismatch", archive("satelle-v0.1.0-linux-arm64-gnu.tar.gz", TarGz,
        &[executable("satelle", Elf, X86_64, Some(Glibc))]), Reject),
    case("target and binary format mismatch", archive("satelle-v0.1.0-linux-x64-gnu.tar.gz", TarGz,
        &[executable("satelle", Pe, X86_64, Some(Glibc))]), Reject),
    case("extension and container mismatch", archive("satelle-v0.1.0-win32-x64-msvc.zip", TarGz,
        &[executable("satelle.exe", Pe, X86_64, None)]), Reject),
    case("gnu target with musl binary", archive("satelle-v0.1.0-linux-x64-gnu.tar.gz", TarGz,
        &[executable("satelle", Elf, X86_64, Some(Musl))]), Reject),
    case("linux target without libc identity", archive("satelle-v0.1.0-linux-x64-gnu.tar.gz", TarGz,
        &[executable("satelle", Elf, X86_64, None)]), Reject),
    case("unsupported target", archive("satelle-v0.1.0-freebsd-x64.tar.gz", TarGz,
        &[executable("satelle", Elf, X86_64, Some(Glibc))]), Reject),
];

fn assert_archive_cases<E: Debug>(
    cases: &[ReleaseArchiveContractCase],
    mut validate: impl FnMut(&ReleaseArchiveFixture) -> Result<ReleaseArchiveValidation, E>,
) {
    for case in cases {
        let outcome = validate(&case.fixture).unwrap_or_else(|error| {
            panic!(
                "archive case '{}' failed before a validator outcome: {error:?}",
                case.name
            )
        });

        match (case.expected, outcome) {
            (Accept, Accepted) | (Reject, Rejected) => {}
            (Accept, Rejected) => panic!("archive case '{}' was rejected", case.name),
            (Reject, Accepted) => panic!("archive case '{}' was accepted", case.name),
        }
    }
}

/// Runs the semantic root-executable case catalog through a caller-supplied adapter.
///
/// The adapter reports the validator decision as [`ReleaseArchiveValidation`]. Errors are
/// reserved for fixture materialization or harness failures and always fail the assertion. This
/// catalog does not materialize archive bytes or prove production release wiring by itself.
pub fn assert_release_archive_root_contract<E: Debug>(
    validate: impl FnMut(&ReleaseArchiveFixture) -> Result<ReleaseArchiveValidation, E>,
) {
    assert_archive_cases(&ROOT_CASES, validate);
}

/// Runs the semantic target-identity case catalog through a caller-supplied adapter.
///
/// Expected outcomes remain private to this crate. The adapter reports ordinary validator
/// rejection with [`ReleaseArchiveValidation::Rejected`] and reserves `Err` for fixture or
/// harness failures. This catalog does not parse or validate archive bytes itself.
pub fn assert_release_archive_target_contract<E: Debug>(
    validate: impl FnMut(&ReleaseArchiveFixture) -> Result<ReleaseArchiveValidation, E>,
) {
    assert_archive_cases(&TARGET_CASES, validate);
}

/// One required package's candidate publication and pre-validation `latest` observation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NpmCandidatePackageFixture {
    pub package: &'static str,
    pub candidate_version: &'static str,
    pub candidate_dist_tag: &'static str,
    pub latest_before_full_graph_validation: Option<&'static str>,
}

/// One package's observed or recorded `latest`; `None` means the tag is absent.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NpmPromotionLatestFixture {
    pub package: &'static str,
    pub latest: Option<&'static str>,
}

/// Required durable-record content without prescribing mode tokens, progress tokens, or storage.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NpmPromotionDurableRecordFixture {
    pub candidate_version: &'static str,
    pub dependency_ordered_packages: &'static [&'static str],
    pub prior_latest_values: &'static [NpmPromotionLatestFixture],
    pub transaction_mode_present: bool,
    pub packages_with_progress: &'static [&'static str],
}

/// Inputs for candidate publication and default-tag preservation before full-graph validation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NpmCandidatePrevalidationFixture {
    pub candidate_version: &'static str,
    pub default_dist_tag: &'static str,
    pub required_packages: &'static [&'static str],
    pub prior_latest_values: &'static [NpmPromotionLatestFixture],
    pub candidate_packages: &'static [NpmCandidatePackageFixture],
}

/// Abstract repository-writer intent used only to express admission contention.
///
/// These variants are not serialized transaction-mode tokens and do not define a complete
/// transaction or recovery-state vocabulary.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NpmPromotionWriterOperation {
    Promotion,
    RollbackRecovery,
}

/// One attempted or active repository writer, including the candidate it operates on.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NpmPromotionWriterFixture {
    pub candidate_version: &'static str,
    pub operation: NpmPromotionWriterOperation,
}

/// Inputs needed to admit a promotion or rollback-recovery repository writer.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NpmPromotionAdmissionFixture {
    pub attempted_writer: NpmPromotionWriterFixture,
    pub active_repository_writer: Option<NpmPromotionWriterFixture>,
    pub dependency_ordered_required_packages: &'static [&'static str],
    pub prior_latest_values: &'static [NpmPromotionLatestFixture],
    pub durable_record: Option<NpmPromotionDurableRecordFixture>,
    pub full_graph_validation_passed: bool,
    pub other_nonterminal_record_exists: bool,
}

/// Draft-release inputs; the flags are blockers, not a complete record-state vocabulary.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NpmPromotionReleaseFixture {
    pub candidate_version: &'static str,
    pub required_packages: &'static [&'static str],
    pub final_registry_reread: &'static [NpmPromotionLatestFixture],
    pub promotion_incomplete: bool,
    pub promotion_conflicted: bool,
    pub rollback_mode: bool,
    pub rollback_completed: bool,
}

/// Ordinary adapter decisions; errors are reserved for materialization or harness failures.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NpmPromotionAdapterOutcome {
    Accepted,
    Rejected,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct NpmPromotionContractCase<F> {
    name: &'static str,
    fixture: F,
    expected: ExpectedOutcome,
}

const fn promotion_case<F>(
    name: &'static str,
    fixture: F,
    expected: ExpectedOutcome,
) -> NpmPromotionContractCase<F> {
    NpmPromotionContractCase {
        name,
        fixture,
        expected,
    }
}

const fn promotion_package(
    package: &'static str,
    candidate_version: &'static str,
    candidate_dist_tag: &'static str,
    latest_before_full_graph_validation: Option<&'static str>,
) -> NpmCandidatePackageFixture {
    NpmCandidatePackageFixture {
        package,
        candidate_version,
        candidate_dist_tag,
        latest_before_full_graph_validation,
    }
}

const fn promotion_latest(
    package: &'static str,
    latest: Option<&'static str>,
) -> NpmPromotionLatestFixture {
    NpmPromotionLatestFixture { package, latest }
}

const REQUIRED_PACKAGES: [&str; 8] = [
    "@microck/satelle-darwin-arm64",
    "@microck/satelle-darwin-x64",
    "@microck/satelle-linux-arm64-gnu",
    "@microck/satelle-linux-x64-gnu",
    "@microck/satelle-win32-arm64-msvc",
    "@microck/satelle-win32-x64-msvc",
    "@microck/satelle",
    "satelle",
];
const PERMUTED_NATIVE_PACKAGES: [&str; 8] = [
    "@microck/satelle-darwin-x64",
    "@microck/satelle-darwin-arm64",
    "@microck/satelle-linux-arm64-gnu",
    "@microck/satelle-linux-x64-gnu",
    "@microck/satelle-win32-arm64-msvc",
    "@microck/satelle-win32-x64-msvc",
    "@microck/satelle",
    "satelle",
];
#[rustfmt::skip]
const VALID_CANDIDATE_PACKAGES: [NpmCandidatePackageFixture; 8] = [
    promotion_package("@microck/satelle-darwin-arm64", "1.2.3", "rc-v1.2.3", Some("1.2.2")),
    promotion_package("@microck/satelle-darwin-x64", "1.2.3", "rc-v1.2.3", Some("1.2.2")),
    promotion_package("@microck/satelle-linux-arm64-gnu", "1.2.3", "rc-v1.2.3", Some("1.2.2")),
    promotion_package("@microck/satelle-linux-x64-gnu", "1.2.3", "rc-v1.2.3", Some("1.2.2")),
    promotion_package("@microck/satelle-win32-arm64-msvc", "1.2.3", "rc-v1.2.3", Some("1.2.2")),
    promotion_package("@microck/satelle-win32-x64-msvc", "1.2.3", "rc-v1.2.3", Some("1.2.2")),
    promotion_package("@microck/satelle", "1.2.3", "rc-v1.2.3", None),
    promotion_package("satelle", "1.2.3", "rc-v1.2.3", Some("1.2.2")),
];
const VALID_PRIOR_LATEST: [NpmPromotionLatestFixture; 8] = [
    promotion_latest("@microck/satelle-darwin-arm64", Some("1.2.2")),
    promotion_latest("@microck/satelle-darwin-x64", Some("1.2.2")),
    promotion_latest("@microck/satelle-linux-arm64-gnu", Some("1.2.2")),
    promotion_latest("@microck/satelle-linux-x64-gnu", Some("1.2.2")),
    promotion_latest("@microck/satelle-win32-arm64-msvc", Some("1.2.2")),
    promotion_latest("@microck/satelle-win32-x64-msvc", Some("1.2.2")),
    promotion_latest("@microck/satelle", None),
    promotion_latest("satelle", Some("1.2.2")),
];
const DEFAULT_TAG_CANDIDATES: [NpmCandidatePackageFixture; 8] = [
    VALID_CANDIDATE_PACKAGES[0],
    VALID_CANDIDATE_PACKAGES[1],
    VALID_CANDIDATE_PACKAGES[2],
    VALID_CANDIDATE_PACKAGES[3],
    VALID_CANDIDATE_PACKAGES[4],
    VALID_CANDIDATE_PACKAGES[5],
    promotion_package("@microck/satelle", "1.2.3", "latest", None),
    VALID_CANDIDATE_PACKAGES[7],
];
const WRONG_TAG_CANDIDATES: [NpmCandidatePackageFixture; 8] = [
    VALID_CANDIDATE_PACKAGES[0],
    VALID_CANDIDATE_PACKAGES[1],
    VALID_CANDIDATE_PACKAGES[2],
    VALID_CANDIDATE_PACKAGES[3],
    VALID_CANDIDATE_PACKAGES[4],
    VALID_CANDIDATE_PACKAGES[5],
    promotion_package("@microck/satelle", "1.2.3", "rc-v1.2.4", None),
    VALID_CANDIDATE_PACKAGES[7],
];
const WRONG_VERSION_CANDIDATES: [NpmCandidatePackageFixture; 8] = [
    VALID_CANDIDATE_PACKAGES[0],
    VALID_CANDIDATE_PACKAGES[1],
    VALID_CANDIDATE_PACKAGES[2],
    VALID_CANDIDATE_PACKAGES[3],
    VALID_CANDIDATE_PACKAGES[4],
    VALID_CANDIDATE_PACKAGES[5],
    promotion_package("@microck/satelle", "1.2.4", "rc-v1.2.3", None),
    VALID_CANDIDATE_PACKAGES[7],
];
const MISSING_CANDIDATE_PACKAGE: [NpmCandidatePackageFixture; 7] = [
    VALID_CANDIDATE_PACKAGES[0],
    VALID_CANDIDATE_PACKAGES[1],
    VALID_CANDIDATE_PACKAGES[2],
    VALID_CANDIDATE_PACKAGES[3],
    VALID_CANDIDATE_PACKAGES[4],
    VALID_CANDIDATE_PACKAGES[5],
    VALID_CANDIDATE_PACKAGES[6],
];
const DUPLICATE_CANDIDATE_PACKAGE_IDENTITY: [NpmCandidatePackageFixture; 8] = [
    VALID_CANDIDATE_PACKAGES[0],
    VALID_CANDIDATE_PACKAGES[1],
    VALID_CANDIDATE_PACKAGES[2],
    VALID_CANDIDATE_PACKAGES[3],
    VALID_CANDIDATE_PACKAGES[4],
    VALID_CANDIDATE_PACKAGES[5],
    VALID_CANDIDATE_PACKAGES[6],
    VALID_CANDIDATE_PACKAGES[0],
];
const ABSENT_PRIOR_LATEST_MOVED_CANDIDATES: [NpmCandidatePackageFixture; 8] = [
    VALID_CANDIDATE_PACKAGES[0],
    VALID_CANDIDATE_PACKAGES[1],
    VALID_CANDIDATE_PACKAGES[2],
    VALID_CANDIDATE_PACKAGES[3],
    VALID_CANDIDATE_PACKAGES[4],
    VALID_CANDIDATE_PACKAGES[5],
    promotion_package("@microck/satelle", "1.2.3", "rc-v1.2.3", Some("1.2.3")),
    VALID_CANDIDATE_PACKAGES[7],
];
const EXISTING_PRIOR_LATEST_MOVED_CANDIDATES: [NpmCandidatePackageFixture; 8] = [
    promotion_package(
        "@microck/satelle-darwin-arm64",
        "1.2.3",
        "rc-v1.2.3",
        Some("1.2.3"),
    ),
    VALID_CANDIDATE_PACKAGES[1],
    VALID_CANDIDATE_PACKAGES[2],
    VALID_CANDIDATE_PACKAGES[3],
    VALID_CANDIDATE_PACKAGES[4],
    VALID_CANDIDATE_PACKAGES[5],
    VALID_CANDIDATE_PACKAGES[6],
    VALID_CANDIDATE_PACKAGES[7],
];
const EXISTING_PRIOR_LATEST_MOVED_TO_UNRELATED_VERSION_CANDIDATES: [NpmCandidatePackageFixture; 8] = [
    promotion_package(
        "@microck/satelle-darwin-arm64",
        "1.2.3",
        "rc-v1.2.3",
        Some("1.2.4"),
    ),
    VALID_CANDIDATE_PACKAGES[1],
    VALID_CANDIDATE_PACKAGES[2],
    VALID_CANDIDATE_PACKAGES[3],
    VALID_CANDIDATE_PACKAGES[4],
    VALID_CANDIDATE_PACKAGES[5],
    VALID_CANDIDATE_PACKAGES[6],
    VALID_CANDIDATE_PACKAGES[7],
];
const WRONG_PRIOR_LATEST: [NpmPromotionLatestFixture; 8] = [
    VALID_PRIOR_LATEST[0],
    VALID_PRIOR_LATEST[1],
    VALID_PRIOR_LATEST[2],
    VALID_PRIOR_LATEST[3],
    VALID_PRIOR_LATEST[4],
    VALID_PRIOR_LATEST[5],
    promotion_latest("@microck/satelle", Some("1.2.2")),
    VALID_PRIOR_LATEST[7],
];
const DUPLICATE_PRIOR_LATEST_IDENTITY: [NpmPromotionLatestFixture; 8] = [
    VALID_PRIOR_LATEST[0],
    VALID_PRIOR_LATEST[1],
    VALID_PRIOR_LATEST[2],
    VALID_PRIOR_LATEST[3],
    VALID_PRIOR_LATEST[4],
    VALID_PRIOR_LATEST[5],
    VALID_PRIOR_LATEST[6],
    VALID_PRIOR_LATEST[0],
];
const MISSING_PROGRESS: [&str; 7] = [
    "@microck/satelle-darwin-arm64",
    "@microck/satelle-darwin-x64",
    "@microck/satelle-linux-arm64-gnu",
    "@microck/satelle-linux-x64-gnu",
    "@microck/satelle-win32-arm64-msvc",
    "@microck/satelle-win32-x64-msvc",
    "@microck/satelle",
];
const DUPLICATE_PROGRESS_IDENTITY: [&str; 8] = [
    "@microck/satelle-darwin-arm64",
    "@microck/satelle-darwin-x64",
    "@microck/satelle-linux-arm64-gnu",
    "@microck/satelle-linux-x64-gnu",
    "@microck/satelle-win32-arm64-msvc",
    "@microck/satelle-win32-x64-msvc",
    "@microck/satelle",
    "@microck/satelle-darwin-arm64",
];
const WRONG_PACKAGE_ORDER: [&str; 8] = [
    "@microck/satelle",
    "@microck/satelle-darwin-arm64",
    "@microck/satelle-darwin-x64",
    "@microck/satelle-linux-arm64-gnu",
    "@microck/satelle-linux-x64-gnu",
    "@microck/satelle-win32-arm64-msvc",
    "@microck/satelle-win32-x64-msvc",
    "satelle",
];

const PROMOTION_WRITER: NpmPromotionWriterFixture = NpmPromotionWriterFixture {
    candidate_version: "1.2.3",
    operation: NpmPromotionWriterOperation::Promotion,
};
const ROLLBACK_RECOVERY_WRITER: NpmPromotionWriterFixture = NpmPromotionWriterFixture {
    candidate_version: "1.2.3",
    operation: NpmPromotionWriterOperation::RollbackRecovery,
};
const OTHER_VERSION_PROMOTION_WRITER: NpmPromotionWriterFixture = NpmPromotionWriterFixture {
    candidate_version: "1.2.4",
    operation: NpmPromotionWriterOperation::Promotion,
};
const OTHER_VERSION_ROLLBACK_RECOVERY_WRITER: NpmPromotionWriterFixture =
    NpmPromotionWriterFixture {
        candidate_version: "1.2.4",
        operation: NpmPromotionWriterOperation::RollbackRecovery,
    };

#[rustfmt::skip]
const VALID_CANDIDATE_PREVALIDATION: NpmCandidatePrevalidationFixture = NpmCandidatePrevalidationFixture {
    candidate_version: "1.2.3", default_dist_tag: "latest", required_packages: &REQUIRED_PACKAGES,
    prior_latest_values: &VALID_PRIOR_LATEST, candidate_packages: &VALID_CANDIDATE_PACKAGES,
};
#[rustfmt::skip]
const VALID_DURABLE_RECORD: NpmPromotionDurableRecordFixture = NpmPromotionDurableRecordFixture {
    candidate_version: "1.2.3", dependency_ordered_packages: &REQUIRED_PACKAGES,
    prior_latest_values: &VALID_PRIOR_LATEST, transaction_mode_present: true, packages_with_progress: &REQUIRED_PACKAGES,
};
#[rustfmt::skip]
const PERMUTED_DURABLE_RECORD: NpmPromotionDurableRecordFixture = NpmPromotionDurableRecordFixture {
    dependency_ordered_packages: &PERMUTED_NATIVE_PACKAGES, ..VALID_DURABLE_RECORD
};
#[rustfmt::skip]
const VALID_ADMISSION: NpmPromotionAdmissionFixture = NpmPromotionAdmissionFixture {
    attempted_writer: PROMOTION_WRITER, active_repository_writer: None,
    dependency_ordered_required_packages: &REQUIRED_PACKAGES,
    prior_latest_values: &VALID_PRIOR_LATEST, durable_record: Some(VALID_DURABLE_RECORD),
    full_graph_validation_passed: true, other_nonterminal_record_exists: false,
};
#[rustfmt::skip]
const VALID_ROLLBACK_RECOVERY_ADMISSION: NpmPromotionAdmissionFixture = NpmPromotionAdmissionFixture {
    attempted_writer: ROLLBACK_RECOVERY_WRITER, ..VALID_ADMISSION
};
#[rustfmt::skip]
const PERMUTED_VALID_ADMISSION: NpmPromotionAdmissionFixture = NpmPromotionAdmissionFixture {
    dependency_ordered_required_packages: &PERMUTED_NATIVE_PACKAGES,
    durable_record: Some(PERMUTED_DURABLE_RECORD), ..VALID_ADMISSION
};

#[rustfmt::skip]
const CANDIDATE_PREVALIDATION_CASES: [NpmPromotionContractCase<NpmCandidatePrevalidationFixture>; 10] = [
    promotion_case("all candidates use rc tag and preserve prior latest", VALID_CANDIDATE_PREVALIDATION, Accept),
    promotion_case("one candidate uses the default tag", NpmCandidatePrevalidationFixture { candidate_packages: &DEFAULT_TAG_CANDIDATES, ..VALID_CANDIDATE_PREVALIDATION }, Reject),
    promotion_case("one candidate uses a mismatched rc tag", NpmCandidatePrevalidationFixture { candidate_packages: &WRONG_TAG_CANDIDATES, ..VALID_CANDIDATE_PREVALIDATION }, Reject),
    promotion_case("one candidate publishes the wrong version", NpmCandidatePrevalidationFixture { candidate_packages: &WRONG_VERSION_CANDIDATES, ..VALID_CANDIDATE_PREVALIDATION }, Reject),
    promotion_case("required candidate package is missing", NpmCandidatePrevalidationFixture { candidate_packages: &MISSING_CANDIDATE_PACKAGE, ..VALID_CANDIDATE_PREVALIDATION }, Reject),
    promotion_case("candidate package identity is duplicated while another is missing", NpmCandidatePrevalidationFixture { candidate_packages: &DUPLICATE_CANDIDATE_PACKAGE_IDENTITY, ..VALID_CANDIDATE_PREVALIDATION }, Reject),
    promotion_case("prior latest identity is duplicated while another is missing", NpmCandidatePrevalidationFixture { prior_latest_values: &DUPLICATE_PRIOR_LATEST_IDENTITY, ..VALID_CANDIDATE_PREVALIDATION }, Reject),
    promotion_case("absent latest became populated before full graph validation", NpmCandidatePrevalidationFixture { candidate_packages: &ABSENT_PRIOR_LATEST_MOVED_CANDIDATES, ..VALID_CANDIDATE_PREVALIDATION }, Reject),
    promotion_case("existing latest moved before full graph validation", NpmCandidatePrevalidationFixture { candidate_packages: &EXISTING_PRIOR_LATEST_MOVED_CANDIDATES, ..VALID_CANDIDATE_PREVALIDATION }, Reject),
    promotion_case("existing latest moved to an unrelated version before full graph validation", NpmCandidatePrevalidationFixture { candidate_packages: &EXISTING_PRIOR_LATEST_MOVED_TO_UNRELATED_VERSION_CANDIDATES, ..VALID_CANDIDATE_PREVALIDATION }, Reject),
];

#[rustfmt::skip]
const PROMOTION_ADMISSION_CASES: [NpmPromotionContractCase<NpmPromotionAdmissionFixture>; 23] = [
    promotion_case("validated candidate with durable exclusive admission", VALID_ADMISSION, Accept),
    promotion_case("rollback recovery may acquire an idle repository writer", VALID_ROLLBACK_RECOVERY_ADMISSION, Accept),
    promotion_case("independent native siblings may be permuted", PERMUTED_VALID_ADMISSION, Accept),
    promotion_case("full graph validation has not passed", NpmPromotionAdmissionFixture { full_graph_validation_passed: false, ..VALID_ADMISSION }, Reject),
    promotion_case("durable promotion record is unavailable", NpmPromotionAdmissionFixture { durable_record: None, ..VALID_ADMISSION }, Reject),
    promotion_case("durable record candidate version is wrong", NpmPromotionAdmissionFixture {
        durable_record: Some(NpmPromotionDurableRecordFixture { candidate_version: "1.2.4", ..VALID_DURABLE_RECORD }), ..VALID_ADMISSION
    }, Reject),
    promotion_case("durable record package order is wrong", NpmPromotionAdmissionFixture {
        durable_record: Some(NpmPromotionDurableRecordFixture { dependency_ordered_packages: &WRONG_PACKAGE_ORDER, ..VALID_DURABLE_RECORD }), ..VALID_ADMISSION
    }, Reject),
    promotion_case("admission package order is wrong", NpmPromotionAdmissionFixture {
        dependency_ordered_required_packages: &WRONG_PACKAGE_ORDER, ..VALID_ADMISSION
    }, Reject),
    promotion_case("admission prior latest value or absence is wrong", NpmPromotionAdmissionFixture {
        prior_latest_values: &WRONG_PRIOR_LATEST, ..VALID_ADMISSION
    }, Reject),
    promotion_case("durable record prior latest value or absence is wrong", NpmPromotionAdmissionFixture {
        durable_record: Some(NpmPromotionDurableRecordFixture { prior_latest_values: &WRONG_PRIOR_LATEST, ..VALID_DURABLE_RECORD }), ..VALID_ADMISSION
    }, Reject),
    promotion_case("durable record prior latest identity is duplicated while another is missing", NpmPromotionAdmissionFixture {
        durable_record: Some(NpmPromotionDurableRecordFixture { prior_latest_values: &DUPLICATE_PRIOR_LATEST_IDENTITY, ..VALID_DURABLE_RECORD }), ..VALID_ADMISSION
    }, Reject),
    promotion_case("durable record transaction mode is missing", NpmPromotionAdmissionFixture {
        durable_record: Some(NpmPromotionDurableRecordFixture { transaction_mode_present: false, ..VALID_DURABLE_RECORD }), ..VALID_ADMISSION
    }, Reject),
    promotion_case("durable record package progress is missing", NpmPromotionAdmissionFixture {
        durable_record: Some(NpmPromotionDurableRecordFixture { packages_with_progress: &MISSING_PROGRESS, ..VALID_DURABLE_RECORD }), ..VALID_ADMISSION
    }, Reject),
    promotion_case("durable record package progress duplicates one identity while another is missing", NpmPromotionAdmissionFixture {
        durable_record: Some(NpmPromotionDurableRecordFixture { packages_with_progress: &DUPLICATE_PROGRESS_IDENTITY, ..VALID_DURABLE_RECORD }), ..VALID_ADMISSION
    }, Reject),
    promotion_case("another promotion record is nonterminal", NpmPromotionAdmissionFixture { other_nonterminal_record_exists: true, ..VALID_ADMISSION }, Reject),
    promotion_case("cross-version promotion contends with active promotion", NpmPromotionAdmissionFixture {
        active_repository_writer: Some(OTHER_VERSION_PROMOTION_WRITER), ..VALID_ADMISSION
    }, Reject),
    promotion_case("cross-version promotion contends with active rollback recovery", NpmPromotionAdmissionFixture {
        active_repository_writer: Some(OTHER_VERSION_ROLLBACK_RECOVERY_WRITER), ..VALID_ADMISSION
    }, Reject),
    promotion_case("cross-version rollback recovery contends with active promotion", NpmPromotionAdmissionFixture {
        active_repository_writer: Some(OTHER_VERSION_PROMOTION_WRITER), ..VALID_ROLLBACK_RECOVERY_ADMISSION
    }, Reject),
    promotion_case("cross-version rollback recovery contends with active rollback recovery", NpmPromotionAdmissionFixture {
        active_repository_writer: Some(OTHER_VERSION_ROLLBACK_RECOVERY_WRITER), ..VALID_ROLLBACK_RECOVERY_ADMISSION
    }, Reject),
    promotion_case("promotion contends with same-candidate promotion", NpmPromotionAdmissionFixture {
        active_repository_writer: Some(PROMOTION_WRITER), ..VALID_ADMISSION
    }, Reject),
    promotion_case("promotion contends with same-candidate rollback recovery", NpmPromotionAdmissionFixture {
        active_repository_writer: Some(ROLLBACK_RECOVERY_WRITER), ..VALID_ADMISSION
    }, Reject),
    promotion_case("rollback recovery contends with same-candidate promotion", NpmPromotionAdmissionFixture {
        active_repository_writer: Some(PROMOTION_WRITER), ..VALID_ROLLBACK_RECOVERY_ADMISSION
    }, Reject),
    promotion_case("rollback recovery contends with same-candidate rollback recovery", NpmPromotionAdmissionFixture {
        active_repository_writer: Some(ROLLBACK_RECOVERY_WRITER), ..VALID_ROLLBACK_RECOVERY_ADMISSION
    }, Reject),
];

const VALID_FINAL_LATEST: [NpmPromotionLatestFixture; 8] = [
    promotion_latest("@microck/satelle-darwin-arm64", Some("1.2.3")),
    promotion_latest("@microck/satelle-darwin-x64", Some("1.2.3")),
    promotion_latest("@microck/satelle-linux-arm64-gnu", Some("1.2.3")),
    promotion_latest("@microck/satelle-linux-x64-gnu", Some("1.2.3")),
    promotion_latest("@microck/satelle-win32-arm64-msvc", Some("1.2.3")),
    promotion_latest("@microck/satelle-win32-x64-msvc", Some("1.2.3")),
    promotion_latest("@microck/satelle", Some("1.2.3")),
    promotion_latest("satelle", Some("1.2.3")),
];
const MISSING_FINAL_LATEST: [NpmPromotionLatestFixture; 7] = [
    VALID_FINAL_LATEST[0],
    VALID_FINAL_LATEST[1],
    VALID_FINAL_LATEST[2],
    VALID_FINAL_LATEST[3],
    VALID_FINAL_LATEST[4],
    VALID_FINAL_LATEST[5],
    VALID_FINAL_LATEST[6],
];
const DUPLICATE_FINAL_LATEST_IDENTITY: [NpmPromotionLatestFixture; 8] = [
    VALID_FINAL_LATEST[0],
    VALID_FINAL_LATEST[1],
    VALID_FINAL_LATEST[2],
    VALID_FINAL_LATEST[3],
    VALID_FINAL_LATEST[4],
    VALID_FINAL_LATEST[5],
    VALID_FINAL_LATEST[6],
    VALID_FINAL_LATEST[0],
];
const ABSENT_FINAL_LATEST: [NpmPromotionLatestFixture; 8] = [
    VALID_FINAL_LATEST[0],
    VALID_FINAL_LATEST[1],
    VALID_FINAL_LATEST[2],
    VALID_FINAL_LATEST[3],
    VALID_FINAL_LATEST[4],
    VALID_FINAL_LATEST[5],
    promotion_latest("@microck/satelle", None),
    VALID_FINAL_LATEST[7],
];
const STALE_FINAL_LATEST: [NpmPromotionLatestFixture; 8] = [
    VALID_FINAL_LATEST[0],
    VALID_FINAL_LATEST[1],
    VALID_FINAL_LATEST[2],
    VALID_FINAL_LATEST[3],
    VALID_FINAL_LATEST[4],
    VALID_FINAL_LATEST[5],
    promotion_latest("@microck/satelle", Some("1.2.2")),
    VALID_FINAL_LATEST[7],
];
#[rustfmt::skip]
const VALID_RELEASE: NpmPromotionReleaseFixture = NpmPromotionReleaseFixture {
    candidate_version: "1.2.3", required_packages: &REQUIRED_PACKAGES,
    final_registry_reread: &VALID_FINAL_LATEST, promotion_incomplete: false, promotion_conflicted: false,
    rollback_mode: false, rollback_completed: false,
};

#[rustfmt::skip]
const PROMOTION_RELEASE_CASES: [NpmPromotionContractCase<NpmPromotionReleaseFixture>; 10] = [
    promotion_case("completed promotion with every latest at candidate", VALID_RELEASE, Accept),
    promotion_case("final registry reread latest does not match the fixture candidate", NpmPromotionReleaseFixture { candidate_version: "1.2.4", ..VALID_RELEASE }, Reject),
    promotion_case("required package missing from final registry reread", NpmPromotionReleaseFixture { final_registry_reread: &MISSING_FINAL_LATEST, ..VALID_RELEASE }, Reject),
    promotion_case("final registry reread duplicates one identity while another is missing", NpmPromotionReleaseFixture { final_registry_reread: &DUPLICATE_FINAL_LATEST_IDENTITY, ..VALID_RELEASE }, Reject),
    promotion_case("required package is present without latest", NpmPromotionReleaseFixture { final_registry_reread: &ABSENT_FINAL_LATEST, ..VALID_RELEASE }, Reject),
    promotion_case("required package latest is not the candidate", NpmPromotionReleaseFixture { final_registry_reread: &STALE_FINAL_LATEST, ..VALID_RELEASE }, Reject),
    promotion_case("promotion record is incomplete", NpmPromotionReleaseFixture { promotion_incomplete: true, ..VALID_RELEASE }, Reject),
    promotion_case("promotion record is conflicted", NpmPromotionReleaseFixture { promotion_conflicted: true, ..VALID_RELEASE }, Reject),
    promotion_case("promotion record is in rollback mode", NpmPromotionReleaseFixture { rollback_mode: true, ..VALID_RELEASE }, Reject),
    promotion_case("promotion record has completed rollback", NpmPromotionReleaseFixture { rollback_completed: true, ..VALID_RELEASE }, Reject),
];

fn assert_npm_promotion_cases<F, E: Debug>(
    cases: &[NpmPromotionContractCase<F>],
    mut evaluate: impl FnMut(&F) -> Result<NpmPromotionAdapterOutcome, E>,
) {
    for case in cases {
        let outcome = evaluate(&case.fixture).unwrap_or_else(|error| {
            panic!(
                "npm promotion case '{}' failed before an adapter outcome: {error:?}",
                case.name
            )
        });

        match (case.expected, outcome) {
            (Accept, NpmPromotionAdapterOutcome::Accepted)
            | (Reject, NpmPromotionAdapterOutcome::Rejected) => {}
            (Accept, NpmPromotionAdapterOutcome::Rejected) => {
                panic!("npm promotion case '{}' was rejected", case.name)
            }
            (Reject, NpmPromotionAdapterOutcome::Accepted) => {
                panic!("npm promotion case '{}' was accepted", case.name)
            }
        }
    }
}

/// Checks versioned non-default candidates and unchanged `latest` values before validation.
pub fn assert_npm_candidate_prevalidation_contract<E: Debug>(
    evaluate: impl FnMut(&NpmCandidatePrevalidationFixture) -> Result<NpmPromotionAdapterOutcome, E>,
) {
    assert_npm_promotion_cases(&CANDIDATE_PREVALIDATION_CASES, evaluate);
}

/// Checks post-validation durable-record and exclusive repository-writer admission.
pub fn assert_npm_promotion_admission_contract<E: Debug>(
    evaluate: impl FnMut(&NpmPromotionAdmissionFixture) -> Result<NpmPromotionAdapterOutcome, E>,
) {
    assert_npm_promotion_cases(&PROMOTION_ADMISSION_CASES, evaluate);
}

/// Evaluates supplied final-reread results and draft-release blockers through a caller adapter.
///
/// This assertion does not perform or prove registry I/O, nor does it prove that the reread occurs
/// immediately before a release is made public.
pub fn assert_npm_promotion_release_contract<E: Debug>(
    evaluate: impl FnMut(&NpmPromotionReleaseFixture) -> Result<NpmPromotionAdapterOutcome, E>,
) {
    assert_npm_promotion_cases(&PROMOTION_RELEASE_CASES, evaluate);
}

/// One versioned release archive's already-extracted native executable digest.
///
/// The digest is an opaque identifier. This fixture does not define its syntax or how it is
/// computed from archive contents.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReleaseArchiveExecutableDigestFixture {
    pub target: &'static str,
    pub candidate_version: &'static str,
    pub executable_digest: &'static str,
}

/// One platform-specific npm package's already-extracted native executable digest.
///
/// The digest is an opaque identifier. This fixture does not define package extraction or digest
/// computation behavior.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NpmPackageExecutableDigestFixture {
    pub package: &'static str,
    pub candidate_version: &'static str,
    pub executable_digest: &'static str,
}

/// Semantic observations needed to compare release archives with their corresponding npm packages.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ArchiveNpmParityFixture {
    pub release_archives: &'static [ReleaseArchiveExecutableDigestFixture],
    pub npm_packages: &'static [NpmPackageExecutableDigestFixture],
}

/// Ordinary adapter decisions; errors are reserved for materialization or harness failures.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ArchiveNpmParityAdapterOutcome {
    Accepted,
    Rejected,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ArchiveNpmParityContractCase<F> {
    name: &'static str,
    fixture: F,
    expected: ExpectedOutcome,
}

const fn archive_npm_parity_case<F>(
    name: &'static str,
    fixture: F,
    expected: ExpectedOutcome,
) -> ArchiveNpmParityContractCase<F> {
    ArchiveNpmParityContractCase {
        name,
        fixture,
        expected,
    }
}

const fn archive_digest(
    target: &'static str,
    candidate_version: &'static str,
    executable_digest: &'static str,
) -> ReleaseArchiveExecutableDigestFixture {
    ReleaseArchiveExecutableDigestFixture {
        target,
        candidate_version,
        executable_digest,
    }
}

const fn npm_package_digest(
    package: &'static str,
    candidate_version: &'static str,
    executable_digest: &'static str,
) -> NpmPackageExecutableDigestFixture {
    NpmPackageExecutableDigestFixture {
        package,
        candidate_version,
        executable_digest,
    }
}

#[rustfmt::skip]
const VERSION_MATCHED_ARCHIVES: [ReleaseArchiveExecutableDigestFixture; 6] = [
    archive_digest("linux-arm64-gnu", "1.2.3", "opaque-linux-arm64"),
    archive_digest("linux-x64-gnu", "1.2.3", "opaque-linux-x64"),
    archive_digest("darwin-arm64", "1.2.3", "opaque-darwin-arm64"),
    archive_digest("darwin-x64", "1.2.3", "opaque-darwin-x64"),
    archive_digest("win32-arm64-msvc", "1.2.3", "opaque-win32-arm64"),
    archive_digest("win32-x64-msvc", "1.2.3", "opaque-win32-x64"),
];

#[rustfmt::skip]
const MATCHING_NPM_PACKAGES: [NpmPackageExecutableDigestFixture; 6] = [
    npm_package_digest("@microck/satelle-linux-arm64-gnu", "1.2.3", "opaque-linux-arm64"),
    npm_package_digest("@microck/satelle-linux-x64-gnu", "1.2.3", "opaque-linux-x64"),
    npm_package_digest("@microck/satelle-darwin-arm64", "1.2.3", "opaque-darwin-arm64"),
    npm_package_digest("@microck/satelle-darwin-x64", "1.2.3", "opaque-darwin-x64"),
    npm_package_digest("@microck/satelle-win32-arm64-msvc", "1.2.3", "opaque-win32-arm64"),
    npm_package_digest("@microck/satelle-win32-x64-msvc", "1.2.3", "opaque-win32-x64"),
];

const PERMUTED_NPM_PACKAGES: [NpmPackageExecutableDigestFixture; 6] = [
    MATCHING_NPM_PACKAGES[5],
    MATCHING_NPM_PACKAGES[4],
    MATCHING_NPM_PACKAGES[3],
    MATCHING_NPM_PACKAGES[2],
    MATCHING_NPM_PACKAGES[1],
    MATCHING_NPM_PACKAGES[0],
];

const MISMATCHED_NPM_PACKAGES: [NpmPackageExecutableDigestFixture; 6] = [
    MATCHING_NPM_PACKAGES[0],
    npm_package_digest("@microck/satelle-linux-x64-gnu", "1.2.3", "opaque-mismatch"),
    MATCHING_NPM_PACKAGES[2],
    MATCHING_NPM_PACKAGES[3],
    MATCHING_NPM_PACKAGES[4],
    MATCHING_NPM_PACKAGES[5],
];

const MISSING_NPM_PACKAGE: [NpmPackageExecutableDigestFixture; 5] = [
    MATCHING_NPM_PACKAGES[0],
    MATCHING_NPM_PACKAGES[1],
    MATCHING_NPM_PACKAGES[2],
    MATCHING_NPM_PACKAGES[3],
    MATCHING_NPM_PACKAGES[4],
];

// Swapping two digests preserves both identity and digest sets while breaking correspondence.
const DIGESTS_UNDER_WRONG_PACKAGE_IDENTITIES: [NpmPackageExecutableDigestFixture; 6] = [
    MATCHING_NPM_PACKAGES[0],
    MATCHING_NPM_PACKAGES[1],
    npm_package_digest(
        "@microck/satelle-darwin-arm64",
        "1.2.3",
        "opaque-darwin-x64",
    ),
    npm_package_digest(
        "@microck/satelle-darwin-x64",
        "1.2.3",
        "opaque-darwin-arm64",
    ),
    MATCHING_NPM_PACKAGES[4],
    MATCHING_NPM_PACKAGES[5],
];

const WRONG_VERSION_NPM_PACKAGES: [NpmPackageExecutableDigestFixture; 6] = [
    MATCHING_NPM_PACKAGES[0],
    MATCHING_NPM_PACKAGES[1],
    MATCHING_NPM_PACKAGES[2],
    MATCHING_NPM_PACKAGES[3],
    MATCHING_NPM_PACKAGES[4],
    npm_package_digest(
        "@microck/satelle-win32-x64-msvc",
        "1.2.4",
        "opaque-win32-x64",
    ),
];

const WRONG_VERSION_ARCHIVES: [ReleaseArchiveExecutableDigestFixture; 6] = [
    VERSION_MATCHED_ARCHIVES[0],
    VERSION_MATCHED_ARCHIVES[1],
    VERSION_MATCHED_ARCHIVES[2],
    VERSION_MATCHED_ARCHIVES[3],
    archive_digest("win32-arm64-msvc", "1.2.4", "opaque-win32-arm64"),
    VERSION_MATCHED_ARCHIVES[5],
];

#[rustfmt::skip]
const VALID_ARCHIVE_NPM_PARITY: ArchiveNpmParityFixture = ArchiveNpmParityFixture {
    release_archives: &VERSION_MATCHED_ARCHIVES, npm_packages: &MATCHING_NPM_PACKAGES,
};

#[rustfmt::skip]
const ARCHIVE_NPM_PARITY_CASES: [ArchiveNpmParityContractCase<ArchiveNpmParityFixture>; 7] = [
    archive_npm_parity_case("all six version-matched archive and npm executable digests match", VALID_ARCHIVE_NPM_PARITY, Accept),
    archive_npm_parity_case("npm package observations may be permuted", ArchiveNpmParityFixture { npm_packages: &PERMUTED_NPM_PACKAGES, ..VALID_ARCHIVE_NPM_PARITY }, Accept),
    archive_npm_parity_case("one archive and npm executable digest mismatches", ArchiveNpmParityFixture { npm_packages: &MISMATCHED_NPM_PACKAGES, ..VALID_ARCHIVE_NPM_PARITY }, Reject),
    archive_npm_parity_case("required platform npm package is missing", ArchiveNpmParityFixture { npm_packages: &MISSING_NPM_PACKAGE, ..VALID_ARCHIVE_NPM_PARITY }, Reject),
    archive_npm_parity_case("archive digests exist only under wrong platform package identities", ArchiveNpmParityFixture { npm_packages: &DIGESTS_UNDER_WRONG_PACKAGE_IDENTITIES, ..VALID_ARCHIVE_NPM_PARITY }, Reject),
    archive_npm_parity_case("one npm package version differs from its release archive", ArchiveNpmParityFixture { npm_packages: &WRONG_VERSION_NPM_PACKAGES, ..VALID_ARCHIVE_NPM_PARITY }, Reject),
    archive_npm_parity_case("one release archive version differs from its npm package", ArchiveNpmParityFixture { release_archives: &WRONG_VERSION_ARCHIVES, ..VALID_ARCHIVE_NPM_PARITY }, Reject),
];

fn assert_archive_npm_parity_cases<F, E: Debug>(
    cases: &[ArchiveNpmParityContractCase<F>],
    mut evaluate: impl FnMut(&F) -> Result<ArchiveNpmParityAdapterOutcome, E>,
) {
    for case in cases {
        let outcome = evaluate(&case.fixture).unwrap_or_else(|error| {
            panic!(
                "archive/npm parity case '{}' failed before an adapter outcome: {error:?}",
                case.name
            )
        });

        match (case.expected, outcome) {
            (Accept, ArchiveNpmParityAdapterOutcome::Accepted)
            | (Reject, ArchiveNpmParityAdapterOutcome::Rejected) => {}
            (Accept, ArchiveNpmParityAdapterOutcome::Rejected) => {
                panic!("archive/npm parity case '{}' was rejected", case.name)
            }
            (Reject, ArchiveNpmParityAdapterOutcome::Accepted) => {
                panic!("archive/npm parity case '{}' was accepted", case.name)
            }
        }
    }
}

/// Runs the six-platform archive-to-npm executable-digest catalog through a caller adapter.
///
/// Expected outcomes remain private to this crate. The adapter reports ordinary parity rejection
/// with [`ArchiveNpmParityAdapterOutcome::Rejected`] and reserves `Err` for fixture materialization
/// or harness failures. This catalog does not read archives or packages, compute or parse digests,
/// serialize observations, or prove production release wiring.
pub fn assert_archive_npm_executable_parity_contract<E: Debug>(
    evaluate: impl FnMut(&ArchiveNpmParityFixture) -> Result<ArchiveNpmParityAdapterOutcome, E>,
) {
    assert_archive_npm_parity_cases(&ARCHIVE_NPM_PARITY_CASES, evaluate);
}

/// The expected top-level framing of one versioned machine-readable payload.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum VersionedPayloadFraming {
    Json,
    Ndjson,
}

/// One top-level enum field and its complete allowed token set for a schema version.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct VersionedPayloadEnumFieldContract {
    pub field: &'static str,
    pub allowed_tokens: &'static [&'static str],
}

/// Raw channel-neutral observations and expectations for one versioned payload surface.
///
/// Carrier values are opaque identifiers compared only for equality. They do not classify or map
/// process, HTTP, WebSocket, or any other transport behavior.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct VersionedPayloadContractFixture {
    pub expected_carrier: &'static str,
    pub observed_carrier: &'static str,
    pub framing: VersionedPayloadFraming,
    pub payload: &'static [u8],
    pub expected_schema_version: &'static str,
    pub required_fields: &'static [&'static str],
    pub enum_fields: &'static [VersionedPayloadEnumFieldContract],
}

/// Ordinary adapter decisions; errors are reserved for materialization or harness failures.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum VersionedPayloadAdapterOutcome {
    Accepted,
    Rejected,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct VersionedPayloadContractCase<F> {
    name: &'static str,
    fixture: F,
    expected: ExpectedOutcome,
}

const fn versioned_payload_case<F>(
    name: &'static str,
    fixture: F,
    expected: ExpectedOutcome,
) -> VersionedPayloadContractCase<F> {
    VersionedPayloadContractCase {
        name,
        fixture,
        expected,
    }
}

const VERSIONED_PAYLOAD_REQUIRED_FIELDS: [&str; 3] = ["schema_version", "id", "state"];
const VERSIONED_PAYLOAD_STATE_TOKENS: [&str; 2] = ["ready", "busy"];
const VERSIONED_PAYLOAD_ENUM_FIELDS: [VersionedPayloadEnumFieldContract; 1] =
    [VersionedPayloadEnumFieldContract {
        field: "state",
        allowed_tokens: &VERSIONED_PAYLOAD_STATE_TOKENS,
    }];

const VALID_JSON_PAYLOAD: &[u8] =
    br#"{"schema_version":"satelle.catalog.v1","id":"one","state":"ready"}"#;
const NULL_REQUIRED_FIELD_JSON_PAYLOAD: &[u8] =
    br#"{"schema_version":"satelle.catalog.v1","id":null,"state":"ready"}"#;
const VALID_NDJSON_PAYLOAD: &[u8] = b"{\"schema_version\":\"satelle.catalog.v1\",\"id\":\"one\",\"state\":\"ready\"}\n{\"schema_version\":\"satelle.catalog.v1\",\"id\":\"two\",\"state\":\"busy\"}\n";
const MISSING_SCHEMA_VERSION_PAYLOAD: &[u8] = br#"{"id":"one","state":"ready"}"#;
const WRONG_SCHEMA_VERSION_PAYLOAD: &[u8] =
    br#"{"schema_version":"satelle.catalog.v2","id":"one","state":"ready"}"#;
const NON_STRING_SCHEMA_VERSION_PAYLOAD: &[u8] =
    br#"{"schema_version":1,"id":"one","state":"ready"}"#;
const MISSING_REQUIRED_FIELD_PAYLOAD: &[u8] =
    br#"{"schema_version":"satelle.catalog.v1","state":"ready"}"#;
const NON_STRING_ENUM_TOKEN_PAYLOAD: &[u8] =
    br#"{"schema_version":"satelle.catalog.v1","id":"one","state":1}"#;
const NON_OBJECT_JSON_PAYLOAD: &[u8] = br#"["satelle.catalog.v1","one","ready"]"#;
const INVALID_SECOND_NDJSON_ENUM_PAYLOAD: &[u8] = b"{\"schema_version\":\"satelle.catalog.v1\",\"id\":\"one\",\"state\":\"ready\"}\n{\"schema_version\":\"satelle.catalog.v1\",\"id\":\"two\",\"state\":\"unknown\"}\n";
const PRETTY_JSON_BYTES_FOR_NDJSON_PAYLOAD: &[u8] = b"{\n  \"schema_version\": \"satelle.catalog.v1\",\n  \"id\": \"one\",\n  \"state\": \"ready\"\n}\n";
const MALFORMED_JSON_PAYLOAD: &[u8] =
    br#"{"schema_version":"satelle.catalog.v1","id":"one","state":"ready"#;
const MALFORMED_SECOND_NDJSON_PAYLOAD: &[u8] = b"{\"schema_version\":\"satelle.catalog.v1\",\"id\":\"one\",\"state\":\"ready\"}\n{\"schema_version\":\"satelle.catalog.v1\",\"id\":\"two\",\"state\":\"busy\"\n";

const VALID_VERSIONED_JSON_FIXTURE: VersionedPayloadContractFixture =
    VersionedPayloadContractFixture {
        expected_carrier: "opaque-catalog-carrier",
        observed_carrier: "opaque-catalog-carrier",
        framing: VersionedPayloadFraming::Json,
        payload: VALID_JSON_PAYLOAD,
        expected_schema_version: "satelle.catalog.v1",
        required_fields: &VERSIONED_PAYLOAD_REQUIRED_FIELDS,
        enum_fields: &VERSIONED_PAYLOAD_ENUM_FIELDS,
    };

#[rustfmt::skip]
const VERSIONED_PAYLOAD_CASES: [VersionedPayloadContractCase<VersionedPayloadContractFixture>; 15] = [
    versioned_payload_case("single JSON value satisfies the versioned contract", VALID_VERSIONED_JSON_FIXTURE, Accept),
    versioned_payload_case("present nullable field satisfies required-field presence", VersionedPayloadContractFixture { payload: NULL_REQUIRED_FIELD_JSON_PAYLOAD, ..VALID_VERSIONED_JSON_FIXTURE }, Accept),
    versioned_payload_case("multiple NDJSON values each satisfy the versioned contract", VersionedPayloadContractFixture { framing: VersionedPayloadFraming::Ndjson, payload: VALID_NDJSON_PAYLOAD, ..VALID_VERSIONED_JSON_FIXTURE }, Accept),
    versioned_payload_case("observed carrier differs from the opaque expected carrier", VersionedPayloadContractFixture { observed_carrier: "other-opaque-carrier", ..VALID_VERSIONED_JSON_FIXTURE }, Reject),
    versioned_payload_case("schema_version is missing", VersionedPayloadContractFixture { payload: MISSING_SCHEMA_VERSION_PAYLOAD, ..VALID_VERSIONED_JSON_FIXTURE }, Reject),
    versioned_payload_case("schema_version has the wrong token", VersionedPayloadContractFixture { payload: WRONG_SCHEMA_VERSION_PAYLOAD, ..VALID_VERSIONED_JSON_FIXTURE }, Reject),
    versioned_payload_case("schema_version is not a string", VersionedPayloadContractFixture { payload: NON_STRING_SCHEMA_VERSION_PAYLOAD, ..VALID_VERSIONED_JSON_FIXTURE }, Reject),
    versioned_payload_case("required field is missing", VersionedPayloadContractFixture { payload: MISSING_REQUIRED_FIELD_PAYLOAD, ..VALID_VERSIONED_JSON_FIXTURE }, Reject),
    versioned_payload_case("enum token is not a string", VersionedPayloadContractFixture { payload: NON_STRING_ENUM_TOKEN_PAYLOAD, ..VALID_VERSIONED_JSON_FIXTURE }, Reject),
    versioned_payload_case("top-level JSON value is not an object", VersionedPayloadContractFixture { payload: NON_OBJECT_JSON_PAYLOAD, ..VALID_VERSIONED_JSON_FIXTURE }, Reject),
    versioned_payload_case("second NDJSON value has an invalid enum token", VersionedPayloadContractFixture { framing: VersionedPayloadFraming::Ndjson, payload: INVALID_SECOND_NDJSON_ENUM_PAYLOAD, ..VALID_VERSIONED_JSON_FIXTURE }, Reject),
    versioned_payload_case("NDJSON bytes do not satisfy single JSON framing", VersionedPayloadContractFixture { payload: VALID_NDJSON_PAYLOAD, ..VALID_VERSIONED_JSON_FIXTURE }, Reject),
    versioned_payload_case("pretty JSON bytes do not satisfy NDJSON framing", VersionedPayloadContractFixture { framing: VersionedPayloadFraming::Ndjson, payload: PRETTY_JSON_BYTES_FOR_NDJSON_PAYLOAD, ..VALID_VERSIONED_JSON_FIXTURE }, Reject),
    versioned_payload_case("malformed JSON is rejected", VersionedPayloadContractFixture { payload: MALFORMED_JSON_PAYLOAD, ..VALID_VERSIONED_JSON_FIXTURE }, Reject),
    versioned_payload_case("malformed second NDJSON value is rejected", VersionedPayloadContractFixture { framing: VersionedPayloadFraming::Ndjson, payload: MALFORMED_SECOND_NDJSON_PAYLOAD, ..VALID_VERSIONED_JSON_FIXTURE }, Reject),
];

fn assert_versioned_payload_cases<F, E: Debug>(
    cases: &[VersionedPayloadContractCase<F>],
    mut evaluate: impl FnMut(&F) -> Result<VersionedPayloadAdapterOutcome, E>,
) {
    for case in cases {
        let outcome = evaluate(&case.fixture).unwrap_or_else(|error| {
            panic!(
                "versioned payload case '{}' failed before an adapter outcome: {error:?}",
                case.name
            )
        });

        match (case.expected, outcome) {
            (Accept, VersionedPayloadAdapterOutcome::Accepted)
            | (Reject, VersionedPayloadAdapterOutcome::Rejected) => {}
            (Accept, VersionedPayloadAdapterOutcome::Rejected) => {
                panic!("versioned payload case '{}' was rejected", case.name)
            }
            (Reject, VersionedPayloadAdapterOutcome::Accepted) => {
                panic!("versioned payload case '{}' was accepted", case.name)
            }
        }
    }
}

/// Runs the shared channel-neutral versioned-payload catalog through a caller adapter.
///
/// Expected outcomes remain private to this crate. The adapter reports ordinary conformance
/// rejection with [`VersionedPayloadAdapterOutcome::Rejected`] and reserves `Err` for fixture
/// materialization or harness failures. This catalog defines no stdout, stderr, exit-status, HTTP,
/// or WebSocket behavior and does not map between process and transport channels.
pub fn assert_versioned_payload_contract<E: Debug>(
    evaluate: impl FnMut(&VersionedPayloadContractFixture) -> Result<VersionedPayloadAdapterOutcome, E>,
) {
    assert_versioned_payload_cases(&VERSIONED_PAYLOAD_CASES, evaluate);
}

#[cfg(test)]
mod tests {
    use super::*;

    static TEMP_TREE_SEQUENCE: AtomicU64 = AtomicU64::new(0);

    #[test]
    fn privacy_canary_assertion_accepts_clean_raw_bytes() {
        assert_privacy_canaries_absent(
            "HTTP logs response",
            b"\x00public log bytes\xff",
            &["PRIVATE_PROMPT_CANARY", "PRIVATE_SECRET_CANARY"],
        );
    }

    #[test]
    #[should_panic(expected = "HTTP logs response leaked private canary \"PRIVATE_SECRET_CANARY\"")]
    fn privacy_canary_assertion_identifies_surface_and_any_leaked_canary() {
        assert_privacy_canaries_absent(
            "HTTP logs response",
            b"public prefix PRIVATE_SECRET_CANARY public suffix",
            &["PRIVATE_PROMPT_CANARY", "PRIVATE_SECRET_CANARY"],
        );
    }

    #[test]
    fn directory_tree_assertion_reports_the_operation_and_added_path() {
        let sequence = TEMP_TREE_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        let tree = std::env::temp_dir().join(format!(
            "satelle-test-contract-{}-{sequence}",
            std::process::id()
        ));
        fs::create_dir(&tree).expect("temporary directory tree should be created");
        let failure = std::panic::catch_unwind(|| {
            assert_directory_tree_unchanged("maintenance dry run", &tree, || {
                fs::write(tree.join("unexpected-state.json"), b"mutated")
                    .expect("deliberate test mutation should be written");
            });
        });
        fs::remove_dir_all(&tree).expect("temporary directory tree should be removed");
        let failure = failure.expect_err("an added file must fail the unchanged assertion");
        let message = failure
            .downcast_ref::<String>()
            .expect("assertion panic should contain a string message");

        assert!(message.contains("maintenance dry run mutated directory tree"));
        assert!(message.contains("unexpected-state.json"));
    }

    #[test]
    fn directory_tree_assertion_reports_a_permission_change() {
        let sequence = TEMP_TREE_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        let tree = std::env::temp_dir().join(format!(
            "satelle-test-contract-{}-{sequence}",
            std::process::id()
        ));
        fs::create_dir(&tree).expect("temporary directory tree should be created");
        let canary = tree.join("permission-canary.txt");
        fs::write(&canary, b"unchanged bytes").expect("permission canary should be written");
        let original_permissions = fs::metadata(&canary)
            .expect("permission canary metadata should be readable")
            .permissions();
        let failure = std::panic::catch_unwind(|| {
            assert_directory_tree_unchanged("maintenance dry run", &tree, || {
                let mut changed_permissions = original_permissions.clone();
                changed_permissions.set_readonly(true);
                fs::set_permissions(&canary, changed_permissions)
                    .expect("permission canary should become read-only");
            });
        });
        fs::set_permissions(&canary, original_permissions)
            .expect("permission canary permissions should be restored");
        fs::remove_dir_all(&tree).expect("temporary directory tree should be removed");
        let failure = failure.expect_err("a permission change must fail the unchanged assertion");
        let message = failure
            .downcast_ref::<String>()
            .expect("assertion panic should contain a string message");

        assert!(message.contains("maintenance dry run mutated directory tree"));
        assert!(message.contains("permission-canary.txt"));
    }

    #[test]
    fn directory_tree_assertion_reports_a_transient_mutation() {
        let sequence = TEMP_TREE_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        let tree = std::env::temp_dir().join(format!(
            "satelle-test-contract-{}-{sequence}",
            std::process::id()
        ));
        fs::create_dir(&tree).expect("temporary directory tree should be created");
        let failure = std::panic::catch_unwind(|| {
            assert_directory_tree_unchanged("maintenance dry run", &tree, || {
                let transient = tree.join("transient-state.json");
                fs::write(&transient, b"mutated")
                    .expect("transient test mutation should be written");
                fs::remove_file(transient).expect("transient test mutation should be removed");
            });
        });
        fs::remove_dir_all(&tree).expect("temporary directory tree should be removed");
        let failure = failure.expect_err("a transient mutation must fail the unchanged assertion");
        let message = failure
            .downcast_ref::<String>()
            .expect("assertion panic should contain a string message");

        assert!(message.contains("maintenance dry run mutated directory tree"));
        assert!(message.contains("transient-state.json"));
    }

    #[test]
    fn mutation_barrier_is_removed_during_unwind() {
        let sequence = TEMP_TREE_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        let tree = std::env::temp_dir().join(format!(
            "satelle-test-contract-{}-{sequence}",
            std::process::id()
        ));
        fs::create_dir(&tree).expect("temporary directory tree should be created");

        let failure = std::panic::catch_unwind(|| {
            let _barrier = MutationBarrier::create("maintenance dry run", &tree);
            panic!("deliberate unwind after mutation barrier creation");
        });

        assert!(failure.is_err(), "the deliberate panic should unwind");
        assert_eq!(
            fs::read_dir(&tree)
                .expect("temporary directory tree should be readable")
                .count(),
            0,
            "the mutation barrier should be removed during unwind"
        );
        fs::remove_dir(&tree).expect("temporary directory tree should be removed");
    }

    #[rustfmt::skip]
    const VERSIONED_PAYLOAD_DRIVER_CASES: [VersionedPayloadContractCase<bool>; 2] = [
        versioned_payload_case("accepted payload case", true, Accept),
        versioned_payload_case("rejected payload case", false, Reject),
    ];

    fn reference_versioned_payload_outcome(
        fixture: &VersionedPayloadContractFixture,
    ) -> VersionedPayloadAdapterOutcome {
        let values = match fixture.framing {
            VersionedPayloadFraming::Json => serde_json::from_slice::<Value>(fixture.payload)
                .ok()
                .filter(Value::is_object)
                .map(|value| vec![value]),
            VersionedPayloadFraming::Ndjson => {
                let payload = fixture
                    .payload
                    .strip_suffix(b"\n")
                    .unwrap_or(fixture.payload);
                (!payload.is_empty())
                    .then(|| {
                        payload
                            .split(|byte| *byte == b'\n')
                            .map(|line| serde_json::from_slice::<Value>(line).ok())
                            .collect::<Option<Vec<_>>>()
                    })
                    .flatten()
                    .filter(|values| values.iter().all(Value::is_object))
            }
        };

        let accepted = fixture.expected_carrier == fixture.observed_carrier
            && values.is_some_and(|values| {
                values.iter().all(|value| {
                    let object = value
                        .as_object()
                        .expect("non-object payloads were rejected before validation");

                    object.get("schema_version").and_then(Value::as_str)
                        == Some(fixture.expected_schema_version)
                        && fixture
                            .required_fields
                            .iter()
                            .all(|field| object.contains_key(*field))
                        && fixture.enum_fields.iter().all(|enum_field| {
                            object
                                .get(enum_field.field)
                                .and_then(Value::as_str)
                                .is_some_and(|token| enum_field.allowed_tokens.contains(&token))
                        })
                })
            });

        if accepted {
            VersionedPayloadAdapterOutcome::Accepted
        } else {
            VersionedPayloadAdapterOutcome::Rejected
        }
    }

    #[test]
    fn versioned_payload_public_catalog_matches_reference_model() {
        let mut evaluated_cases = 0;

        assert_versioned_payload_contract(|fixture| {
            evaluated_cases += 1;
            Ok::<_, &str>(reference_versioned_payload_outcome(fixture))
        });

        assert_eq!(evaluated_cases, 15, "every versioned payload case must run");
    }

    #[test]
    fn versioned_payload_case_driver_accepts_matching_accept_and_reject_outcomes() {
        assert_versioned_payload_cases(&VERSIONED_PAYLOAD_DRIVER_CASES, |fixture| {
            Ok::<_, &str>(if *fixture {
                VersionedPayloadAdapterOutcome::Accepted
            } else {
                VersionedPayloadAdapterOutcome::Rejected
            })
        });
    }

    #[test]
    #[should_panic(expected = "versioned payload case 'rejected payload case' was accepted")]
    fn versioned_payload_case_driver_rejects_false_acceptance() {
        assert_versioned_payload_cases(&VERSIONED_PAYLOAD_DRIVER_CASES[1..], |_| {
            Ok::<_, &str>(VersionedPayloadAdapterOutcome::Accepted)
        });
    }

    #[test]
    #[should_panic(expected = "versioned payload case 'accepted payload case' was rejected")]
    fn versioned_payload_case_driver_rejects_false_rejection() {
        assert_versioned_payload_cases(&VERSIONED_PAYLOAD_DRIVER_CASES[..1], |_| {
            Ok::<_, &str>(VersionedPayloadAdapterOutcome::Rejected)
        });
    }

    #[test]
    #[should_panic(
        expected = "versioned payload case 'rejected payload case' failed before an adapter outcome: \"materialization failed\""
    )]
    fn versioned_payload_case_driver_rejects_harness_error() {
        assert_versioned_payload_cases(&VERSIONED_PAYLOAD_DRIVER_CASES[1..], |_| {
            Err::<VersionedPayloadAdapterOutcome, _>("materialization failed")
        });
    }

    const DRIVER_CASES: [ReleaseArchiveContractCase; 2] = [
        case(
            "accepted case",
            archive("accepted.tar.gz", TarGz, &[]),
            Accept,
        ),
        case(
            "rejected case",
            archive("rejected.tar.gz", TarGz, &[]),
            Reject,
        ),
    ];

    #[test]
    fn release_archive_case_driver_accepts_matching_accept_and_reject_outcomes() {
        assert_archive_cases(&DRIVER_CASES, |fixture| {
            Ok::<_, &str>(match fixture.filename {
                "accepted.tar.gz" => Accepted,
                "rejected.tar.gz" => Rejected,
                filename => panic!("unexpected driver fixture: {filename}"),
            })
        });
    }

    #[test]
    #[should_panic(expected = "archive case 'rejected case' was accepted")]
    fn release_archive_case_driver_rejects_false_acceptance() {
        assert_archive_cases(&DRIVER_CASES[1..], |_| Ok::<_, &str>(Accepted));
    }

    #[test]
    #[should_panic(expected = "archive case 'accepted case' was rejected")]
    fn release_archive_case_driver_rejects_false_rejection() {
        assert_archive_cases(&DRIVER_CASES[..1], |_| Ok::<_, &str>(Rejected));
    }

    #[test]
    #[should_panic(
        expected = "archive case 'rejected case' failed before a validator outcome: \"materialization failed\""
    )]
    fn release_archive_case_driver_rejects_harness_error() {
        assert_archive_cases(&DRIVER_CASES[1..], |_| {
            Err::<ReleaseArchiveValidation, _>("materialization failed")
        });
    }

    #[rustfmt::skip]
    const PROMOTION_DRIVER_CASES: [NpmPromotionContractCase<bool>; 2] = [
        promotion_case("accepted promotion case", true, Accept),
        promotion_case("rejected promotion case", false, Reject),
    ];

    #[test]
    fn npm_promotion_case_driver_accepts_matching_accept_and_reject_outcomes() {
        assert_npm_promotion_cases(&PROMOTION_DRIVER_CASES, |fixture| {
            Ok::<_, &str>(if *fixture {
                NpmPromotionAdapterOutcome::Accepted
            } else {
                NpmPromotionAdapterOutcome::Rejected
            })
        });
    }

    #[test]
    #[should_panic(expected = "npm promotion case 'rejected promotion case' was accepted")]
    fn npm_promotion_case_driver_rejects_false_acceptance() {
        assert_npm_promotion_cases(&PROMOTION_DRIVER_CASES[1..], |_| {
            Ok::<_, &str>(NpmPromotionAdapterOutcome::Accepted)
        });
    }

    #[test]
    #[should_panic(expected = "npm promotion case 'accepted promotion case' was rejected")]
    fn npm_promotion_case_driver_rejects_false_rejection() {
        assert_npm_promotion_cases(&PROMOTION_DRIVER_CASES[..1], |_| {
            Ok::<_, &str>(NpmPromotionAdapterOutcome::Rejected)
        });
    }

    #[test]
    #[should_panic(
        expected = "npm promotion case 'rejected promotion case' failed before an adapter outcome: \"materialization failed\""
    )]
    fn npm_promotion_case_driver_rejects_harness_error() {
        assert_npm_promotion_cases(&PROMOTION_DRIVER_CASES[1..], |_| {
            Err::<NpmPromotionAdapterOutcome, _>("materialization failed")
        });
    }

    #[rustfmt::skip]
    const ARCHIVE_NPM_PARITY_DRIVER_CASES: [ArchiveNpmParityContractCase<bool>; 2] = [
        archive_npm_parity_case("accepted parity case", true, Accept),
        archive_npm_parity_case("rejected parity case", false, Reject),
    ];

    const ARCHIVE_NPM_TARGET_PACKAGE_PAIRS: [(&str, &str); 6] = [
        ("linux-arm64-gnu", "@microck/satelle-linux-arm64-gnu"),
        ("linux-x64-gnu", "@microck/satelle-linux-x64-gnu"),
        ("darwin-arm64", "@microck/satelle-darwin-arm64"),
        ("darwin-x64", "@microck/satelle-darwin-x64"),
        ("win32-arm64-msvc", "@microck/satelle-win32-arm64-msvc"),
        ("win32-x64-msvc", "@microck/satelle-win32-x64-msvc"),
    ];

    #[test]
    fn archive_npm_parity_public_catalog_matches_pairwise_reference_model() {
        let mut evaluated_cases = 0;

        assert_archive_npm_executable_parity_contract(|fixture| {
            evaluated_cases += 1;

            let accepted = fixture.release_archives.len() == ARCHIVE_NPM_TARGET_PACKAGE_PAIRS.len()
                && fixture.npm_packages.len() == ARCHIVE_NPM_TARGET_PACKAGE_PAIRS.len()
                && ARCHIVE_NPM_TARGET_PACKAGE_PAIRS
                    .iter()
                    .all(|(target, package)| {
                        let Some(archive) = fixture
                            .release_archives
                            .iter()
                            .find(|archive| archive.target == *target)
                        else {
                            return false;
                        };
                        let Some(npm_package) = fixture
                            .npm_packages
                            .iter()
                            .find(|npm_package| npm_package.package == *package)
                        else {
                            return false;
                        };

                        archive.candidate_version == npm_package.candidate_version
                            && archive.executable_digest == npm_package.executable_digest
                    });

            Ok::<_, &str>(if accepted {
                ArchiveNpmParityAdapterOutcome::Accepted
            } else {
                ArchiveNpmParityAdapterOutcome::Rejected
            })
        });

        assert_eq!(evaluated_cases, 7, "every parity catalog case must run");
    }

    #[test]
    fn archive_npm_parity_case_driver_accepts_matching_accept_and_reject_outcomes() {
        assert_archive_npm_parity_cases(&ARCHIVE_NPM_PARITY_DRIVER_CASES, |fixture| {
            Ok::<_, &str>(if *fixture {
                ArchiveNpmParityAdapterOutcome::Accepted
            } else {
                ArchiveNpmParityAdapterOutcome::Rejected
            })
        });
    }

    #[test]
    #[should_panic(expected = "archive/npm parity case 'rejected parity case' was accepted")]
    fn archive_npm_parity_case_driver_rejects_false_acceptance() {
        assert_archive_npm_parity_cases(&ARCHIVE_NPM_PARITY_DRIVER_CASES[1..], |_| {
            Ok::<_, &str>(ArchiveNpmParityAdapterOutcome::Accepted)
        });
    }

    #[test]
    #[should_panic(expected = "archive/npm parity case 'accepted parity case' was rejected")]
    fn archive_npm_parity_case_driver_rejects_false_rejection() {
        assert_archive_npm_parity_cases(&ARCHIVE_NPM_PARITY_DRIVER_CASES[..1], |_| {
            Ok::<_, &str>(ArchiveNpmParityAdapterOutcome::Rejected)
        });
    }

    #[test]
    #[should_panic(
        expected = "archive/npm parity case 'rejected parity case' failed before an adapter outcome: \"materialization failed\""
    )]
    fn archive_npm_parity_case_driver_rejects_harness_error() {
        assert_archive_npm_parity_cases(&ARCHIVE_NPM_PARITY_DRIVER_CASES[1..], |_| {
            Err::<ArchiveNpmParityAdapterOutcome, _>("materialization failed")
        });
    }
}
