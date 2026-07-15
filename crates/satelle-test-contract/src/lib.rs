use std::{fmt::Debug, process::Output};

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
    let prefix = format!("error: {expected_code}\n");
    assert!(raw.starts_with(&prefix), "unexpected human error: {raw}");
    assert!(
        !raw[prefix.len()..].trim().is_empty(),
        "human errors must include a message"
    );
    assert!(
        !raw.trim_start().starts_with('{'),
        "human errors must not use JSON framing"
    );
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

#[cfg(test)]
mod tests {
    use super::*;

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
}
