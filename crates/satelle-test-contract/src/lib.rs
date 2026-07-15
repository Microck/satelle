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
}
