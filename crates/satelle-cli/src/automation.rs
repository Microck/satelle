use crate::error_output::error_envelope;
use crate::output::has_explicit_output_selector;
use crate::{Cli, Command as SatelleCommand};
use clap::{Args, CommandFactory, FromArgMatches};
use satelle_core::SatelleError;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::fs::File;
use std::io::{self, BufRead, BufReader, Write};
use std::path::PathBuf;
use std::process::{Command as ProcessCommand, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Instant;

const BATCH_REQUEST_SCHEMA_VERSION: &str = "satelle.batch.request.v1";
const BATCH_RESULT_SCHEMA_VERSION: &str = "satelle.batch.result.v1";
const BATCH_SUMMARY_SCHEMA_VERSION: &str = "satelle.batch.summary.v1";

#[derive(Args, Debug)]
pub(crate) struct BatchCommand {
    /// NDJSON request file, or - for standard input.
    #[arg(long, value_name = "PATH_OR_DASH")]
    input: String,
    /// Maximum commands executed at once.
    #[arg(long, default_value_t = 4, value_parser = parse_batch_concurrency)]
    concurrency: usize,
}

fn parse_batch_concurrency(raw: &str) -> Result<usize, String> {
    let value = raw
        .parse::<usize>()
        .map_err(|_| "concurrency must be an integer from 1 through 16".to_string())?;
    (1..=16)
        .contains(&value)
        .then_some(value)
        .ok_or_else(|| "concurrency must be from 1 through 16".to_string())
}

#[derive(Clone)]
pub(crate) struct BatchContext {
    executable: PathBuf,
    profile: Option<String>,
    no_color: bool,
}

impl BatchContext {
    pub(crate) fn current(profile: Option<&str>, no_color: bool) -> Result<Self, SatelleError> {
        let executable = std::env::current_exe().map_err(|error| {
            SatelleError::invalid_usage(format!("could not locate the Satelle executable: {error}"))
        })?;
        Ok(Self {
            executable,
            profile: profile.map(str::to_string),
            no_color,
        })
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct BatchRequest {
    schema_version: String,
    request_id: String,
    arguments: Vec<String>,
}

#[derive(Debug)]
struct IndexedRequest {
    index: usize,
    state: RequestState,
}

#[derive(Debug)]
enum RequestState {
    Ready(BatchRequest),
    Rejected {
        request_id: Option<String>,
        error: Value,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
enum BatchResultStatus {
    Success,
    Failure,
}

#[derive(Debug, Serialize)]
struct BatchResult {
    schema_version: &'static str,
    index: usize,
    request_id: Option<String>,
    status: BatchResultStatus,
    exit_code: Option<i32>,
    duration_ms: u64,
    output: Vec<Value>,
    errors: Vec<Value>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
enum BatchSummaryStatus {
    Completed,
    CompletedWithFailures,
}

#[derive(Debug, Serialize)]
struct BatchSummary {
    schema_version: &'static str,
    status: BatchSummaryStatus,
    total: usize,
    succeeded: usize,
    failed: usize,
    concurrency: usize,
    duration_ms: u64,
}

pub(crate) struct BatchRunStatus {
    pub(crate) failed: usize,
}

pub(crate) fn run_batch(
    command: BatchCommand,
    context: BatchContext,
) -> Result<BatchRunStatus, SatelleError> {
    let started = Instant::now();
    let requests = if command.input == "-" {
        read_requests(io::stdin().lock())?
    } else {
        let file = File::open(&command.input).map_err(|error| {
            SatelleError::invalid_usage(format!(
                "could not open batch input '{}': {error}",
                command.input
            ))
        })?;
        read_requests(BufReader::new(file))?
    };

    let mut succeeded = 0;
    let mut failed = 0;
    let stdout = io::stdout();
    let mut writer = stdout.lock();
    // Workers claim the next input slot as they become free. Results are put
    // back into indexed slots so one slow command does not idle the pool or
    // change the output order.
    let next_request = AtomicUsize::new(0);
    let worker_count = command.concurrency.min(requests.len());
    let completed = std::thread::scope(|scope| {
        let workers = (0..worker_count)
            .map(|_| {
                let next_request = &next_request;
                let requests = &requests;
                let context = &context;
                scope.spawn(move || {
                    let mut completed = Vec::new();
                    loop {
                        let index = next_request.fetch_add(1, Ordering::Relaxed);
                        let Some(request) = requests.get(index) else {
                            break;
                        };
                        completed.push((index, execute_request(request, context)));
                    }
                    completed
                })
            })
            .collect::<Vec<_>>();
        workers
            .into_iter()
            .flat_map(|worker| worker.join().expect("batch command worker must not panic"))
            .collect::<Vec<_>>()
    });
    let mut ordered_results = (0..requests.len()).map(|_| None).collect::<Vec<_>>();
    for (index, result) in completed {
        ordered_results[index] = Some(result);
    }
    for result in ordered_results {
        let result = result.expect("every batch request must produce one result");
        if result.status == BatchResultStatus::Success {
            succeeded += 1;
        } else {
            failed += 1;
        }
        write_record(&mut writer, &result)?;
    }

    write_record(
        &mut writer,
        &BatchSummary {
            schema_version: BATCH_SUMMARY_SCHEMA_VERSION,
            status: if failed == 0 {
                BatchSummaryStatus::Completed
            } else {
                BatchSummaryStatus::CompletedWithFailures
            },
            total: requests.len(),
            succeeded,
            failed,
            concurrency: command.concurrency,
            duration_ms: elapsed_millis(started),
        },
    )?;
    Ok(BatchRunStatus { failed })
}

fn read_requests(reader: impl BufRead) -> Result<Vec<IndexedRequest>, SatelleError> {
    reader
        .lines()
        .enumerate()
        .map(|(index, line)| {
            let line = line.map_err(|error| {
                SatelleError::invalid_usage(format!(
                    "could not read batch input line {}: {error}",
                    index + 1
                ))
            })?;
            Ok(parse_request(index, &line))
        })
        .collect()
}

fn parse_request(index: usize, line: &str) -> IndexedRequest {
    let state = match serde_json::from_str::<BatchRequest>(line) {
        Ok(request) => {
            let request_id = Some(request.request_id.clone());
            match validate_request(index, request) {
                Ok(request) => RequestState::Ready(request),
                Err(error) => RequestState::Rejected { request_id, error },
            }
        }
        Err(error) => RequestState::Rejected {
            request_id: None,
            error: error_envelope(&SatelleError::invalid_usage(format!(
                "batch input line {} is not a valid {BATCH_REQUEST_SCHEMA_VERSION} object: {error}",
                index + 1
            ))),
        },
    };
    IndexedRequest { index, state }
}

fn validate_request(index: usize, request: BatchRequest) -> Result<BatchRequest, Value> {
    let invalid = |message: String| error_envelope(&SatelleError::invalid_usage(message));
    if request.schema_version != BATCH_REQUEST_SCHEMA_VERSION {
        return Err(invalid(format!(
            "batch input line {} uses unsupported schema_version '{}'",
            index + 1,
            request.schema_version
        )));
    }
    if request.request_id.is_empty() {
        return Err(invalid(format!(
            "batch input line {} requires a non-empty request_id",
            index + 1
        )));
    }
    if request.arguments.is_empty() {
        return Err(invalid(format!(
            "batch input line {} requires at least one command argument",
            index + 1
        )));
    }
    let arguments = std::iter::once("satelle").chain(request.arguments.iter().map(String::as_str));
    let matches = Cli::command()
        .try_get_matches_from(arguments)
        .map_err(|_| {
            invalid(format!(
                "batch input line {} contains invalid Satelle arguments",
                index + 1
            ))
        })?;
    if has_explicit_output_selector(&matches) {
        return Err(invalid(format!(
            "batch input line {} cannot override machine output selectors",
            index + 1
        )));
    }
    let parsed = Cli::from_arg_matches(&matches).map_err(|_| {
        invalid(format!(
            "batch input line {} contains invalid Satelle arguments",
            index + 1
        ))
    })?;
    if matches!(parsed.command, SatelleCommand::Batch(_)) {
        return Err(invalid(format!(
            "batch input line {} cannot start another automation workflow",
            index + 1
        )));
    }
    Ok(request)
}

fn execute_request(indexed: &IndexedRequest, context: &BatchContext) -> BatchResult {
    let started = Instant::now();
    let request = match &indexed.state {
        RequestState::Ready(request) => request,
        RequestState::Rejected { request_id, error } => {
            return BatchResult {
                schema_version: BATCH_RESULT_SCHEMA_VERSION,
                index: indexed.index,
                request_id: request_id.clone(),
                status: BatchResultStatus::Failure,
                exit_code: Some(64),
                duration_ms: elapsed_millis(started),
                output: Vec::new(),
                errors: vec![error.clone()],
            };
        }
    };

    let mut child = ProcessCommand::new(&context.executable);
    if context.no_color {
        child.arg("--no-color");
    }
    if let Some(profile) = &context.profile {
        child.arg("--profile").arg(profile);
    }
    child
        .args(["--error-format", "json"])
        .args(&request.arguments)
        .args(["--format", "compact-json"])
        .stdin(Stdio::null());
    match child.output() {
        Ok(output) => {
            let (output_values, output_error) = match json_values(&output.stdout, "standard output")
            {
                Ok(values) => (values, None),
                Err(error) => (Vec::new(), Some(error)),
            };
            let mut error_values = match json_values(&output.stderr, "standard error") {
                Ok(values) => values,
                Err(error) => vec![error],
            };
            if let Some(error) = output_error {
                error_values.push(error);
            }
            let contract_failed = !output.status.success() || !error_values.is_empty();
            BatchResult {
                schema_version: BATCH_RESULT_SCHEMA_VERSION,
                index: indexed.index,
                request_id: Some(request.request_id.clone()),
                status: if !contract_failed {
                    BatchResultStatus::Success
                } else {
                    BatchResultStatus::Failure
                },
                exit_code: output.status.code(),
                duration_ms: elapsed_millis(started),
                output: output_values,
                errors: error_values,
            }
        }
        Err(error) => BatchResult {
            schema_version: BATCH_RESULT_SCHEMA_VERSION,
            index: indexed.index,
            request_id: Some(request.request_id.clone()),
            status: BatchResultStatus::Failure,
            exit_code: None,
            duration_ms: elapsed_millis(started),
            output: Vec::new(),
            errors: vec![error_envelope(&SatelleError::invalid_usage(format!(
                "could not execute batch item: {error}"
            )))],
        },
    }
}

fn json_values(bytes: &[u8], stream_name: &str) -> Result<Vec<Value>, Value> {
    serde_json::Deserializer::from_slice(bytes)
        .into_iter::<Value>()
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| {
            error_envelope(&SatelleError::invalid_usage(format!(
                "batch item produced invalid JSON on {stream_name}: {error}"
            )))
        })
}

fn elapsed_millis(started: Instant) -> u64 {
    u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX)
}

fn write_record(writer: &mut impl Write, value: &impl Serialize) -> Result<(), SatelleError> {
    serde_json::to_writer(&mut *writer, value).map_err(|error| {
        SatelleError::invalid_usage(format!("could not encode batch output: {error}"))
    })?;
    writeln!(writer).map_err(|error| {
        SatelleError::invalid_usage(format!("could not write batch output: {error}"))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_recursive_workflows_and_output_overrides() {
        for arguments in [
            vec!["batch", "--input", "work.ndjson"],
            vec!["--no-color", "batch", "--input", "work.ndjson"],
            vec!["status", "rs_example", "--json"],
        ] {
            let line = serde_json::json!({
                "schema_version": BATCH_REQUEST_SCHEMA_VERSION,
                "request_id": "item-1",
                "arguments": arguments,
            })
            .to_string();
            assert!(matches!(
                parse_request(0, &line).state,
                RequestState::Rejected { .. }
            ));
        }
    }

    #[test]
    fn accepts_one_closed_request_object() {
        let line = serde_json::json!({
            "schema_version": BATCH_REQUEST_SCHEMA_VERSION,
            "request_id": "item-1",
            "arguments": ["status", "rs_example"],
        })
        .to_string();
        let RequestState::Ready(request) = parse_request(0, &line).state else {
            panic!("request should be valid");
        };
        assert_eq!(request.request_id, "item-1");
        assert_eq!(request.arguments[0], "status");
    }

    #[test]
    fn output_like_prompt_text_after_the_delimiter_is_not_an_option() {
        let line = serde_json::json!({
            "schema_version": BATCH_REQUEST_SCHEMA_VERSION,
            "request_id": "item-1",
            "arguments": ["run", "--host", "office", "--", "--format"],
        })
        .to_string();
        assert!(matches!(
            parse_request(0, &line).state,
            RequestState::Ready(_)
        ));
    }

    #[test]
    fn invalid_child_output_becomes_a_typed_error_without_copying_raw_bytes() {
        let canary = "PRIVATE_CHILD_OUTPUT_CANARY";
        let error = json_values(canary.as_bytes(), "standard output")
            .expect_err("plain text must not satisfy the child output contract");
        assert_eq!(error["code"], "invalid-usage");
        assert!(!error.to_string().contains(canary));
    }
}
