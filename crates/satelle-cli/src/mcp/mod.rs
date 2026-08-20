mod arguments;
pub(crate) mod install;
mod mutation;
#[path = "output-schema.rs"]
mod output_schema;
mod result;
mod schema;
mod stdio;

use super::logs::read_logs_for_host;
use super::read;
use super::{CliFailure, ConfigContext, SelectedHost};
use arguments::{
    ConfigCheckInput, ConfigExplainInput, DoctorInput, HostInput, HostLifecycleInput,
    HostUpdateInput, LogsInput, RepairInput, RunInput, SetupInput, StatusInput, SteerInput,
    StopInput, decode, invalid_params, validate_doctor_scope, validate_host,
};
use result::{operational_error, structured};
use rmcp::handler::server::ServerHandler;
use rmcp::model::{
    CallToolRequestParams, CallToolResult, ContentBlock, Implementation, ListToolsResult,
    PaginatedRequestParams, ProtocolVersion, ServerCapabilities, ServerInfo, Tool,
};
use rmcp::service::{QuitReason, RequestContext};
use rmcp::{ErrorData as McpError, RoleServer, ServiceExt};
use satelle_core::{ErrorCode, SatelleError, SessionId, TransportKind};
use serde_json::Value;
use std::future::Future;
use std::str::FromStr;
use std::sync::Arc;

pub(super) fn serve(profile: Option<&str>, enable_mutations: bool) -> Result<(), CliFailure> {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(|error| mcp_failure(format!("could not start the MCP runtime: {error}")))?;
    runtime
        .block_on(serve_async(profile.map(str::to_owned), enable_mutations))
        .map_err(mcp_failure)
}

async fn serve_async(profile: Option<String>, enable_mutations: bool) -> Result<(), String> {
    let server = SatelleMcp::new(profile, enable_mutations)?;
    let (reader, writer, framer) = stdio::BoundedStdio::start().into_parts();
    let running = match server.serve((reader, writer)).await {
        Ok(running) => running,
        Err(error) => {
            return match stdio::stop_framer(framer).await {
                Err(framing) => Err(framing.to_string()),
                Ok(()) => Err(format!("MCP initialization did not complete: {error}")),
            };
        }
    };

    let service_result = service_result(running.waiting().await);
    let framing_result = stdio::stop_framer(framer)
        .await
        .map_err(|error| error.to_string());
    framing_result?;
    service_result?;
    Ok(())
}

fn service_result(result: Result<QuitReason, tokio::task::JoinError>) -> Result<(), String> {
    match result {
        Ok(QuitReason::Closed) => Ok(()),
        Ok(QuitReason::Cancelled) => Err("MCP server task was cancelled".to_string()),
        Ok(QuitReason::JoinError(error)) => Err(format!("MCP server request task failed: {error}")),
        Ok(reason) => Err(format!("MCP server stopped unexpectedly: {reason:?}")),
        Err(error) => Err(format!("MCP server task failed: {error}")),
    }
}

fn mcp_failure(message: impl Into<String>) -> CliFailure {
    CliFailure {
        error: SatelleError {
            code: ErrorCode::InvalidUsage,
            message: message.into(),
            recovery_command: None,
            source_detail: None,
            details: Default::default(),
        },
        history_session_id: None,
        error_reported: false,
        exit_code_override: None,
    }
}

#[derive(Clone)]
struct SatelleMcp {
    profile: Option<String>,
    executable: Arc<std::path::PathBuf>,
    tools: Arc<Vec<Tool>>,
    local_state_gate: Arc<tokio::sync::Mutex<()>>,
    enable_mutations: bool,
}

impl SatelleMcp {
    fn new(profile: Option<String>, enable_mutations: bool) -> Result<Self, String> {
        // Capture the installed path before a self-update can replace the running inode. On Linux,
        // resolving /proc/self/exe after replacement returns the unlinked old executable instead.
        let executable = std::env::current_exe()
            .map_err(|error| format!("could not resolve Satelle executable: {error}"))?;
        Ok(Self {
            profile,
            executable: Arc::new(executable),
            tools: Arc::new(schema::tools(enable_mutations)),
            local_state_gate: Arc::new(tokio::sync::Mutex::new(())),
            enable_mutations,
        })
    }

    fn config(&self) -> ConfigContext<'_> {
        ConfigContext::new(self.profile.as_deref())
    }

    async fn call(
        &self,
        request: CallToolRequestParams,
        context: RequestContext<RoleServer>,
    ) -> Result<CallToolResult, McpError> {
        let arguments = request.arguments.unwrap_or_default();
        match request.name.as_ref() {
            "config_check" => {
                let input: ConfigCheckInput = decode(arguments)?;
                validate_host(input.host.as_deref())?;
                self.operation(read::config_check_report(
                    input.host,
                    input.all,
                    self.config(),
                ))
            }
            "config_explain" => {
                let input: ConfigExplainInput = decode(arguments)?;
                validate_host(input.host.as_deref())?;
                self.operation(read::config_explain_report(
                    input.host,
                    input.show_secret_references,
                    self.config(),
                ))
            }
            "paths" => {
                let input: HostInput = decode(arguments)?;
                validate_host(input.host.as_deref())?;
                let Some(alias) = input.host.as_deref() else {
                    return self.operation(read::paths_report(None));
                };
                let host = match self.config().resolve_host(Some(alias)) {
                    Ok(host) => host,
                    Err(failure) => return Ok(operational_error(failure.error)),
                };
                let paths = match self
                    .host_read(host, &context, |host| read::paths_report(Some(host)))
                    .await?
                {
                    Ok(paths) => paths,
                    Err(failure) => return Ok(operational_error(failure.error)),
                };
                Ok(structured(paths, false))
            }
            "status" => {
                let input: StatusInput = decode(arguments)?;
                validate_host(input.host.as_deref())?;
                let session_id = SessionId::from_str(&input.session_id)
                    .map_err(|error| invalid_params(error.to_string()))?;
                let host = match self.config().resolve_host(input.host.as_deref()) {
                    Ok(host) => host,
                    Err(failure) => return Ok(operational_error(failure.error)),
                };
                let host_alias = host.alias.clone();
                let session = match self
                    .host_read(host, &context, move |host| {
                        read::status_for_host(&session_id, host)
                    })
                    .await?
                {
                    Ok(result) => result,
                    Err(failure) => return Ok(operational_error(failure.error)),
                };
                let value = read::status_value(&session, &host_alias)
                    .map_err(|error| McpError::internal_error(error.to_string(), None))?;
                Ok(structured(value, false))
            }
            "logs" => {
                let input: LogsInput = decode(arguments)?;
                input.validate()?;
                let request = input.into_request();
                let host = match self.config().resolve_host(request.host.as_deref()) {
                    Ok(host) => host,
                    Err(failure) => return Ok(operational_error(failure.error)),
                };
                let entries = match self
                    .host_read(host, &context, move |host| {
                        read_logs_for_host(&request, host)
                    })
                    .await?
                {
                    Ok(entries) => entries,
                    Err(failure) => return Ok(operational_error(failure.error)),
                };
                let mut text = String::new();
                for entry in entries {
                    text.push_str(
                        &serde_json::to_string(&entry)
                            .map_err(|error| McpError::internal_error(error.to_string(), None))?,
                    );
                    text.push('\n');
                }
                Ok(CallToolResult::success(vec![ContentBlock::text(text)]))
            }
            "doctor" => {
                let input: DoctorInput = decode(arguments)?;
                validate_host(input.host.as_deref())?;
                validate_doctor_scope(input.scope.as_deref())?;
                let host = match self.config().resolve_host(input.host.as_deref()) {
                    Ok(host) => host,
                    Err(failure) => return Ok(operational_error(failure.error)),
                };
                let report = match self
                    .host_read(host, &context, move |host| {
                        read::doctor_for_host(host, input.scope.as_deref())
                    })
                    .await?
                {
                    Ok(report) => report,
                    Err(failure) => return Ok(operational_error(failure.error)),
                };
                let blocked = !report.summary.ready;
                let value = serde_json::to_value(report)
                    .map_err(|error| McpError::internal_error(error.to_string(), None))?;
                Ok(structured(value, blocked))
            }
            "host_status" => {
                let input: HostInput = decode(arguments)?;
                validate_host(input.host.as_deref())?;
                let host = match self.config().resolve_host(input.host.as_deref()) {
                    Ok(host) => host,
                    Err(failure) => return Ok(operational_error(failure.error)),
                };
                let status = match self
                    .host_read(host, &context, read::host_status_for_host)
                    .await?
                {
                    Ok(status) => status,
                    Err(failure) => return Ok(operational_error(failure.error)),
                };
                let text = serde_json::to_string(&status)
                    .map_err(|error| McpError::internal_error(error.to_string(), None))?;
                Ok(CallToolResult::success(vec![ContentBlock::text(text)]))
            }
            "host_sessions" => {
                let input: HostInput = decode(arguments)?;
                validate_host(input.host.as_deref())?;
                let host = match self.config().resolve_host(input.host.as_deref()) {
                    Ok(host) => host,
                    Err(failure) => return Ok(operational_error(failure.error)),
                };
                let report = match self
                    .host_read(host, &context, |host| {
                        read::host_sessions_for_host(host, true)
                    })
                    .await?
                {
                    Ok(report) => report,
                    Err(failure) => return Ok(operational_error(failure.error)),
                };
                let value = serde_json::to_value(report)
                    .map_err(|error| McpError::internal_error(error.to_string(), None))?;
                Ok(structured(value, false))
            }
            "run" if self.enable_mutations => {
                if context.ct.is_cancelled() {
                    return Err(cancelled_request());
                }
                let input = decode::<RunInput>(arguments)?;
                input.validate()?;
                mutation::run(
                    self.executable.clone(),
                    input,
                    self.profile.clone(),
                    context.ct.cancelled(),
                )
                .await
            }
            "steer" if self.enable_mutations => {
                if context.ct.is_cancelled() {
                    return Err(cancelled_request());
                }
                let input = decode::<SteerInput>(arguments)?;
                input.validate()?;
                mutation::steer(
                    self.executable.clone(),
                    input,
                    self.profile.clone(),
                    context.ct.cancelled(),
                )
                .await
            }
            "stop" if self.enable_mutations => {
                if context.ct.is_cancelled() {
                    return Err(cancelled_request());
                }
                let input = decode::<StopInput>(arguments)?;
                input.validate()?;
                mutation::stop(
                    self.executable.clone(),
                    input,
                    self.profile.clone(),
                    context.ct.cancelled(),
                )
                .await
            }
            "setup" if self.enable_mutations => {
                if context.ct.is_cancelled() {
                    return Err(cancelled_request());
                }
                let input = decode::<SetupInput>(arguments)?;
                input.validate()?;
                mutation::setup(
                    self.executable.clone(),
                    input,
                    self.profile.clone(),
                    context.ct.cancelled(),
                )
                .await
            }
            "repair" if self.enable_mutations => {
                if context.ct.is_cancelled() {
                    return Err(cancelled_request());
                }
                let input = decode::<RepairInput>(arguments)?;
                input.validate()?;
                mutation::repair(
                    self.executable.clone(),
                    input,
                    self.profile.clone(),
                    context.ct.cancelled(),
                )
                .await
            }
            "host_update" if self.enable_mutations => {
                if context.ct.is_cancelled() {
                    return Err(cancelled_request());
                }
                let input = decode::<HostUpdateInput>(arguments)?;
                input.validate()?;
                mutation::host_update(
                    self.executable.clone(),
                    input,
                    self.profile.clone(),
                    context.ct.cancelled(),
                )
                .await
            }
            "host_lifecycle" if self.enable_mutations => {
                if context.ct.is_cancelled() {
                    return Err(cancelled_request());
                }
                let input = decode::<HostLifecycleInput>(arguments)?;
                input.validate()?;
                mutation::host_lifecycle(
                    self.executable.clone(),
                    input,
                    self.profile.clone(),
                    context.ct.cancelled(),
                )
                .await
            }
            _ => Err(invalid_params("unknown Satelle MCP tool")),
        }
    }

    fn operation(&self, result: Result<Value, CliFailure>) -> Result<CallToolResult, McpError> {
        Ok(match result {
            Ok(value) => structured(value, false),
            Err(failure) => operational_error(failure.error),
        })
    }

    async fn host_read<T, F>(
        &self,
        host: SelectedHost,
        context: &RequestContext<RoleServer>,
        read: F,
    ) -> Result<Result<T, CliFailure>, McpError>
    where
        T: Send + 'static,
        F: FnOnce(&SelectedHost) -> Result<T, CliFailure> + Send + 'static,
    {
        let state_guard = self.host_state_guard(&host, context).await?;
        // A direct transport owns a Tokio runtime, so its construction and
        // destruction must both stay outside rmcp's async request task. Move
        // the local-state guard too, so cancellation cannot release the gate
        // while an already-dispatched blocking read is still running.
        tokio::task::spawn_blocking(move || {
            let _state_guard = state_guard;
            read(&host)
        })
        .await
        .map_err(|error| {
            McpError::internal_error(format!("MCP Host read task failed: {error}"), None)
        })
    }

    async fn host_state_guard(
        &self,
        host: &SelectedHost,
        context: &RequestContext<RoleServer>,
    ) -> Result<Option<tokio::sync::OwnedMutexGuard<()>>, McpError> {
        let guard = self
            .local_state_guard(
                host.config.transport == TransportKind::Local,
                context.ct.cancelled(),
            )
            .await?;
        if context.ct.is_cancelled() {
            return Err(cancelled_request());
        }
        Ok(guard)
    }

    async fn local_state_guard<F>(
        &self,
        local_state_backed: bool,
        cancellation: F,
    ) -> Result<Option<tokio::sync::OwnedMutexGuard<()>>, McpError>
    where
        F: Future<Output = ()>,
    {
        if !local_state_backed {
            return Ok(None);
        }
        tokio::pin!(cancellation);
        let guard = tokio::select! {
            biased;
            _ = &mut cancellation => return Err(cancelled_request()),
            guard = Arc::clone(&self.local_state_gate).lock_owned() => guard,
        };
        Ok(Some(guard))
    }
}

fn cancelled_request() -> McpError {
    McpError::internal_error("MCP tool request was cancelled", None)
}

impl ServerHandler for SatelleMcp {
    fn get_info(&self) -> ServerInfo {
        ServerInfo::new(ServerCapabilities::builder().enable_tools().build())
            .with_server_info(Implementation::new("satelle", env!("CARGO_PKG_VERSION")))
            .with_protocol_version(ProtocolVersion::V_2025_06_18)
    }

    fn get_tool(&self, name: &str) -> Option<Tool> {
        self.tools
            .iter()
            .find(|tool| tool.name.as_ref() == name)
            .cloned()
    }

    async fn list_tools(
        &self,
        _request: Option<PaginatedRequestParams>,
        _context: RequestContext<RoleServer>,
    ) -> Result<ListToolsResult, McpError> {
        Ok(ListToolsResult::with_all_items(self.tools.as_ref().clone()))
    }

    async fn call_tool(
        &self,
        request: CallToolRequestParams,
        context: RequestContext<RoleServer>,
    ) -> Result<CallToolResult, McpError> {
        self.call(request, context).await
    }
}

#[cfg(test)]
mod tests;
