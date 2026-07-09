#[path = "test-runtime/diagnostics.rs"]
mod diagnostics;

use crate::runtime::{
    AdapterReadiness, AdapterSubject, ComputerUseAdapter, ExecuteRequest, ExecuteResult,
    RecoveryObservation,
};
use crate::{HostService, HostSessionsReport};
use satelle_core::session::{
    ApprovalPolicy, DesktopBindingRef, DesktopTarget, EffectiveModelRef, ExecutionPolicy,
    ExperimentalFeatureChoices, FeatureChoice, ProviderBindingRef, SandboxPolicy, StopObservation,
    TimeoutPolicy, TurnTransition,
};
use satelle_core::{
    DaemonPathOverrides, DoctorReport, EventSource, EventSubject, EventType, LOCAL_DEMO_HOST,
    SatelleError, SatelleEvent, SatelleEventBody, SetupReport,
};
use serde_json::{Value, json};
use time::OffsetDateTime;

impl HostService {
    pub(super) fn fake_doctor(
        &self,
        host: &str,
        scope: Option<&str>,
        refresh: bool,
        adapter: &FakeComputerUseAdapter,
    ) -> Result<DoctorReport, SatelleError> {
        diagnostics::doctor(host, scope, refresh, adapter)
    }

    pub(super) fn setup_fake(
        &self,
        host: &str,
        dry_run: bool,
        setup_mode: String,
        setup_components: Vec<String>,
        daemon_path_overrides: DaemonPathOverrides,
    ) -> Result<SetupReport, SatelleError> {
        Ok(diagnostics::setup(
            host,
            dry_run,
            setup_mode,
            setup_components,
            daemon_path_overrides,
        ))
    }

    pub(super) fn host_sessions_fake(
        &self,
        host: &str,
        no_bootstrap: bool,
    ) -> Result<HostSessionsReport, SatelleError> {
        if host != LOCAL_DEMO_HOST {
            return Err(SatelleError::not_implemented(format!(
                "host '{host}' is configured, but only local-demo execution is implemented"
            )));
        }
        let bootstrap_actions = if no_bootstrap {
            Vec::new()
        } else {
            vec!["direct local-demo host daemon already reachable".to_string()]
        };
        Ok(HostSessionsReport {
            schema_version: 1,
            host: host.to_string(),
            connection_mode: "direct".to_string(),
            bootstrapped: false,
            bootstrap_actions,
            host_daemon_version: env!("CARGO_PKG_VERSION").to_string(),
            sessions: vec![satelle_core::DesktopSessionRecord {
                session_id: "local-demo-console".to_string(),
                desktop_user: "local-demo-user".to_string(),
                state: "active".to_string(),
                session_kind: "visible_desktop".to_string(),
                is_console: true,
                is_remote: false,
                display_summary: "active local demo visible desktop".to_string(),
                portable_selectors: vec!["console".to_string(), "active".to_string()],
                native_selectors: vec!["local-demo:console:active".to_string()],
                selected_by_current_config: true,
            }],
        })
    }
}

#[derive(Clone, Debug)]
pub(super) struct FakeComputerUseAdapter;

impl ComputerUseAdapter for FakeComputerUseAdapter {
    fn preflight(&self, _host: &str) -> Result<AdapterReadiness, SatelleError> {
        let desktop_binding = DesktopBindingRef::new("local-demo-desktop-v1")
            .map_err(|_| adapter_configuration_error("desktop binding"))?;
        let execution_policy = ExecutionPolicy::new(
            EffectiveModelRef::new("fake-model-v1")
                .map_err(|_| adapter_configuration_error("model binding"))?,
            ProviderBindingRef::new("fake-provider-v1")
                .map_err(|_| adapter_configuration_error("provider binding"))?,
            DesktopTarget::new(desktop_binding.clone()),
            ApprovalPolicy::OnRequest,
            SandboxPolicy::WorkspaceWrite,
            TimeoutPolicy::bounded_seconds(120)
                .map_err(|_| adapter_configuration_error("timeout policy"))?,
            ExperimentalFeatureChoices::new(FeatureChoice::Enabled, FeatureChoice::Disabled),
        );
        Ok(AdapterReadiness::ready(
            "fake",
            "fake native computer-use adapter is ready for local demo",
            desktop_binding,
            execution_policy,
        ))
    }

    fn execute(&self, request: ExecuteRequest<'_>) -> Result<ExecuteResult, SatelleError> {
        let subject = request.subject();
        if !subject.host_identity().as_str().starts_with("host-")
            || !subject.has_request_token()
            || subject.has_upstream_references()
        {
            return Err(adapter_configuration_error("admitted work identity"));
        }
        let _private_prompt = request.prompt();
        Ok(ExecuteResult::new(
            TurnTransition::Completed,
            events(request.host(), subject),
        ))
    }

    fn observe_stop(&self, _subject: AdapterSubject<'_>) -> Result<StopObservation, SatelleError> {
        Ok(StopObservation::UpstreamInactiveConfirmed)
    }

    fn observe_recovery(
        &self,
        _subject: AdapterSubject<'_>,
    ) -> Result<RecoveryObservation, SatelleError> {
        // A fresh CLI process cannot prove that the prior deterministic owner
        // is alive. Keep durable ownership until an explicit stop resolves it.
        Ok(RecoveryObservation::Unknown)
    }
}

fn events(host: &str, subject: AdapterSubject<'_>) -> Vec<SatelleEvent> {
    vec![
        event(
            EventType::Preflight,
            1,
            host,
            subject,
            "resolved local demo host",
            json!({"transport": "local", "adapter": "fake"}),
        ),
        event(
            EventType::Readiness,
            2,
            host,
            subject,
            "fake computer-use adapter is ready",
            json!({"ready": true}),
        ),
        event(
            EventType::TurnStarted,
            3,
            host,
            subject,
            "started fake computer-use turn",
            json!({}),
        ),
        event(
            EventType::TurnProgress,
            4,
            host,
            subject,
            "fake adapter observed a visible desktop",
            json!({"observation": "browser title would be read by a real adapter"}),
        ),
        event(
            EventType::TurnCompleted,
            5,
            host,
            subject,
            "completed fake computer-use turn",
            json!({"summary": "fake computer-use turn completed"}),
        ),
    ]
}

fn event(
    event_type: EventType,
    seq: u64,
    host: &str,
    subject: AdapterSubject<'_>,
    message: &str,
    data: Value,
) -> SatelleEvent {
    SatelleEventBody::new(
        event_type,
        EventSource::HostDaemon,
        OffsetDateTime::now_utc(),
        host,
        Some(EventSubject::Turn {
            session_id: subject.session_id().clone(),
            turn_id: subject.turn_id().clone(),
            session_state_revision: subject.session_state_revision(),
            turn_state_revision: subject.turn_state_revision(),
        }),
        message,
        data,
    )
    .and_then(|body| body.with_seq(seq))
    .expect("the deterministic adapter emits a valid Satelle Event")
}

fn adapter_configuration_error(subject: &str) -> SatelleError {
    SatelleError {
        code: satelle_core::ErrorCode::StorageIntegrityFailed,
        message: format!("the deterministic adapter has an invalid {subject}"),
        recovery_command: None,
        source_detail: None,
        details: std::collections::BTreeMap::new(),
    }
}
