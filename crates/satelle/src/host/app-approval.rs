use crate::core::{ActionRequestId, SatelleError, SessionId, TurnId};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::sync::{Arc, Mutex, mpsc};
use std::time::{Duration, Instant};

/// Native code and app consent share this boundary. OS prompts do not.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct NativeApprovalRequest {
    pub action_request_id: ActionRequestId,
    pub subject: NativeApprovalSubject,
    pub desktop_binding: String,
    pub session_id: Option<SessionId>,
    pub turn_id: Option<TurnId>,
    #[serde(with = "time::serde::rfc3339")]
    pub expires_at: time::OffsetDateTime,
}

/// Tool code is reviewed verbatim for one callback, never as a saved app grant.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum NativeApprovalSubject {
    App { app_id: String, allow_always: bool },
    ToolCode { code: String },
}

impl NativeApprovalSubject {
    pub const fn allow_always(&self) -> bool {
        matches!(
            self,
            Self::App {
                allow_always: true,
                ..
            }
        )
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum NativeApprovalDecision {
    Allow,
    Always,
    Deny,
}

/// Process-local authority, never decoded from a client request. The local
/// owner already controls this process; HTTP callers carry exact token grants.
#[derive(Clone, Copy)]
pub enum NativeApprovalAuthority<'a> {
    Owner,
    DesktopBindings(&'a std::collections::BTreeSet<String>),
}

impl NativeApprovalAuthority<'_> {
    fn allows(self, binding: &str) -> bool {
        match self {
            Self::Owner => true,
            Self::DesktopBindings(bindings) => bindings.contains(binding),
        }
    }
}

#[derive(Clone, Default)]
pub(crate) struct NativeApprovals(Arc<Mutex<BTreeMap<ActionRequestId, Entry>>>);

struct Entry {
    request: NativeApprovalRequest,
    deadline: Instant,
    sender: mpsc::Sender<NativeApprovalDecision>,
    decision: Option<NativeApprovalDecision>,
}

/// Dropping the protocol operation removes its request, including on failure.
pub(crate) struct PendingNativeApproval {
    approvals: NativeApprovals,
    id: ActionRequestId,
    deadline: Instant,
    receiver: mpsc::Receiver<NativeApprovalDecision>,
}

impl NativeApprovals {
    pub(crate) fn request(
        &self,
        approval_subject: NativeApprovalSubject,
        desktop_binding: &str,
        subject: Option<(&SessionId, &TurnId)>,
        deadline: Instant,
    ) -> Result<(ActionRequestId, PendingNativeApproval), SatelleError> {
        let remaining = deadline
            .saturating_duration_since(Instant::now())
            .min(Duration::from_secs(300));
        if remaining.is_zero() {
            return Err(SatelleError::invalid_usage(
                "the native approval operation has expired",
            ));
        }
        let id = ActionRequestId::new();
        let request = NativeApprovalRequest {
            action_request_id: id.clone(),
            subject: approval_subject,
            desktop_binding: desktop_binding.to_owned(),
            session_id: subject.map(|(session, _)| session.clone()),
            turn_id: subject.map(|(_, turn)| turn.clone()),
            expires_at: time::OffsetDateTime::now_utc()
                + time::Duration::try_from(remaining).map_err(|_| {
                    SatelleError::invalid_usage("the native approval deadline is invalid")
                })?,
        };
        let deadline = Instant::now() + remaining;
        let (sender, receiver) = mpsc::channel();
        let mut entries = self.0.lock().map_err(|_| unavailable())?;
        // Desktop leases serialize operations; also enforce the invariant at
        // this consent boundary rather than accumulate overlapping requests.
        if entries
            .values()
            .any(|entry| entry.request.desktop_binding == desktop_binding)
        {
            return Err(SatelleError::invalid_usage(
                "this desktop already has a pending native approval",
            ));
        }
        entries.insert(
            id.clone(),
            Entry {
                request,
                deadline,
                sender,
                decision: None,
            },
        );
        Ok((
            id.clone(),
            PendingNativeApproval {
                approvals: self.clone(),
                id,
                deadline,
                receiver,
            },
        ))
    }

    pub(crate) fn list(
        &self,
        authority: NativeApprovalAuthority<'_>,
    ) -> Result<Vec<NativeApprovalRequest>, SatelleError> {
        let entries = self.0.lock().map_err(|_| unavailable())?;
        Ok(entries
            .values()
            .filter(|entry| {
                entry.deadline > Instant::now()
                    && entry.decision.is_none()
                    && authority.allows(&entry.request.desktop_binding)
            })
            .map(|entry| entry.request.clone())
            .collect())
    }

    pub(crate) fn respond(
        &self,
        id: &ActionRequestId,
        decision: NativeApprovalDecision,
        authority: NativeApprovalAuthority<'_>,
    ) -> Result<(), SatelleError> {
        let mut entries = self.0.lock().map_err(|_| unavailable())?;
        let entry = entries
            .get_mut(id)
            .filter(|entry| entry.deadline > Instant::now())
            .ok_or_else(|| {
                SatelleError::invalid_usage("the native approval request is no longer pending")
            })?;
        if !authority.allows(&entry.request.desktop_binding) {
            return Err(SatelleError::desktop_binding_unauthorized(
                &entry.request.desktop_binding,
            ));
        }
        if let Some(previous) = entry.decision {
            return if previous == decision {
                Ok(())
            } else {
                Err(SatelleError::invalid_usage(
                    "the native approval request already has a different decision",
                ))
            };
        }
        if decision == NativeApprovalDecision::Always && !entry.request.subject.allow_always() {
            return Err(SatelleError::invalid_usage(
                "this native request does not support Always allow",
            ));
        }
        entry
            .sender
            .send(decision)
            .map_err(|_| SatelleError::invalid_usage("the native approval operation has ended"))?;
        entry.decision = Some(decision);
        Ok(())
    }
}

impl PendingNativeApproval {
    pub(crate) fn decision(&self) -> Option<NativeApprovalDecision> {
        // Expiry wins a late delivery; a stale decision must never grant access.
        if Instant::now() >= self.deadline {
            return Some(NativeApprovalDecision::Deny);
        }
        match self.receiver.try_recv() {
            Ok(decision) => Some(decision),
            Err(mpsc::TryRecvError::Disconnected) => Some(NativeApprovalDecision::Deny),
            Err(mpsc::TryRecvError::Empty) => None,
        }
    }
}

impl Drop for PendingNativeApproval {
    fn drop(&mut self) {
        if let Ok(mut entries) = self.approvals.0.lock() {
            entries.remove(&self.id);
        }
    }
}

fn unavailable() -> SatelleError {
    SatelleError::invalid_usage("the native approval registry is unavailable")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn consent_is_exact_explicit_and_removed_with_the_operation() {
        let approvals = NativeApprovals::default();
        let (request, pending) = approvals
            .request(
                NativeApprovalSubject::App {
                    app_id: "com.apple.calculator".into(),
                    allow_always: true,
                },
                "operator",
                None,
                Instant::now() + Duration::from_secs(30),
            )
            .unwrap();
        assert_eq!(pending.decision(), None);
        assert_eq!(
            approvals.list(NativeApprovalAuthority::Owner).unwrap()[0].action_request_id,
            request
        );
        approvals
            .respond(
                &request,
                NativeApprovalDecision::Always,
                NativeApprovalAuthority::Owner,
            )
            .unwrap();
        approvals
            .respond(
                &request,
                NativeApprovalDecision::Always,
                NativeApprovalAuthority::Owner,
            )
            .unwrap();
        assert!(
            approvals
                .respond(
                    &request,
                    NativeApprovalDecision::Deny,
                    NativeApprovalAuthority::Owner
                )
                .is_err()
        );
        assert_eq!(pending.decision(), Some(NativeApprovalDecision::Always));
        drop(pending);
        assert!(
            approvals
                .list(NativeApprovalAuthority::Owner)
                .unwrap()
                .is_empty()
        );
        assert!(
            approvals
                .respond(
                    &request,
                    NativeApprovalDecision::Always,
                    NativeApprovalAuthority::Owner
                )
                .is_err()
        );
    }

    #[test]
    fn unsupported_persistence_and_overlapping_requests_do_not_grant() {
        let approvals = NativeApprovals::default();
        let deadline = Instant::now() + Duration::from_secs(30);
        let (request, pending) = approvals
            .request(
                NativeApprovalSubject::App {
                    app_id: "com.apple.calculator".into(),
                    allow_always: false,
                },
                "operator",
                None,
                deadline,
            )
            .unwrap();
        assert!(
            approvals
                .respond(
                    &request,
                    NativeApprovalDecision::Always,
                    NativeApprovalAuthority::Owner
                )
                .is_err()
        );
        assert!(
            approvals
                .request(
                    NativeApprovalSubject::App {
                        app_id: "com.apple.finder".into(),
                        allow_always: true
                    },
                    "operator",
                    None,
                    deadline
                )
                .is_err()
        );
        assert_eq!(pending.decision(), None);
        approvals
            .respond(
                &request,
                NativeApprovalDecision::Deny,
                NativeApprovalAuthority::Owner,
            )
            .unwrap();
        assert_eq!(pending.decision(), Some(NativeApprovalDecision::Deny));
    }
    #[test]
    fn an_expired_request_cannot_accept_a_late_decision() {
        let approvals = NativeApprovals::default();
        let (request, pending) = approvals
            .request(
                NativeApprovalSubject::App {
                    app_id: "com.apple.calculator".into(),
                    allow_always: true,
                },
                "operator",
                None,
                Instant::now() + Duration::from_secs(30),
            )
            .unwrap();
        approvals
            .0
            .lock()
            .unwrap()
            .get_mut(&request)
            .unwrap()
            .deadline = Instant::now();
        assert!(
            approvals
                .respond(
                    &request,
                    NativeApprovalDecision::Always,
                    NativeApprovalAuthority::Owner
                )
                .is_err()
        );
        drop(pending);
        assert!(
            approvals
                .list(NativeApprovalAuthority::Owner)
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn tool_code_is_explicit_exact_and_cannot_be_persisted() {
        let approvals = NativeApprovals::default();
        let code = "await import('node:fs/promises')";
        let (request, pending) = approvals
            .request(
                NativeApprovalSubject::ToolCode { code: code.into() },
                "operator",
                None,
                Instant::now() + Duration::from_secs(30),
            )
            .unwrap();
        assert_eq!(
            approvals.list(NativeApprovalAuthority::Owner).unwrap()[0].subject,
            NativeApprovalSubject::ToolCode { code: code.into() }
        );
        assert_eq!(pending.decision(), None);
        assert!(
            approvals
                .respond(
                    &request,
                    NativeApprovalDecision::Always,
                    NativeApprovalAuthority::Owner
                )
                .is_err()
        );
        assert_eq!(pending.decision(), None);
        approvals
            .respond(
                &request,
                NativeApprovalDecision::Allow,
                NativeApprovalAuthority::Owner,
            )
            .unwrap();
        assert_eq!(pending.decision(), Some(NativeApprovalDecision::Allow));
        drop(pending);
        assert!(
            approvals
                .list(NativeApprovalAuthority::Owner)
                .unwrap()
                .is_empty()
        );
        for value in [
            serde_json::json!({"kind":"tool_code", "code":code, "allow_always":true}),
            serde_json::json!({"kind":"app", "app_id":"com.apple.calculator", "allow_always":false, "code":code}),
        ] {
            assert!(serde_json::from_value::<NativeApprovalSubject>(value).is_err());
        }
    }

    struct ConsentAdapter(NativeApprovals);
    impl crate::host::ComputerUseAdapter for ConsentAdapter {
        fn native_approval_requests(
            &self,
            authority: NativeApprovalAuthority<'_>,
        ) -> Result<Vec<NativeApprovalRequest>, SatelleError> {
            self.0.list(authority)
        }
        fn respond_to_native_approval(
            &self,
            id: &ActionRequestId,
            decision: NativeApprovalDecision,
            authority: NativeApprovalAuthority<'_>,
        ) -> Result<(), SatelleError> {
            self.0.respond(id, decision, authority)
        }
        fn preflight(
            &self,
            host: &str,
            intent: &crate::host::ProviderComputerUseIntent,
        ) -> Result<crate::host::AdapterReadiness, SatelleError> {
            crate::host::test_runtime::FakeComputerUseAdapter.preflight(host, intent)
        }
        fn execute(
            &self,
            request: crate::host::ExecuteRequest<'_>,
        ) -> Result<crate::host::ExecuteResult, SatelleError> {
            crate::host::test_runtime::FakeComputerUseAdapter.execute(request)
        }
        fn observe_stop(
            &self,
            subject: crate::host::AdapterSubject<'_>,
        ) -> Result<crate::core::session::StopObservation, SatelleError> {
            crate::host::test_runtime::FakeComputerUseAdapter.observe_stop(subject)
        }
        fn observe_recovery(
            &self,
            subject: crate::host::AdapterSubject<'_>,
        ) -> Result<crate::host::RecoveryObservation, SatelleError> {
            crate::host::test_runtime::FakeComputerUseAdapter.observe_recovery(subject)
        }
    }

    #[tokio::test]
    async fn authenticated_http_decision_reaches_the_exact_live_broker() {
        use crate::host::{ApiBearerToken, ApiScopes, HostService};
        use crate::transport::{
            DaemonServer, DaemonServerConfig, NativeApprovalResponse,
            NativeApprovalResponseRequest, NativeApprovalsResponse, RequestId,
        };
        for (approval_subject, decision) in [
            (
                NativeApprovalSubject::App {
                    app_id: "com.apple.calculator".into(),
                    allow_always: true,
                },
                NativeApprovalDecision::Always,
            ),
            (
                NativeApprovalSubject::ToolCode {
                    code: "console.log('PRIVATE_TOOL_CODE_CANARY')".into(),
                },
                NativeApprovalDecision::Allow,
            ),
        ] {
            let state = crate::host::test_support::TestStateDir::new().unwrap();
            let approvals = NativeApprovals::default();
            let expected_subject = approval_subject.clone();
            let (request, pending) = approvals
                .request(
                    approval_subject,
                    "local-demo-desktop-v1",
                    None,
                    Instant::now() + Duration::from_secs(30),
                )
                .unwrap();
            let (ungranted_request, ungranted_pending) = approvals
                .request(
                    expected_subject.clone(),
                    "another-desktop",
                    None,
                    Instant::now() + Duration::from_secs(30),
                )
                .unwrap();
            let service = HostService::with_adapter_for_tests_at(
                state.path(),
                ConsentAdapter(approvals.clone()),
            )
            .unwrap();
            let identity = service
                .initialize_daemon()
                .unwrap()
                .host_identity()
                .to_string();
            let token = ApiBearerToken::generate().unwrap();
            let principal = service
                .register_api_token(&token, "consent-test", ApiScopes::CONTROL, None)
                .unwrap();
            assert!(principal.allows_desktop_binding("local-demo-desktop-v1"));
            assert!(!principal.allows_desktop_binding("another-desktop"));
            let reader = ApiBearerToken::generate().unwrap();
            service
                .register_api_token(&reader, "consent-read-only", ApiScopes::READ, None)
                .unwrap();
            let server = DaemonServer::bind(
                service,
                DaemonServerConfig::loopback("127.0.0.1:0".parse().unwrap()),
            )
            .await
            .unwrap();
            let client = reqwest::Client::new();
            let authenticate = |builder: reqwest::RequestBuilder| {
                builder
                    .header(
                        "Authorization",
                        format!("Bearer {}", token.expose().as_str()),
                    )
                    .header("Satelle-Expected-Host-Identity", &identity)
                    .header("Satelle-Request-Id", RequestId::new().to_string())
            };
            let base = format!("http://{}", server.local_addr());
            let denied = client
                .get(format!("{base}/v1/actions"))
                .bearer_auth(reader.expose().as_str())
                .header("Satelle-Expected-Host-Identity", &identity)
                .header("Satelle-Request-Id", RequestId::new().to_string())
                .send()
                .await
                .unwrap();
            assert_eq!(denied.status(), reqwest::StatusCode::FORBIDDEN);
            assert!(
                !denied
                    .text()
                    .await
                    .unwrap()
                    .contains("PRIVATE_TOOL_CODE_CANARY")
            );
            let listed: NativeApprovalsResponse =
                authenticate(client.get(format!("{base}/v1/actions")))
                    .send()
                    .await
                    .unwrap()
                    .error_for_status()
                    .unwrap()
                    .json()
                    .await
                    .unwrap();
            assert_eq!(listed.requests.len(), 1);
            assert_eq!(listed.requests[0].action_request_id, request);
            assert_eq!(listed.requests[0].subject, expected_subject);
            for (index, ungranted_decision) in [
                NativeApprovalDecision::Allow,
                NativeApprovalDecision::Always,
                NativeApprovalDecision::Deny,
            ]
            .into_iter()
            .enumerate()
            {
                let denied = authenticate(
                    client.post(format!("{base}/v1/actions/{ungranted_request}/respond")),
                )
                .header(
                    "Satelle-Protocol-Version",
                    crate::core::host_update::HOST_PROTOCOL_VERSION,
                )
                .header("Idempotency-Key", format!("ungranted-consent-{index}"))
                .json(&NativeApprovalResponseRequest::new(ungranted_decision))
                .send()
                .await
                .unwrap();
                assert_eq!(denied.status(), reqwest::StatusCode::FORBIDDEN);
                assert_eq!(ungranted_pending.decision(), None);
            }
            // An already-decided request is no longer listed, but a same-decision
            // retry remains idempotent until the protocol operation drops it.
            for _ in 0..2 {
                let response: NativeApprovalResponse =
                    authenticate(client.post(format!("{base}/v1/actions/{}/respond", request)))
                        .header(
                            "Satelle-Protocol-Version",
                            crate::core::host_update::HOST_PROTOCOL_VERSION,
                        )
                        .header("Idempotency-Key", "explicit-consent")
                        .json(&NativeApprovalResponseRequest::new(decision))
                        .send()
                        .await
                        .unwrap()
                        .error_for_status()
                        .unwrap()
                        .json()
                        .await
                        .unwrap();
                assert_eq!(response.action_request_id, request);
                assert_eq!(response.decision, decision);
            }
            assert_eq!(pending.decision(), Some(decision));
            drop(pending);
            drop(ungranted_pending);
            assert!(
                approvals
                    .list(NativeApprovalAuthority::Owner)
                    .unwrap()
                    .is_empty()
            );
        }
    }
}
