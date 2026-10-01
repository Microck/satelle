use crate::core::{ActionRequestId, SatelleError, SessionId, TurnId};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::sync::{Arc, Mutex, mpsc};
use std::time::{Duration, Instant};

/// Only app consent crosses this boundary. OS and administrator prompts do not.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AppApprovalRequest {
    pub action_request_id: ActionRequestId,
    pub app_id: String,
    pub desktop_binding: String,
    pub session_id: Option<SessionId>,
    pub turn_id: Option<TurnId>,
    pub allow_always: bool,
    #[serde(with = "time::serde::rfc3339")]
    pub expires_at: time::OffsetDateTime,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AppApprovalDecision {
    Allow,
    Always,
    Deny,
}

#[derive(Clone, Default)]
pub(crate) struct AppApprovals(Arc<Mutex<BTreeMap<ActionRequestId, Entry>>>);

struct Entry {
    request: AppApprovalRequest,
    deadline: Instant,
    sender: mpsc::Sender<AppApprovalDecision>,
    decision: Option<AppApprovalDecision>,
}

/// Dropping the protocol operation removes its request, including on failure.
pub(crate) struct PendingAppApproval {
    approvals: AppApprovals,
    id: ActionRequestId,
    deadline: Instant,
    receiver: mpsc::Receiver<AppApprovalDecision>,
}

impl AppApprovals {
    pub(crate) fn request(
        &self,
        app_id: String,
        allow_always: bool,
        desktop_binding: &str,
        subject: Option<(&SessionId, &TurnId)>,
        deadline: Instant,
    ) -> Result<(AppApprovalRequest, PendingAppApproval), SatelleError> {
        let remaining = deadline
            .saturating_duration_since(Instant::now())
            .min(Duration::from_secs(300));
        if remaining.is_zero() {
            return Err(SatelleError::invalid_usage(
                "the app approval operation has expired",
            ));
        }
        let id = ActionRequestId::new();
        let request = AppApprovalRequest {
            action_request_id: id.clone(),
            app_id,
            desktop_binding: desktop_binding.to_owned(),
            session_id: subject.map(|(session, _)| session.clone()),
            turn_id: subject.map(|(_, turn)| turn.clone()),
            allow_always,
            expires_at: time::OffsetDateTime::now_utc()
                + time::Duration::try_from(remaining).map_err(|_| {
                    SatelleError::invalid_usage("the app approval deadline is invalid")
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
                "this desktop already has a pending app approval",
            ));
        }
        entries.insert(
            id.clone(),
            Entry {
                request: request.clone(),
                deadline,
                sender,
                decision: None,
            },
        );
        Ok((
            request,
            PendingAppApproval {
                approvals: self.clone(),
                id,
                deadline,
                receiver,
            },
        ))
    }

    pub(crate) fn list(&self) -> Result<Vec<AppApprovalRequest>, SatelleError> {
        let entries = self.0.lock().map_err(|_| unavailable())?;
        Ok(entries
            .values()
            .filter(|entry| entry.deadline > Instant::now() && entry.decision.is_none())
            .map(|entry| entry.request.clone())
            .collect())
    }

    pub(crate) fn respond(
        &self,
        id: &ActionRequestId,
        decision: AppApprovalDecision,
    ) -> Result<(), SatelleError> {
        let mut entries = self.0.lock().map_err(|_| unavailable())?;
        let entry = entries
            .get_mut(id)
            .filter(|entry| entry.deadline > Instant::now())
            .ok_or_else(|| {
                SatelleError::invalid_usage("the app approval request is no longer pending")
            })?;
        if let Some(previous) = entry.decision {
            return if previous == decision {
                Ok(())
            } else {
                Err(SatelleError::invalid_usage(
                    "the app approval request already has a different decision",
                ))
            };
        }
        if decision == AppApprovalDecision::Always && !entry.request.allow_always {
            return Err(SatelleError::invalid_usage(
                "this app request does not support Always allow",
            ));
        }
        entry
            .sender
            .send(decision)
            .map_err(|_| SatelleError::invalid_usage("the app approval operation has ended"))?;
        entry.decision = Some(decision);
        Ok(())
    }
}

impl PendingAppApproval {
    pub(crate) fn decision(&self) -> Option<AppApprovalDecision> {
        // Expiry wins a late delivery; a stale decision must never grant access.
        if Instant::now() >= self.deadline {
            return Some(AppApprovalDecision::Deny);
        }
        match self.receiver.try_recv() {
            Ok(decision) => Some(decision),
            Err(mpsc::TryRecvError::Disconnected) => Some(AppApprovalDecision::Deny),
            Err(mpsc::TryRecvError::Empty) => None,
        }
    }
}

impl Drop for PendingAppApproval {
    fn drop(&mut self) {
        if let Ok(mut entries) = self.approvals.0.lock() {
            entries.remove(&self.id);
        }
    }
}

fn unavailable() -> SatelleError {
    SatelleError::invalid_usage("the app approval registry is unavailable")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn consent_is_exact_explicit_and_removed_with_the_operation() {
        let approvals = AppApprovals::default();
        let (request, pending) = approvals
            .request(
                "com.apple.calculator".into(),
                true,
                "operator",
                None,
                Instant::now() + Duration::from_secs(30),
            )
            .unwrap();
        assert_eq!(pending.decision(), None);
        assert_eq!(approvals.list().unwrap(), vec![request.clone()]);
        approvals
            .respond(&request.action_request_id, AppApprovalDecision::Always)
            .unwrap();
        approvals
            .respond(&request.action_request_id, AppApprovalDecision::Always)
            .unwrap();
        assert!(
            approvals
                .respond(&request.action_request_id, AppApprovalDecision::Deny)
                .is_err()
        );
        assert_eq!(pending.decision(), Some(AppApprovalDecision::Always));
        drop(pending);
        assert!(approvals.list().unwrap().is_empty());
        assert!(
            approvals
                .respond(&request.action_request_id, AppApprovalDecision::Always)
                .is_err()
        );
    }

    #[test]
    fn unsupported_persistence_and_overlapping_requests_do_not_grant() {
        let approvals = AppApprovals::default();
        let deadline = Instant::now() + Duration::from_secs(30);
        let (request, pending) = approvals
            .request(
                "com.apple.calculator".into(),
                false,
                "operator",
                None,
                deadline,
            )
            .unwrap();
        assert!(
            approvals
                .respond(&request.action_request_id, AppApprovalDecision::Always)
                .is_err()
        );
        assert!(
            approvals
                .request("com.apple.finder".into(), true, "operator", None, deadline)
                .is_err()
        );
        assert_eq!(pending.decision(), None);
        approvals
            .respond(&request.action_request_id, AppApprovalDecision::Deny)
            .unwrap();
        assert_eq!(pending.decision(), Some(AppApprovalDecision::Deny));
    }
    #[test]
    fn an_expired_request_cannot_accept_a_late_decision() {
        let approvals = AppApprovals::default();
        let (request, pending) = approvals
            .request(
                "com.apple.calculator".into(),
                true,
                "operator",
                None,
                Instant::now() + Duration::from_secs(30),
            )
            .unwrap();
        approvals
            .0
            .lock()
            .unwrap()
            .get_mut(&request.action_request_id)
            .unwrap()
            .deadline = Instant::now();
        assert!(
            approvals
                .respond(&request.action_request_id, AppApprovalDecision::Always)
                .is_err()
        );
        drop(pending);
        assert!(approvals.list().unwrap().is_empty());
    }

    struct ConsentAdapter(AppApprovals);
    impl crate::host::ComputerUseAdapter for ConsentAdapter {
        fn app_approval_requests(&self) -> Result<Vec<AppApprovalRequest>, SatelleError> {
            self.0.list()
        }
        fn respond_to_app_approval(
            &self,
            id: &ActionRequestId,
            decision: AppApprovalDecision,
        ) -> Result<(), SatelleError> {
            self.0.respond(id, decision)
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
            AppApprovalResponse, AppApprovalResponseRequest, AppApprovalsResponse, DaemonServer,
            DaemonServerConfig, RequestId,
        };
        let state = crate::host::test_support::TestStateDir::new().unwrap();
        let approvals = AppApprovals::default();
        let (request, pending) = approvals
            .request(
                "com.apple.calculator".into(),
                true,
                "operator",
                None,
                Instant::now() + Duration::from_secs(30),
            )
            .unwrap();
        let service =
            HostService::with_adapter_for_tests_at(state.path(), ConsentAdapter(approvals.clone()))
                .unwrap();
        let identity = service
            .initialize_daemon()
            .unwrap()
            .host_identity()
            .to_string();
        let token = ApiBearerToken::generate().unwrap();
        service
            .register_api_token(&token, "consent-test", ApiScopes::CONTROL, None)
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
        let listed: AppApprovalsResponse = authenticate(client.get(format!("{base}/v1/actions")))
            .send()
            .await
            .unwrap()
            .error_for_status()
            .unwrap()
            .json()
            .await
            .unwrap();
        assert_eq!(listed.requests, vec![request.clone()]);
        let response: AppApprovalResponse = authenticate(client.post(format!(
            "{base}/v1/actions/{}/respond",
            request.action_request_id
        )))
        .header("Satelle-Protocol-Version", "22")
        .header("Idempotency-Key", "explicit-consent")
        .json(&AppApprovalResponseRequest::new(
            AppApprovalDecision::Always,
        ))
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();
        assert_eq!(response.action_request_id, request.action_request_id);
        assert_eq!(response.decision, AppApprovalDecision::Always);
        assert_eq!(pending.decision(), Some(AppApprovalDecision::Always));
        drop(pending);
        assert!(approvals.list().unwrap().is_empty());
    }
}
