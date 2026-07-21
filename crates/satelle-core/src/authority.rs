#[cfg(test)]
use crate::ids::SessionId;
use crate::session::{DesktopBindingRef, HostIdentityRef, ReferenceError};
use serde::{Deserialize, Serialize};
use std::fmt;
use thiserror::Error;

const MAX_AUTHORITY_REFERENCE_BYTES: usize = 128;

fn validate_authority_reference(value: &str) -> Result<(), ReferenceError> {
    if value.is_empty() {
        return Err(ReferenceError::Empty);
    }
    if value.len() > MAX_AUTHORITY_REFERENCE_BYTES {
        return Err(ReferenceError::TooLong);
    }
    if !value.bytes().all(|byte| {
        byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':' | b'/')
    }) {
        return Err(ReferenceError::InvalidCharacter);
    }
    Ok(())
}

/// Stable model for Satelle's public authority boundary.
///
/// This is the contract-level vocabulary. Runtime code may add storage rows or
/// transport details behind it, but public APIs should not invent a second set
/// of names for these roles, surfaces, or trust boundaries.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CorePublicModel {
    product: ProductAuthorityBoundary,
    bridge: BridgeBoundary,
    roles: AuthorityRoles,
    platforms: PlatformSupport,
    host: HostAuthorityModel,
    lifecycle: LifecycleAuthorityModel,
    phase_one: PhaseOneContractFreeze,
}

impl CorePublicModel {
    pub fn current() -> Self {
        Self {
            product: ProductAuthorityBoundary::current(),
            bridge: BridgeBoundary::current(),
            roles: AuthorityRoles::current(),
            platforms: PlatformSupport::mvp(),
            host: HostAuthorityModel::mvp(),
            lifecycle: LifecycleAuthorityModel::current(),
            phase_one: PhaseOneContractFreeze::current(),
        }
    }

    pub fn product(&self) -> &ProductAuthorityBoundary {
        &self.product
    }

    pub fn bridge(&self) -> &BridgeBoundary {
        &self.bridge
    }

    pub fn roles(&self) -> &AuthorityRoles {
        &self.roles
    }

    pub fn platforms(&self) -> &PlatformSupport {
        &self.platforms
    }

    pub fn host(&self) -> &HostAuthorityModel {
        &self.host
    }

    pub fn lifecycle(&self) -> &LifecycleAuthorityModel {
        &self.lifecycle
    }

    pub fn phase_one(&self) -> &PhaseOneContractFreeze {
        &self.phase_one
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProductAuthorityBoundary {
    controller_surfaces: Vec<ControllerSurface>,
    session_workflows: Vec<SessionWorkflow>,
    client_authorization: ClientAuthorizationBoundary,
    deployment: DeploymentBoundary,
    differentiators: Vec<ProductDifferentiator>,
    authoritative_state: Vec<AuthoritativeStateSubject>,
    artifact_export: ArtifactExportPolicy,
}

impl ProductAuthorityBoundary {
    pub fn current() -> Self {
        Self {
            controller_surfaces: vec![
                ControllerSurface::Cli,
                ControllerSurface::Json,
                ControllerSurface::Event,
                ControllerSurface::Http,
                ControllerSurface::WebSocket,
                ControllerSurface::Mcp,
            ],
            session_workflows: vec![
                SessionWorkflow::Start,
                SessionWorkflow::Inspect,
                SessionWorkflow::Steer,
                SessionWorkflow::Stop,
                SessionWorkflow::Recover,
            ],
            client_authorization: ClientAuthorizationBoundary::HumanAuthorized,
            deployment: DeploymentBoundary::SelfHostedControlPlane,
            differentiators: vec![
                ProductDifferentiator::AgentOrientedStructuredContracts,
                ProductDifferentiator::UserControlledDeployment,
                ProductDifferentiator::DurableSessionControl,
                ProductDifferentiator::AuditableSafetyBehavior,
            ],
            authoritative_state: vec![
                AuthoritativeStateSubject::Host,
                AuthoritativeStateSubject::Session,
                AuthoritativeStateSubject::Turn,
                AuthoritativeStateSubject::Diagnostic,
            ],
            artifact_export: ArtifactExportPolicy::OperatorExplicit,
        }
    }

    pub fn controller_surfaces(&self) -> &[ControllerSurface] {
        &self.controller_surfaces
    }

    pub fn session_workflows(&self) -> &[SessionWorkflow] {
        &self.session_workflows
    }

    pub fn client_authorization(&self) -> ClientAuthorizationBoundary {
        self.client_authorization
    }

    pub fn deployment(&self) -> DeploymentBoundary {
        self.deployment
    }

    pub fn differentiators(&self) -> &[ProductDifferentiator] {
        &self.differentiators
    }

    pub fn authoritative_state(&self) -> &[AuthoritativeStateSubject] {
        &self.authoritative_state
    }

    pub fn artifact_export(&self) -> ArtifactExportPolicy {
        self.artifact_export
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ControllerSurface {
    Cli,
    Json,
    Event,
    Http,
    WebSocket,
    Mcp,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SessionWorkflow {
    Start,
    Inspect,
    Steer,
    Stop,
    Recover,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ClientAuthorizationBoundary {
    HumanAuthorized,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DeploymentBoundary {
    SelfHostedControlPlane,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProductDifferentiator {
    AgentOrientedStructuredContracts,
    UserControlledDeployment,
    DurableSessionControl,
    AuditableSafetyBehavior,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuthoritativeStateSubject {
    Host,
    Session,
    Turn,
    Diagnostic,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ArtifactExportPolicy {
    OperatorExplicit,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BridgeBoundary {
    control_plane: BridgeControlPlane,
    upstream_runtime: UpstreamRuntimeBoundary,
    open_computer_use_role: OpenComputerUseRole,
}

impl BridgeBoundary {
    pub fn current() -> Self {
        Self {
            control_plane: BridgeControlPlane::SelfHosted,
            upstream_runtime: UpstreamRuntimeBoundary::CompatibleAgentRuntime,
            open_computer_use_role: OpenComputerUseRole::ReferenceMaterial,
        }
    }

    pub fn control_plane(&self) -> BridgeControlPlane {
        self.control_plane
    }

    pub fn upstream_runtime(&self) -> UpstreamRuntimeBoundary {
        self.upstream_runtime
    }

    pub fn open_computer_use_role(&self) -> OpenComputerUseRole {
        self.open_computer_use_role
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BridgeControlPlane {
    SelfHosted,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UpstreamRuntimeBoundary {
    CompatibleAgentRuntime,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OpenComputerUseRole {
    ReferenceMaterial,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthorityRoles {
    operator: OperatorAuthority,
    client: ClientAuthority,
    controller: ControllerAuthority,
}

impl AuthorityRoles {
    pub fn current() -> Self {
        Self {
            operator: OperatorAuthority::OwnsHostAndGrantsAuthority,
            client: ClientAuthority::ActsWithinOperatorGrantedAuthority,
            controller: ControllerAuthority::RunsCliOrMcpServer,
        }
    }

    pub fn operator(&self) -> OperatorAuthority {
        self.operator
    }

    pub fn client(&self) -> ClientAuthority {
        self.client
    }

    pub fn controller(&self) -> ControllerAuthority {
        self.controller
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OperatorAuthority {
    OwnsHostAndGrantsAuthority,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ClientAuthority {
    ActsWithinOperatorGrantedAuthority,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ControllerAuthority {
    RunsCliOrMcpServer,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PlatformSupport {
    controller_platforms: Vec<ControllerPlatform>,
    computer_use_host_platforms: Vec<ComputerUseHostPlatform>,
}

impl PlatformSupport {
    pub fn mvp() -> Self {
        Self {
            controller_platforms: vec![
                ControllerPlatform::Linux,
                ControllerPlatform::MacOs,
                ControllerPlatform::Windows,
            ],
            computer_use_host_platforms: vec![
                ComputerUseHostPlatform::MacOs,
                ComputerUseHostPlatform::Windows,
            ],
        }
    }

    pub fn controller_platforms(&self) -> &[ControllerPlatform] {
        &self.controller_platforms
    }

    pub fn computer_use_host_platforms(&self) -> &[ComputerUseHostPlatform] {
        &self.computer_use_host_platforms
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ControllerPlatform {
    Linux,
    MacOs,
    Windows,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ComputerUseHostPlatform {
    MacOs,
    Windows,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HostAuthorityModel {
    daemon_identity: HostDaemonIdentityAuthority,
    daemon_account: HostDaemonAccountAuthority,
    desktop_bindings: HostDesktopBindingCardinality,
    responsibilities: Vec<HostDaemonResponsibility>,
}

impl HostAuthorityModel {
    pub fn mvp() -> Self {
        Self {
            daemon_identity: HostDaemonIdentityAuthority::StableRandomGeneratedAndStored,
            daemon_account: HostDaemonAccountAuthority::OneDaemonOsAccount,
            desktop_bindings: HostDesktopBindingCardinality::ExactlyOneExplicitlyAuthorized,
            responsibilities: vec![
                HostDaemonResponsibility::HostChecks,
                HostDaemonResponsibility::CodexAppServerLifecycle,
                HostDaemonResponsibility::CapabilityProbes,
                HostDaemonResponsibility::AuthoritativeState,
                HostDaemonResponsibility::ClientConnections,
            ],
        }
    }

    pub fn daemon_identity(&self) -> HostDaemonIdentityAuthority {
        self.daemon_identity
    }

    pub fn daemon_account(&self) -> HostDaemonAccountAuthority {
        self.daemon_account
    }

    pub fn desktop_bindings(&self) -> HostDesktopBindingCardinality {
        self.desktop_bindings
    }

    pub fn responsibilities(&self) -> &[HostDaemonResponsibility] {
        &self.responsibilities
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HostDaemonIdentityAuthority {
    StableRandomGeneratedAndStored,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HostDaemonAccountAuthority {
    OneDaemonOsAccount,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HostDesktopBindingCardinality {
    ExactlyOneExplicitlyAuthorized,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HostDaemonResponsibility {
    HostChecks,
    CodexAppServerLifecycle,
    CapabilityProbes,
    AuthoritativeState,
    ClientConnections,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SatelleHost {
    identity: HostIdentityRef,
    daemon_account: DaemonOsAccount,
    desktop_binding: DesktopBindingRef,
}

impl SatelleHost {
    pub fn new(
        identity: HostIdentityRef,
        daemon_account: DaemonOsAccount,
        desktop_bindings: Vec<DesktopBindingRef>,
    ) -> Result<Self, AuthorityModelError> {
        let mut desktop_bindings = desktop_bindings.into_iter();
        let desktop_binding = desktop_bindings
            .next()
            .ok_or(AuthorityModelError::MissingDesktopBinding)?;
        if desktop_bindings.next().is_some() {
            return Err(AuthorityModelError::MultipleDesktopBindings);
        }
        Ok(Self {
            identity,
            daemon_account,
            desktop_binding,
        })
    }

    pub fn identity(&self) -> &HostIdentityRef {
        &self.identity
    }

    pub fn daemon_account(&self) -> &DaemonOsAccount {
        &self.daemon_account
    }

    pub fn desktop_binding(&self) -> &DesktopBindingRef {
        &self.desktop_binding
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DaemonOsAccount(String);

impl DaemonOsAccount {
    pub fn new(value: impl Into<String>) -> Result<Self, ReferenceError> {
        let value = value.into();
        validate_authority_reference(&value)?;
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for DaemonOsAccount {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ApiPrincipalModel {
    principal_ref: PrincipalRef,
    scopes: Vec<ApiPermissionScope>,
}

impl ApiPrincipalModel {
    pub fn new(
        principal_ref: PrincipalRef,
        scopes: Vec<ApiPermissionScope>,
    ) -> Result<Self, AuthorityModelError> {
        if scopes.is_empty() {
            return Err(AuthorityModelError::MissingApiPermissionScope);
        }
        Ok(Self {
            principal_ref,
            scopes,
        })
    }

    pub fn principal_ref(&self) -> &PrincipalRef {
        &self.principal_ref
    }

    pub fn scopes(&self) -> &[ApiPermissionScope] {
        &self.scopes
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PrincipalRef(String);

impl PrincipalRef {
    pub fn new(value: impl Into<String>) -> Result<Self, ReferenceError> {
        let value = value.into();
        validate_authority_reference(&value)?;
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for PrincipalRef {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ApiPermissionScope {
    Read,
    Control,
    Admin,
    DiagnosticsSensitive,
}

#[cfg(test)]
#[derive(Clone, Debug, Eq, PartialEq)]
struct SessionInternalMapping {
    session_id: SessionId,
    host_identity: HostIdentityRef,
    upstream_thread: UpstreamThreadRef,
}

#[cfg(test)]
impl SessionInternalMapping {
    fn new(
        session_id: SessionId,
        host_identity: HostIdentityRef,
        upstream_thread: UpstreamThreadRef,
    ) -> Self {
        Self {
            session_id,
            host_identity,
            upstream_thread,
        }
    }

    fn session_id(&self) -> &SessionId {
        &self.session_id
    }

    fn host_identity(&self) -> &HostIdentityRef {
        &self.host_identity
    }
}

#[cfg(test)]
#[derive(Clone, Debug, Eq, PartialEq)]
struct UpstreamThreadRef(String);

#[cfg(test)]
impl UpstreamThreadRef {
    fn new(value: impl Into<String>) -> Result<Self, ReferenceError> {
        let value = value.into();
        validate_authority_reference(&value)?;
        Ok(Self(value))
    }
}

#[cfg(test)]
#[derive(Clone, Debug, Eq, PartialEq)]
struct GoalMetadata {
    attachment: GoalAttachment,
}

#[cfg(test)]
impl GoalMetadata {
    fn for_session(session_id: SessionId) -> Self {
        Self {
            attachment: GoalAttachment::Session(session_id),
        }
    }

    fn for_upstream_thread(upstream_thread: UpstreamThreadRef) -> Self {
        Self {
            attachment: GoalAttachment::UpstreamThread(upstream_thread),
        }
    }

    fn attachment(&self) -> &GoalAttachment {
        &self.attachment
    }
}

#[cfg(test)]
#[derive(Clone, Debug, Eq, PartialEq)]
enum GoalAttachment {
    Session(SessionId),
    UpstreamThread(UpstreamThreadRef),
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LifecycleAuthorityModel {
    session_mapping: SessionMappingAuthority,
    turn_cardinality: TurnCardinalityAuthority,
    goal_authority: GoalAuthority,
    execution_policy: ExecutionPolicyAuthority,
}

impl LifecycleAuthorityModel {
    pub fn current() -> Self {
        Self {
            session_mapping: SessionMappingAuthority::OneHostAndOneUpstreamThread,
            turn_cardinality: TurnCardinalityAuthority::OneExecutionAttemptInOneSession,
            goal_authority: GoalAuthority::OptionalMetadataOnly,
            execution_policy: ExecutionPolicyAuthority::HostEnforcedTurnChoiceSet,
        }
    }

    pub fn session_mapping(&self) -> SessionMappingAuthority {
        self.session_mapping
    }

    pub fn turn_cardinality(&self) -> TurnCardinalityAuthority {
        self.turn_cardinality
    }

    pub fn goal_authority(&self) -> GoalAuthority {
        self.goal_authority
    }

    pub fn execution_policy(&self) -> ExecutionPolicyAuthority {
        self.execution_policy
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SessionMappingAuthority {
    OneHostAndOneUpstreamThread,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TurnCardinalityAuthority {
    OneExecutionAttemptInOneSession,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GoalAuthority {
    OptionalMetadataOnly,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExecutionPolicyAuthority {
    HostEnforcedTurnChoiceSet,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PhaseOneContractFreeze {
    subjects: Vec<PhaseOneSubject>,
    conformance: PhaseOneConformance,
    public_payload_guards: Vec<PublicPayloadGuard>,
}

impl PhaseOneContractFreeze {
    pub fn current() -> Self {
        Self {
            subjects: vec![
                PhaseOneSubject::DomainVocabulary,
                PhaseOneSubject::PublicIdentifiers,
                PhaseOneSubject::ApiEnvelopes,
                PhaseOneSubject::TypedErrors,
                PhaseOneSubject::ConfigurationTrustBoundaries,
                PhaseOneSubject::EventSchemas,
                PhaseOneSubject::ControlLeaseInvariants,
                PhaseOneSubject::PersistenceContracts,
            ],
            conformance: PhaseOneConformance::DeterministicInternalAdapter,
            public_payload_guards: vec![
                PublicPayloadGuard::UpstreamIdentifiers,
                PublicPayloadGuard::RawPrompts,
                PublicPayloadGuard::SecretValues,
                PublicPayloadGuard::ContradictoryLifecycleStates,
            ],
        }
    }

    pub fn subjects(&self) -> &[PhaseOneSubject] {
        &self.subjects
    }

    pub fn conformance(&self) -> PhaseOneConformance {
        self.conformance
    }

    pub fn public_payload_guards(&self) -> &[PublicPayloadGuard] {
        &self.public_payload_guards
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PhaseOneSubject {
    DomainVocabulary,
    PublicIdentifiers,
    ApiEnvelopes,
    TypedErrors,
    ConfigurationTrustBoundaries,
    EventSchemas,
    ControlLeaseInvariants,
    PersistenceContracts,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PhaseOneConformance {
    DeterministicInternalAdapter,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PublicPayloadGuard {
    UpstreamIdentifiers,
    RawPrompts,
    SecretValues,
    ContradictoryLifecycleStates,
}

#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
pub enum AuthorityModelError {
    #[error("an MVP Host requires exactly one explicitly authorized Desktop Binding")]
    MissingDesktopBinding,
    #[error("an MVP Host cannot own more than one Desktop Binding")]
    MultipleDesktopBindings,
    #[error("an API Principal requires at least one explicit permission scope")]
    MissingApiPermissionScope,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::session::{
        ApprovalPolicy, DesktopTarget, EffectiveModelRef, ExecutionPolicy,
        ExperimentalFeatureChoices, FeatureChoice, ProviderBindingRef, PublicSession,
        SandboxPolicy, TimeoutPolicy,
    };
    use serde_json::{Value, json};

    const SESSION_ID: &str = "rs_01890a5d-ac96-7b7c-8f89-37c3d0a66e11";
    const TURN_ID: &str = "rt_01890a5d-ac96-7b7c-8f89-37c3d0a66e21";

    #[test]
    fn current_model_freezes_public_product_authority_boundaries() {
        let model = CorePublicModel::current();

        assert_eq!(
            model.product().controller_surfaces(),
            &[
                ControllerSurface::Cli,
                ControllerSurface::Json,
                ControllerSurface::Event,
                ControllerSurface::Http,
                ControllerSurface::WebSocket,
                ControllerSurface::Mcp
            ]
        );
        assert_eq!(
            model.product().session_workflows(),
            &[
                SessionWorkflow::Start,
                SessionWorkflow::Inspect,
                SessionWorkflow::Steer,
                SessionWorkflow::Stop,
                SessionWorkflow::Recover
            ]
        );
        assert_eq!(
            model.product().client_authorization(),
            ClientAuthorizationBoundary::HumanAuthorized
        );
        assert_eq!(
            model.product().deployment(),
            DeploymentBoundary::SelfHostedControlPlane
        );
        assert_eq!(
            model.product().authoritative_state(),
            &[
                AuthoritativeStateSubject::Host,
                AuthoritativeStateSubject::Session,
                AuthoritativeStateSubject::Turn,
                AuthoritativeStateSubject::Diagnostic
            ]
        );
        assert_eq!(
            model.product().artifact_export(),
            ArtifactExportPolicy::OperatorExplicit
        );
    }

    #[test]
    fn current_model_freezes_bridge_roles_and_platform_boundaries() {
        let model = CorePublicModel::current();

        assert_eq!(
            model.bridge().control_plane(),
            BridgeControlPlane::SelfHosted
        );
        assert_eq!(
            model.bridge().upstream_runtime(),
            UpstreamRuntimeBoundary::CompatibleAgentRuntime
        );
        assert_eq!(
            model.bridge().open_computer_use_role(),
            OpenComputerUseRole::ReferenceMaterial
        );
        assert_eq!(
            model.roles().operator(),
            OperatorAuthority::OwnsHostAndGrantsAuthority
        );
        assert_eq!(
            model.roles().client(),
            ClientAuthority::ActsWithinOperatorGrantedAuthority
        );
        assert_eq!(
            model.roles().controller(),
            ControllerAuthority::RunsCliOrMcpServer
        );
        assert_eq!(
            model.platforms().controller_platforms(),
            &[
                ControllerPlatform::Linux,
                ControllerPlatform::MacOs,
                ControllerPlatform::Windows
            ]
        );
        assert_eq!(
            model.platforms().computer_use_host_platforms(),
            &[
                ComputerUseHostPlatform::MacOs,
                ComputerUseHostPlatform::Windows
            ]
        );
    }

    #[test]
    fn host_model_requires_one_stored_daemon_identity_and_one_desktop_binding() {
        let model = CorePublicModel::current();
        assert_eq!(
            model.host().daemon_identity(),
            HostDaemonIdentityAuthority::StableRandomGeneratedAndStored
        );
        assert_eq!(
            model.host().daemon_account(),
            HostDaemonAccountAuthority::OneDaemonOsAccount
        );
        assert_eq!(
            model.host().desktop_bindings(),
            HostDesktopBindingCardinality::ExactlyOneExplicitlyAuthorized
        );
        assert_eq!(
            model.host().responsibilities(),
            &[
                HostDaemonResponsibility::HostChecks,
                HostDaemonResponsibility::CodexAppServerLifecycle,
                HostDaemonResponsibility::CapabilityProbes,
                HostDaemonResponsibility::AuthoritativeState,
                HostDaemonResponsibility::ClientConnections
            ]
        );

        let satelle_host = SatelleHost::new(host(), daemon_account(), vec![desktop()])
            .expect("one desktop binding is accepted");
        assert_eq!(satelle_host.identity(), &host());
        assert_eq!(satelle_host.daemon_account().as_str(), "daemon-account");
        assert_eq!(satelle_host.desktop_binding(), &desktop());

        assert_eq!(
            SatelleHost::new(host(), daemon_account(), Vec::new()),
            Err(AuthorityModelError::MissingDesktopBinding)
        );
        assert_eq!(
            SatelleHost::new(host(), daemon_account(), vec![desktop(), other_desktop()]),
            Err(AuthorityModelError::MultipleDesktopBindings)
        );
    }

    #[test]
    fn api_principal_requires_explicit_permission_scopes() {
        let principal = PrincipalRef::new("operator-token").unwrap();
        assert_eq!(
            ApiPrincipalModel::new(principal.clone(), Vec::new()),
            Err(AuthorityModelError::MissingApiPermissionScope)
        );

        let principal =
            ApiPrincipalModel::new(principal, vec![ApiPermissionScope::Control]).unwrap();
        assert_eq!(principal.principal_ref().as_str(), "operator-token");
        assert_eq!(principal.scopes(), &[ApiPermissionScope::Control]);
    }

    #[test]
    fn authority_references_cover_validation_boundaries() {
        let exact = "a".repeat(MAX_AUTHORITY_REFERENCE_BYTES);
        assert_eq!(DaemonOsAccount::new(exact.clone()).unwrap().as_str(), exact);
        assert_eq!(PrincipalRef::new(exact.clone()).unwrap().as_str(), exact);
        assert_eq!(
            UpstreamThreadRef::new(exact.clone()).unwrap(),
            UpstreamThreadRef(exact)
        );

        assert_eq!(DaemonOsAccount::new(""), Err(ReferenceError::Empty));
        assert_eq!(PrincipalRef::new(""), Err(ReferenceError::Empty));
        assert_eq!(UpstreamThreadRef::new(""), Err(ReferenceError::Empty));

        let too_long = "a".repeat(MAX_AUTHORITY_REFERENCE_BYTES + 1);
        assert_eq!(
            DaemonOsAccount::new(too_long.clone()),
            Err(ReferenceError::TooLong)
        );
        assert_eq!(
            PrincipalRef::new(too_long.clone()),
            Err(ReferenceError::TooLong)
        );
        assert_eq!(
            UpstreamThreadRef::new(too_long),
            Err(ReferenceError::TooLong)
        );

        for invalid in ["thread id", "thread\tid", "thread?id"] {
            assert_eq!(
                DaemonOsAccount::new(invalid),
                Err(ReferenceError::InvalidCharacter)
            );
            assert_eq!(
                PrincipalRef::new(invalid),
                Err(ReferenceError::InvalidCharacter)
            );
            assert_eq!(
                UpstreamThreadRef::new(invalid),
                Err(ReferenceError::InvalidCharacter)
            );
        }
    }

    #[test]
    fn lifecycle_model_keeps_upstream_mapping_and_goal_metadata_internal() {
        let model = CorePublicModel::current();
        assert_eq!(
            model.lifecycle().session_mapping(),
            SessionMappingAuthority::OneHostAndOneUpstreamThread
        );
        assert_eq!(
            model.lifecycle().turn_cardinality(),
            TurnCardinalityAuthority::OneExecutionAttemptInOneSession
        );
        assert_eq!(
            model.lifecycle().goal_authority(),
            GoalAuthority::OptionalMetadataOnly
        );
        assert_eq!(
            model.lifecycle().execution_policy(),
            ExecutionPolicyAuthority::HostEnforcedTurnChoiceSet
        );

        let mapping = SessionInternalMapping::new(
            SessionId::parse(SESSION_ID).unwrap(),
            host(),
            UpstreamThreadRef::new("codex-thread-1").unwrap(),
        );
        assert_eq!(mapping.session_id().as_str(), SESSION_ID);
        assert_eq!(mapping.host_identity(), &host());
        assert_eq!(
            mapping.upstream_thread,
            UpstreamThreadRef("codex-thread-1".to_string())
        );

        let goal = GoalMetadata::for_session(SessionId::parse(SESSION_ID).unwrap());
        assert!(
            matches!(goal.attachment(), GoalAttachment::Session(id) if id.as_str() == SESSION_ID)
        );
        let goal =
            GoalMetadata::for_upstream_thread(UpstreamThreadRef::new("codex-thread-1").unwrap());
        assert!(
            matches!(goal.attachment(), GoalAttachment::UpstreamThread(thread) if thread == &UpstreamThreadRef("codex-thread-1".to_string()))
        );
    }

    #[test]
    fn execution_policy_captures_each_host_enforced_turn_choice() {
        let policy = execution_policy();

        assert_eq!(policy.effective_model().as_str(), "computer-use-model");
        assert_eq!(policy.provider_binding().as_str(), "provider-binding-a");
        assert_eq!(policy.desktop_target().binding(), &desktop());
        assert_eq!(policy.approval_policy(), ApprovalPolicy::OnRequest);
        assert_eq!(policy.sandbox_policy(), SandboxPolicy::WorkspaceWrite);
        assert_eq!(policy.timeout_policy().seconds(), 300);
        assert_eq!(
            policy.experimental_features(),
            ExperimentalFeatureChoices::new(FeatureChoice::Enabled, FeatureChoice::Disabled)
        );
    }

    #[test]
    fn phase_one_freeze_names_contract_subjects_and_public_payload_guards() {
        let phase_one = CorePublicModel::current().phase_one().clone();

        assert_eq!(
            phase_one.subjects(),
            &[
                PhaseOneSubject::DomainVocabulary,
                PhaseOneSubject::PublicIdentifiers,
                PhaseOneSubject::ApiEnvelopes,
                PhaseOneSubject::TypedErrors,
                PhaseOneSubject::ConfigurationTrustBoundaries,
                PhaseOneSubject::EventSchemas,
                PhaseOneSubject::ControlLeaseInvariants,
                PhaseOneSubject::PersistenceContracts
            ]
        );
        assert_eq!(
            phase_one.conformance(),
            PhaseOneConformance::DeterministicInternalAdapter
        );
        assert_eq!(
            phase_one.public_payload_guards(),
            &[
                PublicPayloadGuard::UpstreamIdentifiers,
                PublicPayloadGuard::RawPrompts,
                PublicPayloadGuard::SecretValues,
                PublicPayloadGuard::ContradictoryLifecycleStates
            ]
        );
    }

    #[test]
    fn public_model_and_public_session_do_not_serialize_private_payloads() {
        let model = serde_json::to_string(&CorePublicModel::current())
            .expect("serialize public authority model");
        for canary in [
            "raw prompt",
            "sk-secret-canary",
            "upstream_thread_id",
            "hosted_relay",
            "remote_desktop_viewer",
            "replacement_runtime",
        ] {
            assert!(
                !model.contains(canary),
                "public authority model leaked private canary {canary}"
            );
        }

        let session = public_session_json();
        let session = serde_json::from_value::<PublicSession>(session)
            .expect("public Session accepts coherent lifecycle");
        let serialized = serde_json::to_string(&session).expect("serialize public Session");
        for canary in [
            "codex-thread-1",
            "raw prompt",
            "sk-secret-canary",
            "effective_model",
            "provider_binding",
            "desktop_target",
            "approval_policy",
            "sandbox_policy",
        ] {
            assert!(
                !serialized.contains(canary),
                "public Session leaked private canary {canary}"
            );
        }
    }

    fn execution_policy() -> ExecutionPolicy {
        ExecutionPolicy::new(
            EffectiveModelRef::new("computer-use-model").unwrap(),
            ProviderBindingRef::new("provider-binding-a").unwrap(),
            DesktopTarget::new(desktop()),
            ApprovalPolicy::OnRequest,
            SandboxPolicy::WorkspaceWrite,
            TimeoutPolicy::bounded_seconds(300).unwrap(),
            ExperimentalFeatureChoices::new(FeatureChoice::Enabled, FeatureChoice::Disabled),
        )
    }

    fn public_session_json() -> Value {
        json!({
            "session_id": SESSION_ID,
            "display_name": null,
            "session_state_revision": 1,
            "created_at": "2024-01-01T00:00:00Z",
            "updated_at": "2024-01-01T00:00:00Z",
            "activity": {
                "state": "starting",
                "turn_id": TURN_ID,
                "turn_state_revision": 1
            },
            "turns": [{
                "session_id": SESSION_ID,
                "turn_id": TURN_ID,
                "turn_state_revision": 1,
                "state": "starting",
                "started_at": "2024-01-01T00:00:00Z",
                "updated_at": "2024-01-01T00:00:00Z",
                "terminal_at": null,
                "safe_summary": null
            }]
        })
    }

    fn host() -> HostIdentityRef {
        HostIdentityRef::new("host-a").unwrap()
    }

    fn desktop() -> DesktopBindingRef {
        DesktopBindingRef::new("desktop-a").unwrap()
    }

    fn other_desktop() -> DesktopBindingRef {
        DesktopBindingRef::new("desktop-b").unwrap()
    }

    fn daemon_account() -> DaemonOsAccount {
        DaemonOsAccount::new("daemon-account").unwrap()
    }
}
