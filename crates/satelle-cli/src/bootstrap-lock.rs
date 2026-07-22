pub(super) const READY: &str = "satelle-bootstrap-lock-v2";
pub(super) const BUSY: &str = "satelle-bootstrap-busy-v1";
pub(super) const HEARTBEAT: &str = "satelle-bootstrap-heartbeat-v1";
pub(super) const RELEASE: &str = "satelle-bootstrap-release-v1";
pub(super) const MUTATION_STARTED: &str = "satelle-bootstrap-mutation-started-v1";
pub(super) const MUTATION_COMMITTED: &str = "satelle-bootstrap-mutation-committed-v1";
pub(super) const MUTATION_EXECUTING: &str = "satelle-bootstrap-mutation-executing-v1";
const STALE_AFTER_SECONDS: u64 = 30;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum OperationKind {
    InitialSetup,
    MissingDaemonRepair,
    ServiceStop,
    ServiceRestart,
}

impl OperationKind {
    pub(super) const fn as_str(self) -> &'static str {
        match self {
            Self::InitialSetup => "initial_setup",
            Self::MissingDaemonRepair => "missing_daemon_repair",
            Self::ServiceStop => "service_stop",
            Self::ServiceRestart => "service_restart",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct Request {
    operation_id: String,
    operation_kind: OperationKind,
    controller_identity: Option<String>,
}

impl Request {
    pub(super) fn new(
        operation_id: impl Into<String>,
        operation_kind: OperationKind,
        controller_identity: Option<String>,
    ) -> Result<Self, InvalidRequest> {
        let operation_id = validated_token(operation_id.into(), "operation id")?;
        let controller_identity = controller_identity
            .map(|identity| validated_token(identity, "Controller identity"))
            .transpose()?;
        Ok(Self {
            operation_id,
            operation_kind,
            controller_identity,
        })
    }

    pub(super) fn operation_id(&self) -> &str {
        &self.operation_id
    }

    pub(super) const fn operation_kind(&self) -> OperationKind {
        self.operation_kind
    }

    pub(super) fn posix_command(&self) -> String {
        format!("sh -c {}", posix_quote(&self.posix_script()))
    }

    pub(super) fn windows_script(&self) -> String {
        let operation_id = powershell_quote(&self.operation_id);
        let operation_kind = powershell_quote(self.operation_kind.as_str());
        let controller_identity = powershell_quote(
            self.controller_identity
                .as_deref()
                .unwrap_or("controller-identity-unknown"),
        );
        format!(
            r#"$ErrorActionPreference = 'Stop'
$operationId = {operation_id}
$operationKind = {operation_kind}
$controllerIdentity = {controller_identity}
$stateRoot = if ($env:SATELLE_STATE_DIR) {{ $env:SATELLE_STATE_DIR }} else {{ Join-Path $env:LOCALAPPDATA 'Satelle\state' }}
$lockRoot = Join-Path $stateRoot 'bootstrap.lock'
$cacheRoot = if ($env:SATELLE_CACHE_DIR) {{ $env:SATELLE_CACHE_DIR }} else {{ Join-Path $env:LOCALAPPDATA 'Satelle\host' }}
$pendingPath = $null
$claimPath = $null
$claimIdentity = $null
$claimPublished = $false
$mutationStarted = $false
$mutationAttempt = $null
$mutationPhase = $null
$claimUncertain = $false
$released = $false
function Set-OwnerOnly([string]$Path) {{
  $acl = Get-Acl -LiteralPath $Path
  $acl.SetAccessRuleProtection($true, $false)
  foreach ($rule in @($acl.Access)) {{ [void]$acl.RemoveAccessRuleAll($rule) }}
  $rule = New-Object System.Security.AccessControl.FileSystemAccessRule(
    [System.Security.Principal.WindowsIdentity]::GetCurrent().Name,
    'FullControl',
    'ContainerInherit,ObjectInherit',
    'None',
    'Allow')
  $acl.SetAccessRule($rule)
  Set-Acl -LiteralPath $Path -AclObject $acl
}}
function Write-Value([string]$Root, [string]$Name, [string]$Value) {{
  $path = Join-Path $Root $Name
  [System.IO.File]::WriteAllText($path, $Value + [Environment]::NewLine)
  Set-OwnerOnly $path
}}
function Read-Operation([string]$Root) {{
  (Get-Content -LiteralPath (Join-Path $Root 'operation_id') -Raw).Trim()
}}
function Same-Owner {{
  $claimPath -and (Test-Path -LiteralPath $claimPath -PathType Container) -and
    ((Read-Operation $claimPath) -ceq $operationId) -and
    (((Get-Content -LiteralPath (Join-Path $claimPath 'claim_identity') -Raw).Trim()) -ceq $claimIdentity)
}}
function Remove-OwnClaim {{
  if (Same-Owner) {{ Remove-Item -LiteralPath $claimPath -Recurse -Force }}
}}
function Restore-Competitor([string]$Original, [string]$QuarantineRoot, [string]$QuarantinedClaim) {{
  if ((Test-Path -LiteralPath $QuarantinedClaim -PathType Container) -and
      (-not (Test-Path -LiteralPath $Original))) {{
    [IO.Directory]::Move($QuarantinedClaim, $Original)
  }}
  if (-not (Test-Path -LiteralPath $QuarantinedClaim)) {{
    Remove-Item -LiteralPath $QuarantineRoot -Force -ErrorAction SilentlyContinue
  }}
}}
function Fail-Busy {{
  if ($pendingPath -and (Test-Path -LiteralPath $pendingPath)) {{
    Remove-Item -LiteralPath $pendingPath -Recurse -Force -ErrorAction SilentlyContinue
  }}
  if ($claimPublished) {{ Remove-OwnClaim }}
  Write-Output '{BUSY}'
  exit 75
}}
function Record-Recovery([string]$Observed, [string]$Reason, [object]$Process, [bool]$Binary, [object]$Service, [object]$Daemon) {{
  $record = Join-Path $stateRoot ('bootstrap-recovery-' + $Observed + '.json')
  @{{schema_version='satelle.bootstrap-recovery.v1';operation_id=$Observed;reason=$Reason;process_probe=$Process;binary_probe=$Binary;service_probe=$Service;daemon_probe=$Daemon;observed_at=[DateTimeOffset]::UtcNow.ToString('O')}} |
    ConvertTo-Json -Compress | Set-Content -LiteralPath $record -Encoding UTF8
  Set-OwnerOnly $record
}}
function Get-ExecutionMarkers([string]$Root) {{
  @(Get-ChildItem -LiteralPath $Root -Force -ErrorAction Stop | Where-Object {{
    $_.Name.StartsWith('execution_started.', [StringComparison]::Ordinal) -or
      $_.Name.StartsWith('execution_retiring.', [StringComparison]::Ordinal) -or
      $_.Name.StartsWith('execution_succeeded.', [StringComparison]::Ordinal) -or
      $_.Name.StartsWith('execution_failed.', [StringComparison]::Ordinal) -or
      $_.Name.StartsWith('execution_committed.', [StringComparison]::Ordinal)
  }})
}}
function Retire-TerminalAttempt([string]$PriorPhase, [string]$PriorAttempt) {{
  $priorRequiresCommit = $PriorPhase -cin @('daemon_start', 'durable_token_verification', 'maintenance_handoff_begin', 'maintenance_handoff_complete')
  $priorUsesSuccess = $PriorPhase -cin @('cache_directory_creation', 'cache_upload', 'cache_staging_permissions', 'cache_promotion', 'state_owner_release')
  if (-not $priorRequiresCommit -and -not $priorUsesSuccess) {{ return $false }}
  $startedName = 'execution_started.' + $PriorAttempt
  $retiringName = 'execution_retiring.' + $PriorAttempt
  $terminalName = if ($priorRequiresCommit) {{ 'execution_committed.' + $PriorAttempt }} else {{ 'execution_succeeded.' + $PriorAttempt }}
  $launcherTerminalName = 'execution_succeeded.' + $PriorAttempt
  $allowedMarkers = @($startedName, $terminalName)
  if ($PriorPhase -ceq 'daemon_start') {{ $allowedMarkers += $launcherTerminalName }}
  $foreignMarkers = @(Get-ExecutionMarkers $claimPath | Where-Object {{
    ($allowedMarkers -cnotcontains $_.Name) -or $_.PSIsContainer -or
      (($_.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0)
  }})
  if ($foreignMarkers.Count -ne 0) {{ return $false }}
  $startedPath = Join-Path $claimPath $startedName
  $retiringPath = Join-Path $claimPath $retiringName
  $terminalPath = Join-Path $claimPath $terminalName
  if (-not (Test-Path -LiteralPath $startedPath -PathType Leaf) -or
      (Test-Path -LiteralPath $retiringPath) -or
      -not (Test-Path -LiteralPath $terminalPath -PathType Leaf)) {{ return $false }}
  try {{
    [IO.File]::Move($startedPath, $retiringPath)
    Remove-Item -LiteralPath $terminalPath
    if ($PriorPhase -ceq 'daemon_start' -and $launcherTerminalName -cne $terminalName -and
        (Test-Path -LiteralPath (Join-Path $claimPath $launcherTerminalName) -PathType Leaf)) {{
      Remove-Item -LiteralPath (Join-Path $claimPath $launcherTerminalName)
    }}
    Remove-Item -LiteralPath $retiringPath
  }} catch {{ return $false }}
  return $true
}}
function Finalize-InterruptedClaim {{
  $closingPath = $claimPath + '.closing'
  try {{ [IO.Directory]::Move($claimPath, $closingPath) }} catch {{ return }}
  $currentStarted = $mutationAttempt -and
    (Test-Path -LiteralPath (Join-Path $closingPath ('execution_started.' + $mutationAttempt)) -PathType Leaf)
  $currentRetiring = $mutationAttempt -and
    (Test-Path -LiteralPath (Join-Path $closingPath ('execution_retiring.' + $mutationAttempt)) -PathType Leaf)
  $requiresCommit = $mutationPhase -cin @('daemon_start', 'durable_token_verification', 'maintenance_handoff_begin', 'maintenance_handoff_complete')
  $marker = if ($requiresCommit) {{ 'execution_committed.' }} else {{ 'execution_succeeded.' }}
  $allowedClosingMarkers = @()
  if ($currentStarted) {{ $allowedClosingMarkers += 'execution_started.' + $mutationAttempt }}
  if ($currentRetiring) {{ $allowedClosingMarkers += 'execution_retiring.' + $mutationAttempt }}
  $allowedClosingMarkers += $marker + $mutationAttempt
  if ($mutationPhase -ceq 'daemon_start') {{ $allowedClosingMarkers += 'execution_succeeded.' + $mutationAttempt }}
  $invalidClosingMarkers = @(Get-ExecutionMarkers $closingPath | Where-Object {{
    ($allowedClosingMarkers -cnotcontains $_.Name) -or $_.PSIsContainer -or
      (($_.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0)
  }}).Count -ne 0
  if ($currentStarted -and $currentRetiring) {{
    $currentReconciled = $false
  }} elseif ($currentRetiring) {{
    $currentReconciled = -not $invalidClosingMarkers
  }} elseif ($currentStarted) {{
    $currentReconciled = (-not $invalidClosingMarkers) -and
      (Test-Path -LiteralPath (Join-Path $closingPath ($marker + $mutationAttempt)) -PathType Leaf)
  }} else {{
    $currentReconciled = @(Get-ExecutionMarkers $closingPath).Count -eq 0
  }}
  if ($currentReconciled) {{
    $failure = Join-Path $stateRoot ('bootstrap-operation-' + $operationId + '.json')
    $anyStarted = @(Get-ExecutionMarkers $closingPath | Where-Object {{
      $_.Name.StartsWith('execution_started.', [StringComparison]::Ordinal) -or
        $_.Name.StartsWith('execution_retiring.', [StringComparison]::Ordinal)
    }}).Count -gt 0
    $terminal = if ($anyStarted) {{ 'reconciled_failed' }} else {{ 'clean_failed' }}
    $failedPhase = if ($anyStarted) {{ 'after_reconciled_remote_mutation' }} else {{ 'before_remote_mutation' }}
    @{{schema_version='satelle.bootstrap-operation.v1';operation_id=$operationId;operation_kind=$operationKind;terminal_state=$terminal;failed_phase=$failedPhase;observed_at=[DateTimeOffset]::UtcNow.ToString('O')}} |
      ConvertTo-Json -Compress | Set-Content -LiteralPath $failure -Encoding UTF8
    Set-OwnerOnly $failure
    Remove-Item -LiteralPath $closingPath -Recurse -Force
    return
  }}
  Write-Value $closingPath 'state' 'recovery_pending'
  Write-Value $closingPath 'recovery_reason' 'controller channel closed after remote mutation'
  try {{ [IO.Directory]::Move($closingPath, $claimPath) }} catch {{}}
}}
try {{
  New-Item -ItemType Directory -Force -Path $stateRoot | Out-Null
  Set-OwnerOnly $stateRoot
  New-Item -ItemType Directory -Force -Path $lockRoot | Out-Null
  $lockItem = Get-Item -LiteralPath $lockRoot
  if (-not $lockItem.PSIsContainer -or
      (($lockItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0)) {{ Fail-Busy }}
  Set-OwnerOnly $lockRoot
  $nonce = [Guid]::NewGuid().ToString('N')
  $claimIdentity = $nonce
  $pendingPath = Join-Path $stateRoot ('bootstrap.pending.' + $nonce)
  New-Item -ItemType Directory -Path $pendingPath -ErrorAction Stop | Out-Null
  Set-OwnerOnly $pendingPath
  $now = [DateTimeOffset]::UtcNow.ToString('O')
  Write-Value $pendingPath 'schema_version' 'satelle.bootstrap-lock.v1'
  Write-Value $pendingPath 'operation_id' $operationId
  Write-Value $pendingPath 'claim_identity' $claimIdentity
  Write-Value $pendingPath 'operation_kind' $operationKind
  Write-Value $pendingPath 'controller_identity' $controllerIdentity
  Write-Value $pendingPath 'acquired_at' $now
  Write-Value $pendingPath 'heartbeat_at' $now
  Write-Value $pendingPath 'state' 'live'
  $claimPath = Join-Path $lockRoot ('claim.' + $operationId + '.' + $nonce)
  [IO.Directory]::Move($pendingPath, $claimPath)
  $pendingPath = $null
  $claimPublished = $true
}} catch {{ Fail-Busy }}
foreach ($item in @(Get-ChildItem -LiteralPath $lockRoot -Force -ErrorAction Stop)) {{
  if ([StringComparer]::OrdinalIgnoreCase.Equals($item.FullName, $claimPath)) {{ continue }}
  if (-not $item.PSIsContainer -or
      (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) -or
      (-not $item.Name.StartsWith('claim.', [StringComparison]::Ordinal))) {{ Fail-Busy }}
  try {{
    $observed = Read-Operation $item.FullName
    if ($observed -notmatch '^[A-Za-z0-9_.@-]{{1,128}}$') {{ Fail-Busy }}
    $heartbeat = (Get-Content -LiteralPath (Join-Path $item.FullName 'heartbeat_at') -Raw).Trim()
    $heartbeatTime = [DateTimeOffset]::Parse($heartbeat)
    $claimState = (Get-Content -LiteralPath (Join-Path $item.FullName 'state') -Raw).Trim()
    $observedIdentity = (Get-Content -LiteralPath (Join-Path $item.FullName 'claim_identity') -Raw).Trim()
    if ($observedIdentity -notmatch '^[0-9a-f]{{32}}$') {{ Fail-Busy }}
    $claimOperationKind = $null
    $mutationPhase = $null
    $mutationAttempt = $null
    $executionStarted = $false
    $executionRetiring = $false
    $executionSucceeded = $false
    $executionFailed = $false
    $executionCommitted = $false
    $unexpectedExecutionEvidence = $false
    $requiresCommit = $false
    if ($claimState -ne 'live') {{
      $claimOperationKind = (Get-Content -LiteralPath (Join-Path $item.FullName 'operation_kind') -Raw).Trim()
      $mutationPhase = (Get-Content -LiteralPath (Join-Path $item.FullName 'mutation_phase') -Raw).Trim()
      $mutationAttempt = (Get-Content -LiteralPath (Join-Path $item.FullName 'mutation_attempt') -Raw).Trim()
      if ($claimOperationKind -cnotin @('initial_setup', 'missing_daemon_repair') -or
          $mutationPhase -cnotin @('cache_directory_creation', 'cache_upload', 'cache_staging_permissions', 'cache_promotion', 'daemon_start', 'state_owner_release', 'durable_token_verification', 'maintenance_handoff_begin', 'maintenance_handoff_complete') -or
          $mutationAttempt -notmatch '^[0-9a-f]{{32}}$') {{ Fail-Busy }}
      $executionStarted = Test-Path -LiteralPath (Join-Path $item.FullName ('execution_started.' + $mutationAttempt)) -PathType Leaf
      $executionRetiring = Test-Path -LiteralPath (Join-Path $item.FullName ('execution_retiring.' + $mutationAttempt)) -PathType Leaf
      $executionSucceeded = Test-Path -LiteralPath (Join-Path $item.FullName ('execution_succeeded.' + $mutationAttempt)) -PathType Leaf
      $executionFailed = Test-Path -LiteralPath (Join-Path $item.FullName ('execution_failed.' + $mutationAttempt)) -PathType Leaf
      $executionCommitted = Test-Path -LiteralPath (Join-Path $item.FullName ('execution_committed.' + $mutationAttempt)) -PathType Leaf
      $requiresCommit = $mutationPhase -cin @('daemon_start', 'durable_token_verification', 'maintenance_handoff_begin', 'maintenance_handoff_complete')
      $expectedTerminalMarker = if ($requiresCommit) {{ 'execution_committed.' + $mutationAttempt }} else {{ 'execution_succeeded.' + $mutationAttempt }}
      $expectedExecutionMarkers = @('execution_started.' + $mutationAttempt, 'execution_retiring.' + $mutationAttempt, $expectedTerminalMarker)
      if ($mutationPhase -ceq 'daemon_start') {{
        $expectedExecutionMarkers += @('execution_succeeded.' + $mutationAttempt, 'execution_failed.' + $mutationAttempt)
      }}
      $unexpectedExecutionEvidence = @(Get-ChildItem -LiteralPath $item.FullName -Force -ErrorAction Stop | Where-Object {{
        $markerLike = $_.Name.StartsWith('execution_started.', [StringComparison]::Ordinal) -or
          $_.Name.StartsWith('execution_retiring.', [StringComparison]::Ordinal) -or
          $_.Name.StartsWith('execution_succeeded.', [StringComparison]::Ordinal) -or
          $_.Name.StartsWith('execution_failed.', [StringComparison]::Ordinal) -or
          $_.Name.StartsWith('execution_committed.', [StringComparison]::Ordinal)
        $markerLike -and (($expectedExecutionMarkers -cnotcontains $_.Name) -or $_.PSIsContainer -or
          (($_.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0))
      }}).Count -gt 0
      if ($mutationPhase -ceq 'daemon_start') {{
        $validDaemonMarkerShape = ((-not $executionStarted) -and (-not $executionSucceeded) -and
          (-not $executionRetiring) -and (-not $executionFailed) -and (-not $executionCommitted)) -or
          ($executionStarted -and (-not $executionRetiring) -and (-not $executionCommitted) -and
            (-not ($executionSucceeded -and $executionFailed))) -or
          ($executionStarted -and (-not $executionRetiring) -and $executionCommitted -and (-not $executionFailed)) -or
          ((-not $executionStarted) -and $executionRetiring -and (-not $executionFailed))
        if (-not $validDaemonMarkerShape) {{ $unexpectedExecutionEvidence = $true }}
      }} else {{
        $validMarkerShape = ((-not $executionStarted) -and (-not $executionRetiring) -and
          (-not $executionSucceeded) -and (-not $executionCommitted)) -or
          ($executionStarted -xor $executionRetiring)
        if (-not $validMarkerShape) {{ $unexpectedExecutionEvidence = $true }}
      }}
    }}
  }} catch {{ Fail-Busy }}
  if (([DateTimeOffset]::UtcNow - $heartbeatTime).TotalSeconds -le {STALE_AFTER_SECONDS}) {{ Fail-Busy }}
  if ($claimState -cnotin @('live', 'mutation_started', 'recovery_pending')) {{ Fail-Busy }}
  $processProbe = $null
  try {{
    $processProbe = [bool](Get-CimInstance Win32_Process -ErrorAction Stop | Where-Object {{ $_.Name -match '^satelle(.exe)?$' -and $_.CommandLine -match 'host start' }} | Select-Object -First 1)
  }} catch {{}}
  $processActive = $processProbe -eq $true
  $binaryPresent = [bool](Get-ChildItem -LiteralPath $cacheRoot -File -Recurse -ErrorAction SilentlyContinue | Where-Object {{ $_.Name -match '^satelle(-[0-9a-f]+)?.exe$' }} | Select-Object -First 1)
  $serviceProbe = $null
  try {{
    $serviceProbe = [bool](Get-CimInstance Win32_Service -Filter "Name = 'SatelleHost'" -ErrorAction Stop | Where-Object {{ $_.State -ne 'Stopped' }} | Select-Object -First 1)
  }} catch {{}}
  $serviceActive = $serviceProbe -eq $true
  $daemonProbe = $null
  try {{
    $response = Invoke-WebRequest -Uri 'http://127.0.0.1:3001/v1/capabilities' -Method Get -TimeoutSec 2 -UseBasicParsing
    $daemonProbe = $true
  }} catch {{
    if ($_.Exception.Response) {{
      $daemonProbe = $true
    }} else {{
      $probeError = $_.Exception
      while ($probeError) {{
        if ($probeError -is [Net.Sockets.SocketException] -and
            $probeError.SocketErrorCode -eq [Net.Sockets.SocketError]::ConnectionRefused) {{
          $daemonProbe = $false
          break
        }}
        $probeError = $probeError.InnerException
      }}
    }}
  }}
  $daemonActive = $daemonProbe -eq $true
  Record-Recovery $observed 'stale heartbeat postcondition probes' $processProbe $binaryPresent $serviceProbe $daemonProbe
  $terminalEvidence = ($requiresCommit -and $executionCommitted) -or
    ((-not $requiresCommit) -and $executionSucceeded)
  $failedDaemonStart = ($claimState -cin @('mutation_started', 'recovery_pending')) -and
    ($claimOperationKind -cin @('initial_setup', 'missing_daemon_repair')) -and
    ($mutationPhase -ceq 'daemon_start') -and
    $executionStarted -and ($executionSucceeded -xor $executionFailed) -and
    (-not $executionCommitted) -and (-not $unexpectedExecutionEvidence) -and
    ($processProbe -eq $false) -and ($serviceProbe -eq $false) -and ($daemonProbe -eq $false)
  $resolvedExecutionEvidence = $executionRetiring -or $terminalEvidence -or $failedDaemonStart
  $reconciled = (-not $unexpectedExecutionEvidence) -and
    (($claimState -ceq 'live') -or (-not $executionStarted) -or $resolvedExecutionEvidence)
  if (-not $reconciled) {{ Fail-Busy }}
  if (($processActive -or $serviceActive -or $daemonActive) -and
      $executionStarted -and
      -not $resolvedExecutionEvidence) {{ Fail-Busy }}
  $quarantineRoot = Join-Path $stateRoot ('bootstrap.quarantine.' + [Guid]::NewGuid().ToString('N'))
  New-Item -ItemType Directory -Path $quarantineRoot -ErrorAction Stop | Out-Null
  Set-OwnerOnly $quarantineRoot
  $quarantinedClaim = Join-Path $quarantineRoot 'claim'
  try {{ [IO.Directory]::Move($item.FullName, $quarantinedClaim) }} catch {{
    Remove-Item -LiteralPath $quarantineRoot -Force -ErrorAction SilentlyContinue
    Fail-Busy
  }}
  try {{
    $movedOperation = Read-Operation $quarantinedClaim
    $movedHeartbeat = (Get-Content -LiteralPath (Join-Path $quarantinedClaim 'heartbeat_at') -Raw).Trim()
    $movedState = (Get-Content -LiteralPath (Join-Path $quarantinedClaim 'state') -Raw).Trim()
    $movedIdentity = (Get-Content -LiteralPath (Join-Path $quarantinedClaim 'claim_identity') -Raw).Trim()
    $movedOperationKind = $null
    $movedMutationPhase = $null
    $movedMutationAttempt = $null
    $movedExecutionStarted = $false
    $movedExecutionRetiring = $false
    $movedExecutionSucceeded = $false
    $movedExecutionFailed = $false
    $movedExecutionCommitted = $false
    $movedUnexpectedExecutionEvidence = $false
    $movedRequiresCommit = $false
    if ($movedState -ne 'live') {{
      $movedOperationKind = (Get-Content -LiteralPath (Join-Path $quarantinedClaim 'operation_kind') -Raw).Trim()
      $movedMutationPhase = (Get-Content -LiteralPath (Join-Path $quarantinedClaim 'mutation_phase') -Raw).Trim()
      $movedMutationAttempt = (Get-Content -LiteralPath (Join-Path $quarantinedClaim 'mutation_attempt') -Raw).Trim()
      $movedExecutionStarted = Test-Path -LiteralPath (Join-Path $quarantinedClaim ('execution_started.' + $movedMutationAttempt)) -PathType Leaf
      $movedExecutionRetiring = Test-Path -LiteralPath (Join-Path $quarantinedClaim ('execution_retiring.' + $movedMutationAttempt)) -PathType Leaf
      $movedExecutionSucceeded = Test-Path -LiteralPath (Join-Path $quarantinedClaim ('execution_succeeded.' + $movedMutationAttempt)) -PathType Leaf
      $movedExecutionFailed = Test-Path -LiteralPath (Join-Path $quarantinedClaim ('execution_failed.' + $movedMutationAttempt)) -PathType Leaf
      $movedExecutionCommitted = Test-Path -LiteralPath (Join-Path $quarantinedClaim ('execution_committed.' + $movedMutationAttempt)) -PathType Leaf
      $movedRequiresCommit = $movedMutationPhase -cin @('daemon_start', 'durable_token_verification', 'maintenance_handoff_begin', 'maintenance_handoff_complete')
      $movedExpectedTerminalMarker = if ($movedRequiresCommit) {{ 'execution_committed.' + $movedMutationAttempt }} else {{ 'execution_succeeded.' + $movedMutationAttempt }}
      $movedExpectedExecutionMarkers = @('execution_started.' + $movedMutationAttempt, 'execution_retiring.' + $movedMutationAttempt, $movedExpectedTerminalMarker)
      if ($movedMutationPhase -ceq 'daemon_start') {{
        $movedExpectedExecutionMarkers += @('execution_succeeded.' + $movedMutationAttempt, 'execution_failed.' + $movedMutationAttempt)
      }}
      $movedUnexpectedExecutionEvidence = @(Get-ChildItem -LiteralPath $quarantinedClaim -Force -ErrorAction Stop | Where-Object {{
        $markerLike = $_.Name.StartsWith('execution_started.', [StringComparison]::Ordinal) -or
          $_.Name.StartsWith('execution_retiring.', [StringComparison]::Ordinal) -or
          $_.Name.StartsWith('execution_succeeded.', [StringComparison]::Ordinal) -or
          $_.Name.StartsWith('execution_failed.', [StringComparison]::Ordinal) -or
          $_.Name.StartsWith('execution_committed.', [StringComparison]::Ordinal)
        $markerLike -and (($movedExpectedExecutionMarkers -cnotcontains $_.Name) -or $_.PSIsContainer -or
          (($_.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0))
      }}).Count -gt 0
      if ($movedMutationPhase -ceq 'daemon_start') {{
        $movedValidDaemonMarkerShape = ((-not $movedExecutionStarted) -and (-not $movedExecutionSucceeded) -and
          (-not $movedExecutionRetiring) -and (-not $movedExecutionFailed) -and (-not $movedExecutionCommitted)) -or
          ($movedExecutionStarted -and (-not $movedExecutionRetiring) -and (-not $movedExecutionCommitted) -and
            (-not ($movedExecutionSucceeded -and $movedExecutionFailed))) -or
          ($movedExecutionStarted -and (-not $movedExecutionRetiring) -and $movedExecutionCommitted -and (-not $movedExecutionFailed)) -or
          ((-not $movedExecutionStarted) -and $movedExecutionRetiring -and (-not $movedExecutionFailed))
        if (-not $movedValidDaemonMarkerShape) {{ $movedUnexpectedExecutionEvidence = $true }}
      }} else {{
        $movedValidMarkerShape = ((-not $movedExecutionStarted) -and (-not $movedExecutionRetiring) -and
          (-not $movedExecutionSucceeded) -and (-not $movedExecutionCommitted)) -or
          ($movedExecutionStarted -xor $movedExecutionRetiring)
        if (-not $movedValidMarkerShape) {{ $movedUnexpectedExecutionEvidence = $true }}
      }}
    }}
  }} catch {{
    Restore-Competitor $item.FullName $quarantineRoot $quarantinedClaim
    Fail-Busy
  }}
  if (($movedOperation -cne $observed) -or ($movedIdentity -cne $observedIdentity) -or ($movedHeartbeat -cne $heartbeat) -or
      ($movedState -cne $claimState) -or ($movedOperationKind -cne $claimOperationKind) -or
      ($movedMutationPhase -cne $mutationPhase) -or ($movedMutationAttempt -cne $mutationAttempt) -or
      ($movedExecutionStarted -ne $executionStarted) -or ($movedExecutionRetiring -ne $executionRetiring) -or
      ($movedExecutionSucceeded -ne $executionSucceeded) -or
      ($movedExecutionFailed -ne $executionFailed) -or
      ($movedExecutionCommitted -ne $executionCommitted) -or
      ($movedUnexpectedExecutionEvidence -ne $unexpectedExecutionEvidence)) {{
    Restore-Competitor $item.FullName $quarantineRoot $quarantinedClaim
    Fail-Busy
  }}
  if ($failedDaemonStart) {{
    $postProcessProbe = $null
    try {{
      $postProcessProbe = [bool](Get-CimInstance Win32_Process -ErrorAction Stop | Where-Object {{ $_.Name -match '^satelle(.exe)?$' -and $_.CommandLine -match 'host start' }} | Select-Object -First 1)
    }} catch {{}}
    $postServiceProbe = $null
    try {{
      $postServiceProbe = [bool](Get-CimInstance Win32_Service -Filter "Name = 'SatelleHost'" -ErrorAction Stop | Where-Object {{ $_.State -ne 'Stopped' }} | Select-Object -First 1)
    }} catch {{}}
    $postDaemonProbe = $null
    try {{
      $null = Invoke-WebRequest -Uri 'http://127.0.0.1:3001/v1/capabilities' -Method Get -TimeoutSec 2 -UseBasicParsing
      $postDaemonProbe = $true
    }} catch {{
      if ($_.Exception.Response) {{
        $postDaemonProbe = $true
      }} else {{
        $probeError = $_.Exception
        while ($probeError) {{
          if ($probeError -is [Net.Sockets.SocketException] -and
              $probeError.SocketErrorCode -eq [Net.Sockets.SocketError]::ConnectionRefused) {{
            $postDaemonProbe = $false
            break
          }}
          $probeError = $probeError.InnerException
        }}
      }}
    }}
    if (($postProcessProbe -ne $false) -or ($postServiceProbe -ne $false) -or ($postDaemonProbe -ne $false)) {{
      Restore-Competitor $item.FullName $quarantineRoot $quarantinedClaim
      Fail-Busy
    }}
  }}
  Remove-Item -LiteralPath $quarantineRoot -Recurse -Force
}}
foreach ($item in @(Get-ChildItem -LiteralPath $lockRoot -Force -ErrorAction Stop)) {{
  if (-not [StringComparer]::OrdinalIgnoreCase.Equals($item.FullName, $claimPath)) {{ Fail-Busy }}
}}
if (-not (Same-Owner)) {{ Fail-Busy }}
Write-Output ('{READY} ' + $claimIdentity + ' ' + [IO.Path]::GetFileName($claimPath))
try {{
  while (($line = [Console]::In.ReadLine()) -ne $null) {{
    if (-not (Same-Owner)) {{ exit 75 }}
    if ($line -ceq '{HEARTBEAT}') {{
      Write-Value $claimPath 'heartbeat_at' ([DateTimeOffset]::UtcNow.ToString('O'))
      continue
    }}
    if ($line.StartsWith('{MUTATION_STARTED} ')) {{
      $parts = @($line.Substring({mutation_prefix_length}).Split(' ', [StringSplitOptions]::RemoveEmptyEntries))
      if ($parts.Count -ne 2) {{ exit 64 }}
      $phase = $parts[0]
      $attempt = $parts[1]
      if ($phase -notmatch '^[A-Za-z0-9_-]{{1,128}}$' -or $attempt -notmatch '^[0-9a-f]{{32}}$') {{ exit 64 }}
      if ($mutationStarted) {{
        if (($attempt -ceq $mutationAttempt) -or -not (Retire-TerminalAttempt $mutationPhase $mutationAttempt)) {{
          $claimUncertain = $true
          exit 75
        }}
      }} elseif (@(Get-ExecutionMarkers $claimPath).Count -ne 0) {{
        $claimUncertain = $true
        exit 75
      }}
      Write-Value $claimPath 'mutation_phase' $phase
      Write-Value $claimPath 'mutation_attempt' $attempt
      Write-Value $claimPath 'state' 'mutation_started'
      $mutationStarted = $true
      $mutationPhase = $phase
      $mutationAttempt = $attempt
    }} elseif ($line.StartsWith('{MUTATION_EXECUTING} ')) {{
      $parts = @($line.Substring({executing_prefix_length}).Split(' ', [StringSplitOptions]::RemoveEmptyEntries))
      if ($parts.Count -ne 2 -or $parts[0] -cne $mutationPhase -or $parts[1] -cne $mutationAttempt) {{ exit 75 }}
      [IO.File]::Open((Join-Path $claimPath ('execution_started.' + $mutationAttempt)), [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None).Dispose()
    }} elseif ($line.StartsWith('{MUTATION_COMMITTED} ')) {{
      $parts = @($line.Substring({commit_prefix_length}).Split(' ', [StringSplitOptions]::RemoveEmptyEntries))
      if ($parts.Count -ne 2 -or $parts[0] -cne $mutationPhase -or $parts[1] -cne $mutationAttempt -or
          -not (Test-Path -LiteralPath (Join-Path $claimPath ('execution_started.' + $mutationAttempt)) -PathType Leaf)) {{ exit 75 }}
      [IO.File]::Open((Join-Path $claimPath ('execution_committed.' + $mutationAttempt)), [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None).Dispose()
    }} elseif ($line -ceq '{RELEASE}') {{
      if (-not (Same-Owner)) {{ exit 75 }}
      Remove-OwnClaim
      $claimPublished = $false
      $released = $true
      Write-Output $line
      break
    }}
    Write-Output $line
  }}
}} finally {{
  if (-not $released -and (Same-Owner)) {{
    if ($claimUncertain) {{
      Write-Value $claimPath 'state' 'recovery_pending'
      Write-Value $claimPath 'recovery_reason' 'phase advance found uncertain execution evidence'
    }} elseif ($mutationStarted) {{
      Finalize-InterruptedClaim
    }} else {{
      $failure = Join-Path $stateRoot ('bootstrap-operation-' + $operationId + '.json')
      @{{schema_version='satelle.bootstrap-operation.v1';operation_id=$operationId;operation_kind=$operationKind;terminal_state='clean_failed';failed_phase='before_remote_mutation';observed_at=[DateTimeOffset]::UtcNow.ToString('O')}} |
        ConvertTo-Json -Compress | Set-Content -LiteralPath $failure -Encoding UTF8
      Set-OwnerOnly $failure
      Remove-OwnClaim
    }}
  }}
}}"#,
            mutation_prefix_length = MUTATION_STARTED.len() + 1,
            executing_prefix_length = MUTATION_EXECUTING.len() + 1,
            commit_prefix_length = MUTATION_COMMITTED.len() + 1,
        )
    }

    fn posix_script(&self) -> String {
        let operation_id = posix_quote(&self.operation_id);
        let operation_kind = posix_quote(self.operation_kind.as_str());
        let controller_identity = posix_quote(
            self.controller_identity
                .as_deref()
                .unwrap_or("controller-identity-unknown"),
        );
        format!(
            r#"set -eu
operation_id={operation_id}
operation_kind={operation_kind}
controller_identity={controller_identity}
state_root="${{SATELLE_STATE_DIR:-${{XDG_STATE_HOME:-$HOME/.local/state}}/satelle}}"
lock_root="$state_root/bootstrap.lock"
cache_root="${{SATELLE_CACHE_DIR:-${{XDG_CACHE_HOME:-$HOME/.cache}}/satelle/host}}"
pending_path=
claim_path=
claim_identity=
claim_published=false
mutation_started=false
mutation_attempt=
mutation_phase=
claim_uncertain=false
released=false
write_value() {{ printf '%s\n' "$2" >"$1/$3"; chmod 600 "$1/$3"; }}
read_operation() {{ cat "$1/operation_id" 2>/dev/null; }}
same_owner() {{
  [ -n "$claim_path" ] && [ -d "$claim_path" ] &&
    [ "$(read_operation "$claim_path")" = "$operation_id" ] &&
    [ "$(cat "$claim_path/claim_identity" 2>/dev/null)" = "$claim_identity" ]
}}
remove_own_claim() {{ if same_owner; then rm -rf "$claim_path"; fi; }}
restore_competitor() {{
  if [ -d "$quarantined_claim" ] && [ ! -e "$competitor" ] && mv "$quarantined_claim" "$competitor" 2>/dev/null; then
    rmdir "$quarantine_root" 2>/dev/null || true
  fi
}}
record_recovery() {{
  record="$state_root/bootstrap-recovery-$1.json"
  printf '{{"schema_version":"satelle.bootstrap-recovery.v1","operation_id":"%s","reason":"stale heartbeat postcondition probes","process_probe":%s,"binary_probe":%s,"service_probe":%s,"daemon_probe":%s,"observed_at":"%s"}}\n' "$1" "$2" "$3" "$4" "$5" "$(date -u +%Y-%m-%dT%H:%M:%SZ)" >"$record"
  chmod 600 "$record"
}}
has_execution_markers() {{
  for marker in "$claim_path"/execution_started.* "$claim_path"/execution_retiring.* "$claim_path"/execution_succeeded.* "$claim_path"/execution_failed.* "$claim_path"/execution_committed.*; do
    [ -e "$marker" ] || [ -L "$marker" ] || continue
    return 0
  done
  return 1
}}
retire_terminal_attempt() {{
  prior_phase=$1
  prior_attempt=$2
  case "$prior_phase" in
    daemon_start|durable_token_verification|maintenance_handoff_begin|maintenance_handoff_complete) terminal_kind=execution_committed;;
    cache_directory_creation|cache_upload|cache_staging_permissions|cache_promotion|state_owner_release) terminal_kind=execution_succeeded;;
    *) return 1;;
  esac
  started_path="$claim_path/execution_started.$prior_attempt"
  retiring_path="$claim_path/execution_retiring.$prior_attempt"
  terminal_path="$claim_path/$terminal_kind.$prior_attempt"
  [ -d "$started_path" ] && [ ! -L "$started_path" ] || return 1
  [ ! -e "$retiring_path" ] && [ ! -L "$retiring_path" ] || return 1
  [ -d "$terminal_path" ] && [ ! -L "$terminal_path" ] || return 1
  launcher_terminal_path="$claim_path/execution_succeeded.$prior_attempt"
  for marker in "$claim_path"/execution_started.* "$claim_path"/execution_retiring.* "$claim_path"/execution_succeeded.* "$claim_path"/execution_failed.* "$claim_path"/execution_committed.*; do
    [ -e "$marker" ] || [ -L "$marker" ] || continue
    case "$marker" in
      "$started_path"|"$terminal_path") [ -d "$marker" ] && [ ! -L "$marker" ] || return 1;;
      "$launcher_terminal_path") [ "$prior_phase" = daemon_start ] && [ -d "$marker" ] && [ ! -L "$marker" ] || return 1;;
      *) return 1;;
    esac
  done
  mv "$started_path" "$retiring_path" || return 1
  rmdir "$terminal_path" || return 1
  if [ "$prior_phase" = daemon_start ] && [ "$launcher_terminal_path" != "$terminal_path" ] && [ -d "$launcher_terminal_path" ]; then
    rmdir "$launcher_terminal_path" || return 1
  fi
  rmdir "$retiring_path" || return 1
}}
finalize_interrupted_claim() {{
  closing_path="$claim_path.closing"
  mv "$claim_path" "$closing_path" 2>/dev/null || return
  current_started=false
  [ -n "$mutation_attempt" ] && [ -d "$closing_path/execution_started.$mutation_attempt" ] && current_started=true
  current_retiring=false
  [ -n "$mutation_attempt" ] && [ -d "$closing_path/execution_retiring.$mutation_attempt" ] && current_retiring=true
  requires_commit=false
  case "$mutation_phase" in daemon_start|durable_token_verification|maintenance_handoff_begin|maintenance_handoff_complete) requires_commit=true;; esac
  if [ "$requires_commit" = true ]; then terminal_kind=execution_committed; else terminal_kind=execution_succeeded; fi
  started_path="$closing_path/execution_started.$mutation_attempt"
  retiring_path="$closing_path/execution_retiring.$mutation_attempt"
  terminal_path="$closing_path/$terminal_kind.$mutation_attempt"
  launcher_terminal_path="$closing_path/execution_succeeded.$mutation_attempt"
  closing_markers_present=false
  invalid_closing_markers=false
  for marker in "$closing_path"/execution_started.* "$closing_path"/execution_retiring.* "$closing_path"/execution_succeeded.* "$closing_path"/execution_failed.* "$closing_path"/execution_committed.*; do
    [ -e "$marker" ] || [ -L "$marker" ] || continue
    closing_markers_present=true
    case "$marker" in
      "$started_path") [ "$current_started" = true ] && [ -d "$marker" ] && [ ! -L "$marker" ] || invalid_closing_markers=true;;
      "$retiring_path") [ "$current_retiring" = true ] && [ -d "$marker" ] && [ ! -L "$marker" ] || invalid_closing_markers=true;;
      "$terminal_path") [ -d "$marker" ] && [ ! -L "$marker" ] || invalid_closing_markers=true;;
      "$launcher_terminal_path") [ "$mutation_phase" = daemon_start ] && [ -d "$marker" ] && [ ! -L "$marker" ] || invalid_closing_markers=true;;
      *) invalid_closing_markers=true;;
    esac
  done
  current_reconciled=false
  if [ "$current_started" = true ] && [ "$current_retiring" = true ]; then
    :
  elif [ "$current_retiring" = true ] && [ "$invalid_closing_markers" = false ]; then
    current_reconciled=true
  elif [ "$current_started" = true ] && [ "$invalid_closing_markers" = false ] && [ -d "$terminal_path" ]; then
    current_reconciled=true
  elif [ "$current_started" = false ] && [ "$current_retiring" = false ] && [ "$closing_markers_present" = false ]; then
    current_reconciled=true
  fi
  if [ "$current_reconciled" = true ]; then
    any_started=false
    for started in "$closing_path"/execution_started.* "$closing_path"/execution_retiring.*; do [ -d "$started" ] && any_started=true; done
    terminal_state=clean_failed
    failed_phase=before_remote_mutation
    if [ "$any_started" = true ]; then terminal_state=reconciled_failed; failed_phase=after_reconciled_remote_mutation; fi
    failure="$state_root/bootstrap-operation-$operation_id.json"
    printf '{{"schema_version":"satelle.bootstrap-operation.v1","operation_id":"%s","operation_kind":"%s","terminal_state":"%s","failed_phase":"%s","observed_at":"%s"}}\n' "$operation_id" "$operation_kind" "$terminal_state" "$failed_phase" "$(date -u +%Y-%m-%dT%H:%M:%SZ)" >"$failure"
    chmod 600 "$failure"
    rm -rf "$closing_path"
    return
  fi
  write_value "$closing_path" recovery_pending state
  write_value "$closing_path" 'controller channel closed after remote mutation' recovery_reason
  mv "$closing_path" "$claim_path" 2>/dev/null || true
}}
cleanup() {{
  if [ -n "$pending_path" ] && [ -d "$pending_path" ]; then rm -rf "$pending_path"; fi
  if [ "$claim_published" = true ] && [ "$released" = false ] && same_owner; then
    if [ "$claim_uncertain" = true ]; then
      write_value "$claim_path" recovery_pending state
      write_value "$claim_path" 'phase advance found uncertain execution evidence' recovery_reason
    elif [ "$mutation_started" = true ]; then
      finalize_interrupted_claim
    else
      failure="$state_root/bootstrap-operation-$operation_id.json"
      printf '{{"schema_version":"satelle.bootstrap-operation.v1","operation_id":"%s","operation_kind":"%s","terminal_state":"clean_failed","failed_phase":"before_remote_mutation","observed_at":"%s"}}\n' "$operation_id" "$operation_kind" "$(date -u +%Y-%m-%dT%H:%M:%SZ)" >"$failure"
      chmod 600 "$failure"
      remove_own_claim
    fi
  fi
}}
busy() {{
  if [ -n "$pending_path" ] && [ -d "$pending_path" ]; then rm -rf "$pending_path"; pending_path=; fi
  if [ "$claim_published" = true ]; then remove_own_claim; claim_published=false; fi
  printf '%s\n' '{BUSY}'
  exit 75
}}
trap cleanup EXIT HUP INT TERM
mkdir -p "$state_root"
chmod 700 "$state_root"
if [ -L "$lock_root" ]; then busy; fi
mkdir -p "$lock_root"
[ -d "$lock_root" ] && [ ! -L "$lock_root" ] || busy
chmod 700 "$lock_root"
claim_identity="$(od -An -N16 -tx1 /dev/urandom 2>/dev/null | tr -d ' \n')"
case "$claim_identity" in *[!0-9a-f]*|'') busy;; esac
pending_path="$(mktemp -d "$state_root/bootstrap.pending.$operation_id.XXXXXX")" || busy
chmod 700 "$pending_path"
now="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
write_value "$pending_path" 'satelle.bootstrap-lock.v1' schema_version
write_value "$pending_path" "$operation_id" operation_id
write_value "$pending_path" "$claim_identity" claim_identity
write_value "$pending_path" "$operation_kind" operation_kind
write_value "$pending_path" "$controller_identity" controller_identity
write_value "$pending_path" "$now" acquired_at
write_value "$pending_path" "$now" heartbeat_at
write_value "$pending_path" live state
claim_nonce="${{pending_path##*.}}"
claim_path="$lock_root/claim.$operation_id.$claim_nonce"
pending_name="${{pending_path##*/}}"
mv "$pending_path" "$claim_path" 2>/dev/null || busy
published_identity="$(cat "$claim_path/claim_identity" 2>/dev/null)" || published_identity=
if [ "$published_identity" != "$claim_identity" ]; then
  nested_pending="$claim_path/$pending_name"
  if [ -d "$nested_pending" ] &&
     [ "$(cat "$nested_pending/claim_identity" 2>/dev/null)" = "$claim_identity" ]; then
    rm -rf "$nested_pending"
  fi
  pending_path=
  claim_path=
  busy
fi
pending_path=
claim_published=true
for competitor in "$lock_root"/*; do
  [ -e "$competitor" ] || continue
  [ "$competitor" = "$claim_path" ] && continue
  [ -d "$competitor" ] && [ ! -L "$competitor" ] || busy
  case "${{competitor##*/}}" in claim.*) ;; *) busy;; esac
  observed="$(read_operation "$competitor")" || busy
  case "$observed" in *[!A-Za-z0-9_.@-]*|'') busy;; esac
  heartbeat="$(cat "$competitor/heartbeat_at" 2>/dev/null)" || busy
  heartbeat_epoch="$(date -u -d "$heartbeat" +%s 2>/dev/null || date -j -u -f '%Y-%m-%dT%H:%M:%SZ' "$heartbeat" +%s 2>/dev/null)" || busy
  claim_state="$(cat "$competitor/state" 2>/dev/null)" || busy
  observed_identity="$(cat "$competitor/claim_identity" 2>/dev/null)" || busy
  [ "${{#observed_identity}}" -eq 32 ] || busy
  case "$observed_identity" in *[!0-9a-f]*) busy;; esac
  now_epoch="$(date -u +%s)"
  [ "$((now_epoch - heartbeat_epoch))" -gt {STALE_AFTER_SECONDS} ] || busy
  case "$claim_state" in live|mutation_started|recovery_pending) ;; *) busy;; esac
  claim_operation_kind=
  mutation_phase=
  mutation_attempt=
  execution_started=false
  execution_retiring=false
  execution_succeeded=false
  execution_failed=false
  execution_committed=false
  unexpected_execution_evidence=false
  requires_commit=false
  if [ "$claim_state" != live ]; then
    claim_operation_kind="$(cat "$competitor/operation_kind" 2>/dev/null)" || busy
    mutation_phase="$(cat "$competitor/mutation_phase" 2>/dev/null)" || busy
    mutation_attempt="$(cat "$competitor/mutation_attempt" 2>/dev/null)" || busy
    case "$claim_operation_kind" in initial_setup|missing_daemon_repair) ;; *) busy;; esac
    case "$mutation_phase" in cache_directory_creation|cache_upload|cache_staging_permissions|cache_promotion|daemon_start|state_owner_release|durable_token_verification|maintenance_handoff_begin|maintenance_handoff_complete) ;; *) busy;; esac
    [ "${{#mutation_attempt}}" -eq 32 ] || busy
    case "$mutation_attempt" in *[!0-9a-f]*) busy;; esac
    case "$mutation_phase" in daemon_start|durable_token_verification|maintenance_handoff_begin|maintenance_handoff_complete) requires_commit=true;; esac
    if [ "$requires_commit" = true ]; then expected_terminal_kind=execution_committed; else expected_terminal_kind=execution_succeeded; fi
    expected_terminal_path="$competitor/$expected_terminal_kind.$mutation_attempt"
    [ -d "$competitor/execution_started.$mutation_attempt" ] && [ ! -L "$competitor/execution_started.$mutation_attempt" ] && execution_started=true
    [ -d "$competitor/execution_retiring.$mutation_attempt" ] && [ ! -L "$competitor/execution_retiring.$mutation_attempt" ] && execution_retiring=true
    [ -d "$competitor/execution_succeeded.$mutation_attempt" ] && [ ! -L "$competitor/execution_succeeded.$mutation_attempt" ] && execution_succeeded=true
    [ -d "$competitor/execution_failed.$mutation_attempt" ] && [ ! -L "$competitor/execution_failed.$mutation_attempt" ] && execution_failed=true
    [ -d "$competitor/execution_committed.$mutation_attempt" ] && [ ! -L "$competitor/execution_committed.$mutation_attempt" ] && execution_committed=true
    for marker in "$competitor"/execution_started.* "$competitor"/execution_retiring.* "$competitor"/execution_succeeded.* "$competitor"/execution_failed.* "$competitor"/execution_committed.*; do
      [ -e "$marker" ] || [ -L "$marker" ] || continue
      case "$marker" in
        "$competitor/execution_started.$mutation_attempt"|"$competitor/execution_retiring.$mutation_attempt"|"$expected_terminal_path")
          [ -d "$marker" ] && [ ! -L "$marker" ] || unexpected_execution_evidence=true
          ;;
        "$competitor/execution_succeeded.$mutation_attempt"|"$competitor/execution_failed.$mutation_attempt")
          if [ "$mutation_phase" = daemon_start ] && [ -d "$marker" ] && [ ! -L "$marker" ]; then :; else unexpected_execution_evidence=true; fi
          ;;
        *) unexpected_execution_evidence=true;;
      esac
    done
    if [ "$mutation_phase" = daemon_start ]; then
      valid_daemon_marker_shape=false
      if [ "$execution_started" = false ] && [ "$execution_succeeded" = false ] &&
         [ "$execution_retiring" = false ] && [ "$execution_failed" = false ] && [ "$execution_committed" = false ]; then
        valid_daemon_marker_shape=true
      elif [ "$execution_started" = true ] && [ "$execution_retiring" = false ] && [ "$execution_committed" = false ] &&
           ! {{ [ "$execution_succeeded" = true ] && [ "$execution_failed" = true ]; }}; then
        valid_daemon_marker_shape=true
      elif [ "$execution_started" = true ] && [ "$execution_retiring" = false ] && [ "$execution_committed" = true ] &&
           [ "$execution_failed" = false ]; then
        valid_daemon_marker_shape=true
      elif [ "$execution_started" = false ] && [ "$execution_retiring" = true ] &&
           [ "$execution_failed" = false ]; then
        valid_daemon_marker_shape=true
      fi
      [ "$valid_daemon_marker_shape" = true ] || unexpected_execution_evidence=true
    else
      valid_marker_shape=false
      if [ "$execution_started" = false ] && [ "$execution_retiring" = false ] &&
         [ "$execution_succeeded" = false ] && [ "$execution_committed" = false ]; then
        valid_marker_shape=true
      elif {{ [ "$execution_started" = true ] && [ "$execution_retiring" = false ]; }} ||
           {{ [ "$execution_started" = false ] && [ "$execution_retiring" = true ]; }}; then
        valid_marker_shape=true
      fi
      [ "$valid_marker_shape" = true ] || unexpected_execution_evidence=true
    fi
  fi
  process_probe=null
  if process_output="$(ps -eo pid=,comm=,args= 2>/dev/null)"; then
    if printf '%s\n' "$process_output" | awk -v self="$$" -v parent="$PPID" '$1 != self && $1 != parent && ($2 == "satelle" || $2 == "satelle.exe") && $0 ~ /host start/ {{ found=1 }} END {{ exit !found }}'; then
      process_probe=true
    else
      probe_status=$?
      [ "$probe_status" -eq 1 ] && process_probe=false
    fi
  fi
  process_active=false
  [ "$process_probe" = true ] && process_active=true
  binary_present=false
  if [ -d "$cache_root" ] && find "$cache_root" -type f -name satelle -print -quit 2>/dev/null | grep . >/dev/null 2>&1; then binary_present=true; fi
  service_probe=null
  if command -v systemctl >/dev/null 2>&1; then
    if systemctl --user is-active --quiet satelle-host 2>/dev/null; then
      service_probe=true
    else
      probe_status=$?
      case "$probe_status" in 3|4) service_probe=false;; esac
    fi
  elif command -v launchctl >/dev/null 2>&1; then
    if launchctl print "gui/$(id -u)/satelle-host" >/dev/null 2>&1; then
      service_probe=true
    else
      probe_status=$?
      [ "$probe_status" -eq 113 ] && service_probe=false
    fi
  else
    service_probe=false
  fi
  service_active=false
  [ "$service_probe" = true ] && service_active=true
  daemon_probe=null
  if command -v curl >/dev/null 2>&1; then
    if status="$(curl -sS -o /dev/null -w '%{{http_code}}' --max-time 2 http://127.0.0.1:3001/v1/capabilities 2>/dev/null)"; then
      case "$status" in 000|'') ;; *) daemon_probe=true;; esac
    else
      probe_status=$?
      [ "$probe_status" -eq 7 ] && daemon_probe=false
    fi
  fi
  daemon_active=false
  [ "$daemon_probe" = true ] && daemon_active=true
  record_recovery "$observed" "$process_probe" "$binary_present" "$service_probe" "$daemon_probe"
  terminal_evidence=false
  if [ "$requires_commit" = true ] && [ "$execution_committed" = true ]; then
    terminal_evidence=true
  elif [ "$requires_commit" = false ] && [ "$execution_succeeded" = true ]; then
    terminal_evidence=true
  fi
  operation_allows_daemon_start=false
  case "$claim_operation_kind" in initial_setup|missing_daemon_repair) operation_allows_daemon_start=true;; esac
  launcher_terminal_evidence=false
  if [ "$execution_succeeded" = true ] && [ "$execution_failed" = false ]; then
    launcher_terminal_evidence=true
  elif [ "$execution_succeeded" = false ] && [ "$execution_failed" = true ]; then
    launcher_terminal_evidence=true
  fi
  failed_daemon_start=false
  case "$claim_state" in mutation_started|recovery_pending)
    if [ "$operation_allows_daemon_start" = true ] && [ "$mutation_phase" = daemon_start ] &&
       [ "$execution_started" = true ] && [ "$launcher_terminal_evidence" = true ] &&
       [ "$execution_committed" = false ] && [ "$unexpected_execution_evidence" = false ] &&
       [ "$process_probe" = false ] && [ "$service_probe" = false ] && [ "$daemon_probe" = false ]; then
      failed_daemon_start=true
    fi
    ;;
  esac
  resolved_execution_evidence=false
  if [ "$execution_retiring" = true ] || [ "$terminal_evidence" = true ] || [ "$failed_daemon_start" = true ]; then resolved_execution_evidence=true; fi
  reconciled=false
  if [ "$unexpected_execution_evidence" = false ] &&
     {{ [ "$claim_state" = live ] || [ "$execution_started" = false ] || [ "$resolved_execution_evidence" = true ]; }}; then
    reconciled=true
  fi
  [ "$reconciled" = true ] || busy
  if [ "$process_active" = true ] || [ "$service_active" = true ] || [ "$daemon_active" = true ]; then
    if [ "$execution_started" = true ]; then
      [ "$resolved_execution_evidence" = true ] || busy
    fi
  fi
  quarantine_root="$(mktemp -d "$state_root/bootstrap.quarantine.XXXXXX")" || busy
  chmod 700 "$quarantine_root"
  quarantined_claim="$quarantine_root/claim"
  if ! mv "$competitor" "$quarantined_claim" 2>/dev/null; then rmdir "$quarantine_root"; busy; fi
  moved_operation="$(read_operation "$quarantined_claim")" || {{ restore_competitor; busy; }}
  moved_heartbeat="$(cat "$quarantined_claim/heartbeat_at" 2>/dev/null)" || {{ restore_competitor; busy; }}
  moved_state="$(cat "$quarantined_claim/state" 2>/dev/null)" || {{ restore_competitor; busy; }}
  moved_identity="$(cat "$quarantined_claim/claim_identity" 2>/dev/null)" || {{ restore_competitor; busy; }}
  moved_operation_kind=
  moved_mutation_phase=
  moved_mutation_attempt=
  moved_execution_started=false
  moved_execution_retiring=false
  moved_execution_succeeded=false
  moved_execution_failed=false
  moved_execution_committed=false
  moved_unexpected_execution_evidence=false
  moved_requires_commit=false
  if [ "$moved_state" != live ]; then
    moved_operation_kind="$(cat "$quarantined_claim/operation_kind" 2>/dev/null)" || {{ restore_competitor; busy; }}
    moved_mutation_phase="$(cat "$quarantined_claim/mutation_phase" 2>/dev/null)" || {{ restore_competitor; busy; }}
    moved_mutation_attempt="$(cat "$quarantined_claim/mutation_attempt" 2>/dev/null)" || {{ restore_competitor; busy; }}
    case "$moved_mutation_phase" in daemon_start|durable_token_verification|maintenance_handoff_begin|maintenance_handoff_complete) moved_requires_commit=true;; esac
    if [ "$moved_requires_commit" = true ]; then moved_expected_terminal_kind=execution_committed; else moved_expected_terminal_kind=execution_succeeded; fi
    moved_expected_terminal_path="$quarantined_claim/$moved_expected_terminal_kind.$moved_mutation_attempt"
    [ -d "$quarantined_claim/execution_started.$moved_mutation_attempt" ] && [ ! -L "$quarantined_claim/execution_started.$moved_mutation_attempt" ] && moved_execution_started=true
    [ -d "$quarantined_claim/execution_retiring.$moved_mutation_attempt" ] && [ ! -L "$quarantined_claim/execution_retiring.$moved_mutation_attempt" ] && moved_execution_retiring=true
    [ -d "$quarantined_claim/execution_succeeded.$moved_mutation_attempt" ] && [ ! -L "$quarantined_claim/execution_succeeded.$moved_mutation_attempt" ] && moved_execution_succeeded=true
    [ -d "$quarantined_claim/execution_failed.$moved_mutation_attempt" ] && [ ! -L "$quarantined_claim/execution_failed.$moved_mutation_attempt" ] && moved_execution_failed=true
    [ -d "$quarantined_claim/execution_committed.$moved_mutation_attempt" ] && [ ! -L "$quarantined_claim/execution_committed.$moved_mutation_attempt" ] && moved_execution_committed=true
    for marker in "$quarantined_claim"/execution_started.* "$quarantined_claim"/execution_retiring.* "$quarantined_claim"/execution_succeeded.* "$quarantined_claim"/execution_failed.* "$quarantined_claim"/execution_committed.*; do
      [ -e "$marker" ] || [ -L "$marker" ] || continue
      case "$marker" in
        "$quarantined_claim/execution_started.$moved_mutation_attempt"|"$quarantined_claim/execution_retiring.$moved_mutation_attempt"|"$moved_expected_terminal_path")
          [ -d "$marker" ] && [ ! -L "$marker" ] || moved_unexpected_execution_evidence=true
          ;;
        "$quarantined_claim/execution_succeeded.$moved_mutation_attempt"|"$quarantined_claim/execution_failed.$moved_mutation_attempt")
          if [ "$moved_mutation_phase" = daemon_start ] && [ -d "$marker" ] && [ ! -L "$marker" ]; then :; else moved_unexpected_execution_evidence=true; fi
          ;;
        *) moved_unexpected_execution_evidence=true;;
      esac
    done
    if [ "$moved_mutation_phase" = daemon_start ]; then
      moved_valid_daemon_marker_shape=false
      if [ "$moved_execution_started" = false ] && [ "$moved_execution_succeeded" = false ] &&
         [ "$moved_execution_retiring" = false ] && [ "$moved_execution_failed" = false ] && [ "$moved_execution_committed" = false ]; then
        moved_valid_daemon_marker_shape=true
      elif [ "$moved_execution_started" = true ] && [ "$moved_execution_retiring" = false ] && [ "$moved_execution_committed" = false ] &&
           ! {{ [ "$moved_execution_succeeded" = true ] && [ "$moved_execution_failed" = true ]; }}; then
        moved_valid_daemon_marker_shape=true
      elif [ "$moved_execution_started" = true ] && [ "$moved_execution_retiring" = false ] && [ "$moved_execution_committed" = true ] &&
           [ "$moved_execution_failed" = false ]; then
        moved_valid_daemon_marker_shape=true
      elif [ "$moved_execution_started" = false ] && [ "$moved_execution_retiring" = true ] &&
           [ "$moved_execution_failed" = false ]; then
        moved_valid_daemon_marker_shape=true
      fi
      [ "$moved_valid_daemon_marker_shape" = true ] || moved_unexpected_execution_evidence=true
    else
      moved_valid_marker_shape=false
      if [ "$moved_execution_started" = false ] && [ "$moved_execution_retiring" = false ] &&
         [ "$moved_execution_succeeded" = false ] && [ "$moved_execution_committed" = false ]; then
        moved_valid_marker_shape=true
      elif {{ [ "$moved_execution_started" = true ] && [ "$moved_execution_retiring" = false ]; }} ||
           {{ [ "$moved_execution_started" = false ] && [ "$moved_execution_retiring" = true ]; }}; then
        moved_valid_marker_shape=true
      fi
      [ "$moved_valid_marker_shape" = true ] || moved_unexpected_execution_evidence=true
    fi
  fi
  if [ "$moved_operation" != "$observed" ] || [ "$moved_identity" != "$observed_identity" ] || [ "$moved_heartbeat" != "$heartbeat" ] ||
     [ "$moved_state" != "$claim_state" ] || [ "$moved_operation_kind" != "$claim_operation_kind" ] ||
     [ "$moved_mutation_phase" != "$mutation_phase" ] || [ "$moved_mutation_attempt" != "$mutation_attempt" ] ||
     [ "$moved_execution_started" != "$execution_started" ] || [ "$moved_execution_retiring" != "$execution_retiring" ] ||
     [ "$moved_execution_succeeded" != "$execution_succeeded" ] ||
     [ "$moved_execution_failed" != "$execution_failed" ] ||
     [ "$moved_execution_committed" != "$execution_committed" ] ||
     [ "$moved_unexpected_execution_evidence" != "$unexpected_execution_evidence" ]; then
    restore_competitor
    busy
  fi
  if [ "$failed_daemon_start" = true ]; then
    post_process_probe=null
    if process_output="$(ps -eo pid=,comm=,args= 2>/dev/null)"; then
      if printf '%s\n' "$process_output" | awk -v self="$$" -v parent="$PPID" '$1 != self && $1 != parent && ($2 == "satelle" || $2 == "satelle.exe") && $0 ~ /host start/ {{ found=1 }} END {{ exit !found }}'; then
        post_process_probe=true
      else
        probe_status=$?
        [ "$probe_status" -eq 1 ] && post_process_probe=false
      fi
    fi
    post_service_probe=null
    if command -v systemctl >/dev/null 2>&1; then
      if systemctl --user is-active --quiet satelle-host 2>/dev/null; then post_service_probe=true; else
        probe_status=$?
        case "$probe_status" in 3|4) post_service_probe=false;; esac
      fi
    elif command -v launchctl >/dev/null 2>&1; then
      if launchctl print "gui/$(id -u)/satelle-host" >/dev/null 2>&1; then post_service_probe=true; else
        probe_status=$?
        [ "$probe_status" -eq 113 ] && post_service_probe=false
      fi
    else
      post_service_probe=false
    fi
    post_daemon_probe=null
    if command -v curl >/dev/null 2>&1; then
      if status="$(curl -sS -o /dev/null -w '%{{http_code}}' --max-time 2 http://127.0.0.1:3001/v1/capabilities 2>/dev/null)"; then
        case "$status" in 000|'') ;; *) post_daemon_probe=true;; esac
      else
        probe_status=$?
        [ "$probe_status" -eq 7 ] && post_daemon_probe=false
      fi
    fi
    record_recovery "$observed" "$post_process_probe" "$binary_present" "$post_service_probe" "$post_daemon_probe"
    if [ "$post_process_probe" != false ] || [ "$post_service_probe" != false ] || [ "$post_daemon_probe" != false ]; then
      restore_competitor
      busy
    fi
  fi
  rm -rf "$quarantine_root"
done
for competitor in "$lock_root"/*; do
  [ -e "$competitor" ] || continue
  [ "$competitor" = "$claim_path" ] || busy
done
same_owner || busy
printf '%s %s %s\n' '{READY}' "$claim_identity" "${{claim_path##*/}}"
while IFS= read -r line; do
  same_owner || exit 75
  if [ "$line" = '{HEARTBEAT}' ]; then
    write_value "$claim_path" "$(date -u +%Y-%m-%dT%H:%M:%SZ)" heartbeat_at
    continue
  fi
  case "$line" in
    '{MUTATION_STARTED} '*)
      payload="${{line#'{MUTATION_STARTED} '}}"
      set -- $payload
      [ "$#" -eq 2 ] || exit 64
      phase="$1"
      attempt="$2"
      case "$phase" in *[!A-Za-z0-9_-]*|'') exit 64;; esac
      [ "${{#attempt}}" -eq 32 ] || exit 64
      case "$attempt" in *[!0-9a-f]*) exit 64;; esac
      if [ "$mutation_started" = true ]; then
        if [ "$attempt" = "$mutation_attempt" ] || ! retire_terminal_attempt "$mutation_phase" "$mutation_attempt"; then
          claim_uncertain=true
          exit 75
        fi
      elif has_execution_markers; then
        claim_uncertain=true
        exit 75
      fi
      write_value "$claim_path" "$phase" mutation_phase
      write_value "$claim_path" "$attempt" mutation_attempt
      write_value "$claim_path" mutation_started state
      mutation_started=true
      mutation_phase="$phase"
      mutation_attempt="$attempt"
      ;;
    '{MUTATION_COMMITTED} '*)
      payload="${{line#'{MUTATION_COMMITTED} '}}"
      set -- $payload
      [ "$#" -eq 2 ] && [ "$1" = "$mutation_phase" ] && [ "$2" = "$mutation_attempt" ] || exit 75
      [ -d "$claim_path/execution_started.$mutation_attempt" ] || exit 75
      mkdir "$claim_path/execution_committed.$mutation_attempt" || exit 75
      ;;
    '{MUTATION_EXECUTING} '*)
      payload="${{line#'{MUTATION_EXECUTING} '}}"
      set -- $payload
      [ "$#" -eq 2 ] && [ "$1" = "$mutation_phase" ] && [ "$2" = "$mutation_attempt" ] || exit 75
      mkdir "$claim_path/execution_started.$mutation_attempt" || exit 75
      ;;
    '{RELEASE}')
      same_owner || exit 75
      remove_own_claim
      claim_published=false
      released=true
      printf '%s\n' "$line"
      break
      ;;
  esac
  printf '%s\n' "$line"
done"#,
        )
    }
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct InvalidRequest {
    field: &'static str,
}

impl std::fmt::Display for InvalidRequest {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            formatter,
            "{} is not a valid Bootstrap Lock token",
            self.field
        )
    }
}

impl std::error::Error for InvalidRequest {}

fn validated_token(value: String, field: &'static str) -> Result<String, InvalidRequest> {
    if value.is_empty()
        || value.len() > 128
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b'@'))
    {
        return Err(InvalidRequest { field });
    }
    Ok(value)
}

fn posix_quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', "'\"'\"'"))
}

fn powershell_quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', "''"))
}

pub(super) fn mutation_started_line(phase: &str, attempt: &str) -> Result<String, InvalidRequest> {
    let phase = validated_token(phase.to_string(), "mutation phase")?;
    let attempt = validated_identity(attempt, "mutation attempt")?;
    Ok(format!("{MUTATION_STARTED} {phase} {attempt}"))
}

pub(super) fn mutation_committed_line(
    phase: &str,
    attempt: &str,
) -> Result<String, InvalidRequest> {
    let phase = validated_token(phase.to_string(), "mutation phase")?;
    let attempt = validated_identity(attempt, "mutation attempt")?;
    Ok(format!("{MUTATION_COMMITTED} {phase} {attempt}"))
}

pub(super) fn mutation_executing_line(
    phase: &str,
    attempt: &str,
) -> Result<String, InvalidRequest> {
    let phase = validated_token(phase.to_string(), "mutation phase")?;
    let attempt = validated_identity(attempt, "mutation attempt")?;
    Ok(format!("{MUTATION_EXECUTING} {phase} {attempt}"))
}

fn validated_identity<'a>(value: &'a str, field: &'static str) -> Result<&'a str, InvalidRequest> {
    if value.len() != 32
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(InvalidRequest { field });
    }
    Ok(value)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(unix)]
    use std::fs;
    #[cfg(unix)]
    use std::io::{BufRead, BufReader, Write};
    #[cfg(unix)]
    use std::os::unix::fs::PermissionsExt;
    #[cfg(unix)]
    use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};

    fn request() -> Request {
        Request::new(
            "operation-1",
            OperationKind::MissingDaemonRepair,
            Some("controller@test".to_string()),
        )
        .expect("valid request")
    }

    #[cfg(unix)]
    fn claim_directories(lock_root: &std::path::Path) -> Vec<std::path::PathBuf> {
        let mut claims = fs::read_dir(lock_root)
            .expect("read stable lock root")
            .map(|entry| entry.expect("read lock entry").path())
            .filter(|path| {
                path.is_dir()
                    && path
                        .file_name()
                        .is_some_and(|name| name.to_string_lossy().starts_with("claim."))
            })
            .collect::<Vec<_>>();
        claims.sort();
        claims
    }

    #[cfg(unix)]
    fn only_claim(lock_root: &std::path::Path) -> std::path::PathBuf {
        let claims = claim_directories(lock_root);
        assert_eq!(claims.len(), 1, "expected one active claim: {claims:?}");
        claims.into_iter().next().expect("one active claim")
    }

    #[cfg(unix)]
    fn write_claim(path: &std::path::Path, operation_id: &str, heartbeat: &str, state: &str) {
        fs::create_dir_all(path).expect("create claim");
        fs::write(path.join("operation_id"), format!("{operation_id}\n"))
            .expect("write operation id");
        fs::write(path.join("heartbeat_at"), format!("{heartbeat}\n")).expect("write heartbeat");
        fs::write(path.join("state"), format!("{state}\n")).expect("write claim state");
        fs::write(
            path.join("claim_identity"),
            "0123456789abcdef0123456789abcdef\n",
        )
        .expect("write claim identity");
    }

    #[test]
    fn request_tokens_reject_command_injection() {
        for invalid in ["", "../escape", "line\nbreak", "quote'", "space value"] {
            assert!(
                Request::new(invalid, OperationKind::InitialSetup, None).is_err(),
                "{invalid:?} must not reach a remote shell"
            );
        }
    }

    #[test]
    fn posix_protocol_is_atomic_owner_checked_and_recoverable() {
        let command = request().posix_command();
        for required in [
            "mkdir -p \"$lock_root\"",
            "bootstrap.pending.",
            "claim.$operation_id.",
            "claim_identity",
            "/dev/urandom",
            "mv \"$pending_path\" \"$claim_path\"",
            "published_identity",
            "bootstrap.quarantine.",
            "operation_id",
            "controller_identity",
            "acquired_at",
            "heartbeat_at",
            HEARTBEAT,
            "ps -eo pid=,comm=,args=",
            "binary_present",
            "systemctl --user is-active",
            "launchctl print",
            "/v1/capabilities",
            "read_operation \"$competitor\"",
            "remove_own_claim",
            "execution_started.",
            "execution_retiring.",
            "execution_succeeded.",
            "execution_failed.",
            "execution_committed.",
            "finalize_interrupted_claim",
            "recovery_pending",
            "clean_failed",
        ] {
            assert!(command.contains(required), "missing {required:?}");
        }
        assert!(!command.contains("scp "));
    }

    #[test]
    fn windows_protocol_is_atomic_owner_checked_and_recoverable() {
        let script = request().windows_script();
        for required in [
            "New-Item -ItemType Directory -Force -Path $lockRoot",
            "bootstrap.pending.",
            "claim.' + $operationId",
            "claim_identity",
            "[IO.Directory]::Move($pendingPath, $claimPath)",
            "bootstrap.quarantine.",
            "SetAccessRuleProtection($true, $false)",
            "operation_id",
            "controller_identity",
            "acquired_at",
            "heartbeat_at",
            HEARTBEAT,
            "Get-CimInstance Win32_Process",
            "Get-ChildItem",
            "Get-CimInstance Win32_Service",
            "/v1/capabilities",
            "catch { Fail-Busy }",
            "Remove-OwnClaim",
            "execution_started.",
            "execution_retiring.",
            "execution_succeeded.",
            "execution_failed.",
            "execution_committed.",
            "$executionStarted -and",
            "$terminalEvidence",
            "Finalize-InterruptedClaim",
            "recovery_pending",
            "clean_failed",
        ] {
            assert!(script.contains(required), "missing {required:?}");
        }
    }

    #[test]
    fn windows_stale_recovery_operation_kind_allowlist_is_closed() {
        let script = request().windows_script();
        assert!(
            script.contains(
                "$claimOperationKind -cnotin @('initial_setup', 'missing_daemon_repair')"
            )
        );
    }

    #[test]
    fn windows_active_daemon_fence_distinguishes_preexecution_and_started_claims() {
        let script = request().windows_script();
        assert!(script.contains(
            "$terminalEvidence = ($requiresCommit -and $executionCommitted) -or\n    ((-not $requiresCommit) -and $executionSucceeded)"
        ));
        assert!(script.contains(
            "if (($processActive -or $serviceActive -or $daemonActive) -and\n      $executionStarted -and\n      -not $resolvedExecutionEvidence) { Fail-Busy }"
        ));
        assert!(
            script.contains(
                "$reconciled = (-not $unexpectedExecutionEvidence) -and\n    (($claimState -ceq 'live') -or (-not $executionStarted) -or $resolvedExecutionEvidence)"
            )
        );
    }

    #[test]
    fn windows_failed_daemon_start_recovery_requires_exact_inactive_evidence() {
        let script = request().windows_script();
        assert!(script.contains("$unexpectedExecutionEvidence ="));
        assert!(script.contains(
            "$failedDaemonStart = ($claimState -cin @('mutation_started', 'recovery_pending')) -and"
        ));
        assert!(script.contains("($mutationPhase -ceq 'daemon_start') -and"));
        assert!(
            script.contains(
                "$executionStarted -and ($executionSucceeded -xor $executionFailed) -and"
            )
        );
        assert!(
            script.contains(
                "(-not $executionCommitted) -and (-not $unexpectedExecutionEvidence) -and"
            )
        );
        assert!(script.contains(
            "($processProbe -eq $false) -and ($serviceProbe -eq $false) -and ($daemonProbe -eq $false)"
        ));
        assert!(script.contains("if ($failedDaemonStart)"));
        assert!(script.contains("$postProcessProbe -ne $false"));
        assert!(
            script.contains("Restore-Competitor $item.FullName $quarantineRoot $quarantinedClaim")
        );
        assert!(script.contains("$terminalEvidence -or $failedDaemonStart"));
    }

    #[test]
    fn retirement_sentinel_is_the_commit_point_and_is_removed_last() {
        let posix = request().posix_command();
        let posix_rename = posix
            .find("mv \"$started_path\" \"$retiring_path\"")
            .expect("POSIX retirement commit point");
        let posix_terminal = posix
            .find("rmdir \"$terminal_path\"")
            .expect("POSIX terminal retirement");
        let posix_launcher = posix
            .find("rmdir \"$launcher_terminal_path\"")
            .expect("POSIX launcher terminal retirement");
        let posix_retiring = posix
            .find("rmdir \"$retiring_path\"")
            .expect("POSIX sentinel retirement");
        assert!(posix_rename < posix_terminal);
        assert!(posix_terminal < posix_launcher);
        assert!(posix_launcher < posix_retiring);

        let windows = request().windows_script();
        let windows_rename = windows
            .find("[IO.File]::Move($startedPath, $retiringPath)")
            .expect("Windows retirement commit point");
        let windows_terminal = windows
            .find("Remove-Item -LiteralPath $terminalPath")
            .expect("Windows terminal retirement");
        let windows_launcher = windows
            .find("Remove-Item -LiteralPath (Join-Path $claimPath $launcherTerminalName)")
            .expect("Windows launcher terminal retirement");
        let windows_retiring = windows
            .find("Remove-Item -LiteralPath $retiringPath")
            .expect("Windows sentinel retirement");
        assert!(windows_rename < windows_terminal);
        assert!(windows_terminal < windows_launcher);
        assert!(windows_launcher < windows_retiring);
    }

    #[test]
    fn windows_phase_advance_retires_only_exact_terminal_attempt_evidence() {
        let script = request().windows_script();
        assert!(script.contains("function Retire-TerminalAttempt"));
        assert!(script.contains("$priorRequiresCommit = $PriorPhase -cin @('daemon_start'"));
        assert!(
            script.contains("$priorUsesSuccess = $PriorPhase -cin @('cache_directory_creation'")
        );
        assert!(!script.contains("$PriorPhase -in @("));
        assert!(script.contains("$allowedMarkers = @($startedName, $terminalName)"));
        assert!(script.contains("if ($foreignMarkers.Count -ne 0) { return $false }"));
        let started_rename = script
            .find("[IO.File]::Move($startedPath, $retiringPath)")
            .expect("retirement commit point");
        let terminal_remove = script
            .find("Remove-Item -LiteralPath $terminalPath")
            .expect("terminal marker retirement");
        let retiring_remove = script
            .find("Remove-Item -LiteralPath $retiringPath")
            .expect("retiring marker retirement");
        assert!(started_rename < terminal_remove);
        assert!(terminal_remove < retiring_remove);
        assert!(script.contains("$claimUncertain = $true"));
    }

    #[test]
    fn windows_stale_recovery_expected_markers_follow_the_exact_phase_contract() {
        let script = request().windows_script();
        assert!(script.contains(
            "$expectedTerminalMarker = if ($requiresCommit) { 'execution_committed.' + $mutationAttempt } else { 'execution_succeeded.' + $mutationAttempt }"
        ));
        assert!(script.contains(
            "$expectedExecutionMarkers = @('execution_started.' + $mutationAttempt, 'execution_retiring.' + $mutationAttempt, $expectedTerminalMarker)"
        ));
        assert!(script.contains(
            "$movedExpectedTerminalMarker = if ($movedRequiresCommit) { 'execution_committed.' + $movedMutationAttempt } else { 'execution_succeeded.' + $movedMutationAttempt }"
        ));
        assert!(script.contains(
            "$movedExpectedExecutionMarkers = @('execution_started.' + $movedMutationAttempt, 'execution_retiring.' + $movedMutationAttempt, $movedExpectedTerminalMarker)"
        ));
    }

    #[test]
    fn interrupted_cleanup_renames_before_observing_execution_markers() {
        let posix = request().posix_script();
        let posix_rename = posix
            .find("mv \"$claim_path\" \"$closing_path\"")
            .expect("POSIX cleanup atomically renames the exact claim");
        let posix_observe = posix
            .find("$closing_path/execution_started.$mutation_attempt")
            .expect("POSIX cleanup observes the moved marker");
        assert!(posix_rename < posix_observe);

        let windows = request().windows_script();
        let windows_rename = windows
            .find("[IO.Directory]::Move($claimPath, $closingPath)")
            .expect("Windows cleanup atomically renames the exact claim");
        let windows_observe = windows
            .find("$closingPath ('execution_started.' + $mutationAttempt)")
            .expect("Windows cleanup observes the moved marker");
        assert!(windows_rename < windows_observe);
    }

    #[test]
    fn every_remote_mutation_protocol_line_has_one_closed_token() {
        let attempt = "0123456789abcdef0123456789abcdef";
        assert_eq!(
            mutation_started_line("cache_promotion", attempt).unwrap(),
            format!("satelle-bootstrap-mutation-started-v1 cache_promotion {attempt}")
        );
        assert!(mutation_started_line("invalid phase", attempt).is_err());
        assert!(mutation_started_line("cache_promotion", "invalid").is_err());
        assert_eq!(
            mutation_committed_line("daemon_start", attempt).unwrap(),
            format!("satelle-bootstrap-mutation-committed-v1 daemon_start {attempt}")
        );
        assert_eq!(
            mutation_executing_line("maintenance_handoff_begin", attempt).unwrap(),
            format!("satelle-bootstrap-mutation-executing-v1 maintenance_handoff_begin {attempt}")
        );
        assert_eq!(RELEASE, "satelle-bootstrap-release-v1");
    }

    #[cfg(unix)]
    struct RunningProtocol {
        child: Child,
        stdin: ChildStdin,
        stdout: BufReader<ChildStdout>,
    }

    #[cfg(unix)]
    impl RunningProtocol {
        fn start(request: &Request, state_home: &std::path::Path) -> Self {
            Self::start_with_path(request, state_home, None)
        }

        fn start_with_path(
            request: &Request,
            state_home: &std::path::Path,
            path: Option<&std::ffi::OsStr>,
        ) -> Self {
            let mut command = Command::new("sh");
            command
                .arg("-c")
                .arg(request.posix_script())
                .env("XDG_STATE_HOME", state_home)
                .env("XDG_CACHE_HOME", state_home.join("cache"))
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped());
            if let Some(path) = path {
                command.env("PATH", path);
            }
            let mut child = command.spawn().expect("spawn Bootstrap Lock protocol");
            let stdin = child.stdin.take().expect("piped stdin");
            let stdout = BufReader::new(child.stdout.take().expect("piped stdout"));
            Self {
                child,
                stdin,
                stdout,
            }
        }

        fn read_line(&mut self) -> String {
            let mut line = String::new();
            self.stdout
                .read_line(&mut line)
                .expect("read Bootstrap Lock response");
            line.trim_end().to_string()
        }

        fn exchange(&mut self, line: &str) {
            writeln!(self.stdin, "{line}").expect("write Bootstrap Lock request");
            self.stdin.flush().expect("flush Bootstrap Lock request");
            assert_eq!(self.read_line(), line);
        }

        fn close(mut self) -> std::process::ExitStatus {
            drop(self.stdin);
            self.child.wait().expect("wait for Bootstrap Lock protocol")
        }
    }

    #[cfg(unix)]
    fn assert_ready_line(line: &str) {
        let mut fields = line.split(' ');
        assert_eq!(fields.next(), Some(READY));
        let identity = fields
            .next()
            .expect("ready response carries its claim generation");
        let basename = fields
            .next()
            .expect("ready response carries its exact published claim");
        assert!(fields.next().is_none());
        assert_eq!(identity.len(), 32);
        assert!(
            identity
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        );
        assert!(basename.starts_with("claim."));
        assert!(!basename.ends_with(".closing"));
    }

    #[cfg(unix)]
    fn path_with_daemon_probe_script(
        root: &std::path::Path,
        curl_script: &str,
    ) -> std::ffi::OsString {
        let bin = root.join("probe-bin");
        fs::create_dir(&bin).expect("create probe bin");
        for (name, script) in [
            ("ps", "#!/bin/sh\nexit 0\n"),
            ("systemctl", "#!/bin/sh\nexit 3\n"),
            ("curl", curl_script),
        ] {
            let executable = bin.join(name);
            fs::write(&executable, script).expect("write deterministic recovery probe");
            let mut permissions = fs::metadata(&executable)
                .expect("recovery probe metadata")
                .permissions();
            permissions.set_mode(0o700);
            fs::set_permissions(&executable, permissions).expect("make recovery probe executable");
        }

        let inherited = std::env::var_os("PATH").unwrap_or_default();
        std::env::join_paths(std::iter::once(bin).chain(std::env::split_paths(&inherited)))
            .expect("prepend daemon probe to PATH")
    }

    #[cfg(unix)]
    fn path_with_active_daemon_probe(root: &std::path::Path) -> std::ffi::OsString {
        path_with_daemon_probe_script(root, "#!/bin/sh\nprintf '200'\n")
    }

    #[cfg(unix)]
    fn path_with_inactive_daemon_probe(root: &std::path::Path) -> std::ffi::OsString {
        path_with_daemon_probe_script(root, "#!/bin/sh\nexit 7\n")
    }

    #[cfg(unix)]
    fn path_with_unknown_daemon_probe(root: &std::path::Path) -> std::ffi::OsString {
        path_with_daemon_probe_script(root, "#!/bin/sh\nexit 28\n")
    }

    #[cfg(unix)]
    fn path_with_racing_daemon_probe(root: &std::path::Path) -> std::ffi::OsString {
        let calls = root.join("daemon-probe-calls");
        path_with_daemon_probe_script(
            root,
            &format!(
                "#!/bin/sh\nif [ -e '{}' ]; then printf '200'; else : >'{}'; exit 7; fi\n",
                calls.display(),
                calls.display()
            ),
        )
    }

    #[cfg(unix)]
    fn write_stale_mutation_claim(
        lock_root: &std::path::Path,
        phase: &str,
        attempt: &str,
    ) -> std::path::PathBuf {
        let claim = lock_root.join("claim.operation-1.stale");
        write_claim(
            &claim,
            "operation-1",
            "2000-01-01T00:00:00Z",
            "recovery_pending",
        );
        fs::write(claim.join("operation_kind"), "missing_daemon_repair\n")
            .expect("write operation kind");
        fs::write(claim.join("mutation_phase"), format!("{phase}\n"))
            .expect("write mutation phase");
        fs::write(claim.join("mutation_attempt"), format!("{attempt}\n"))
            .expect("write mutation attempt");
        claim
    }

    #[cfg(unix)]
    #[test]
    fn posix_protocol_serializes_owners_and_releases_cleanly() {
        let state_home = tempfile::tempdir().expect("temporary state home");
        let state_root = state_home.path().join("satelle");
        let lock_root = state_root.join("bootstrap.lock");
        let mut owner = RunningProtocol::start(&request(), state_home.path());
        assert_ready_line(&owner.read_line());
        assert_eq!(
            fs::metadata(&lock_root)
                .expect("stable lock root metadata")
                .permissions()
                .mode()
                & 0o777,
            0o700
        );
        assert_eq!(
            fs::read_to_string(only_claim(&lock_root).join("operation_id"))
                .expect("operation id")
                .trim(),
            "operation-1"
        );

        let contender = RunningProtocol::start(
            &Request::new("operation-2", OperationKind::MissingDaemonRepair, None)
                .expect("valid contender"),
            state_home.path(),
        );
        let mut contender = contender;
        assert_eq!(contender.read_line(), BUSY);
        assert_eq!(contender.close().code(), Some(75));

        writeln!(owner.stdin, "{HEARTBEAT}").expect("write heartbeat");
        owner.stdin.flush().expect("flush heartbeat");
        owner.exchange("satelle-bootstrap-confirm-test");
        owner.exchange(RELEASE);
        assert!(owner.close().success());
        assert!(lock_root.exists());
        assert!(claim_directories(&lock_root).is_empty());
    }

    #[cfg(unix)]
    #[test]
    fn release_removes_only_the_owners_unique_claim() {
        let state_home = tempfile::tempdir().expect("temporary state home");
        let lock_root = state_home.path().join("satelle/bootstrap.lock");
        let mut owner = RunningProtocol::start(&request(), state_home.path());
        assert_ready_line(&owner.read_line());
        let foreign = lock_root.join("claim.operation-2.foreign");
        write_claim(&foreign, "operation-2", "2000-01-01T00:00:00Z", "live");

        owner.exchange(RELEASE);
        assert!(owner.close().success());
        assert_eq!(
            fs::read_to_string(foreign.join("operation_id"))
                .expect("foreign claim remains")
                .trim(),
            "operation-2"
        );
    }

    #[cfg(unix)]
    #[test]
    fn posix_protocol_distinguishes_clean_and_uncertain_failures() {
        let state_home = tempfile::tempdir().expect("temporary state home");
        let state_root = state_home.path().join("satelle");
        let lock_root = state_root.join("bootstrap.lock");

        let mut clean = RunningProtocol::start(&request(), state_home.path());
        assert_ready_line(&clean.read_line());
        assert!(clean.close().success());
        assert!(claim_directories(&lock_root).is_empty());
        let clean_record =
            fs::read_to_string(state_root.join("bootstrap-operation-operation-1.json"))
                .expect("clean failure record");
        assert!(clean_record.contains("\"terminal_state\":\"clean_failed\""));

        let mut uncertain = RunningProtocol::start(&request(), state_home.path());
        assert_ready_line(&uncertain.read_line());
        let attempt = "0123456789abcdef0123456789abcdef";
        uncertain.exchange(
            &mutation_started_line("cache_promotion", attempt).expect("valid mutation phase"),
        );
        fs::create_dir(only_claim(&lock_root).join(format!("execution_started.{attempt}")))
            .expect("record remote mutation start");
        assert!(uncertain.close().success());
        let uncertain_claim = only_claim(&lock_root);
        assert_eq!(
            fs::read_to_string(uncertain_claim.join("state"))
                .expect("lock state")
                .trim(),
            "recovery_pending"
        );
    }

    #[cfg(unix)]
    #[test]
    fn posix_protocol_recovers_only_the_observed_stale_live_owner() {
        let state_home = tempfile::tempdir().expect("temporary state home");
        let state_root = state_home.path().join("satelle");
        let lock_root = state_root.join("bootstrap.lock");
        let stale_claim = lock_root.join("claim.operation-1.stale");
        write_claim(&stale_claim, "operation-1", "2000-01-01T00:00:00Z", "live");

        let replacement_request =
            Request::new("operation-2", OperationKind::MissingDaemonRepair, None)
                .expect("valid replacement");
        let mut replacement = RunningProtocol::start(&replacement_request, state_home.path());
        assert_ready_line(&replacement.read_line());
        assert_eq!(
            fs::read_to_string(only_claim(&lock_root).join("operation_id"))
                .expect("replacement operation")
                .trim(),
            "operation-2"
        );
        assert!(
            state_root
                .join("bootstrap-recovery-operation-1.json")
                .exists()
        );

        replacement.exchange(RELEASE);
        assert!(replacement.close().success());
    }

    #[cfg(unix)]
    #[test]
    fn active_daemon_recovers_preexecution_claims_but_fences_execution_started_claim() {
        let clean_home = tempfile::tempdir().expect("temporary clean state home");
        let clean_root = clean_home.path().join("satelle");
        let clean_lock = clean_root.join("bootstrap.lock");
        write_claim(
            &clean_lock.join("claim.operation-1.stale"),
            "operation-1",
            "2000-01-01T00:00:00Z",
            "live",
        );
        let active_probe_path = path_with_active_daemon_probe(clean_home.path());
        let replacement_request =
            Request::new("operation-2", OperationKind::MissingDaemonRepair, None)
                .expect("valid replacement");
        let mut replacement = RunningProtocol::start_with_path(
            &replacement_request,
            clean_home.path(),
            Some(&active_probe_path),
        );
        assert_ready_line(&replacement.read_line());
        assert!(
            fs::read_to_string(clean_root.join("bootstrap-recovery-operation-1.json"))
                .expect("clean stale recovery record")
                .contains("\"daemon_probe\":true")
        );
        replacement.exchange(RELEASE);
        assert!(replacement.close().success());

        let attempt = "0123456789abcdef0123456789abcdef";
        let write_stale_started_claim = |lock_root: &std::path::Path| {
            let claim = lock_root.join("claim.operation-1.stale");
            write_claim(
                &claim,
                "operation-1",
                "2000-01-01T00:00:00Z",
                "mutation_started",
            );
            fs::write(claim.join("operation_kind"), "missing_daemon_repair\n")
                .expect("write operation kind");
            fs::write(claim.join("mutation_phase"), "cache_promotion\n")
                .expect("write mutation phase");
            fs::write(claim.join("mutation_attempt"), format!("{attempt}\n"))
                .expect("write mutation attempt");
            claim
        };

        let preexecution_home = tempfile::tempdir().expect("temporary preexecution state home");
        let preexecution_root = preexecution_home.path().join("satelle");
        let preexecution_lock = preexecution_root.join("bootstrap.lock");
        write_stale_started_claim(&preexecution_lock);
        let active_probe_path = path_with_active_daemon_probe(preexecution_home.path());
        let mut replacement = RunningProtocol::start_with_path(
            &replacement_request,
            preexecution_home.path(),
            Some(&active_probe_path),
        );
        assert_ready_line(&replacement.read_line());
        assert!(
            fs::read_to_string(preexecution_root.join("bootstrap-recovery-operation-1.json"))
                .expect("preexecution stale recovery record")
                .contains("\"daemon_probe\":true")
        );
        replacement.exchange(RELEASE);
        assert!(replacement.close().success());

        let succeeded_home = tempfile::tempdir().expect("temporary succeeded state home");
        let succeeded_lock = succeeded_home.path().join("satelle/bootstrap.lock");
        let succeeded_claim = write_stale_started_claim(&succeeded_lock);
        fs::create_dir(succeeded_claim.join(format!("execution_started.{attempt}")))
            .expect("record exact execution start");
        fs::create_dir(succeeded_claim.join(format!("execution_succeeded.{attempt}")))
            .expect("record exact execution success");
        let active_probe_path = path_with_active_daemon_probe(succeeded_home.path());
        let mut recovered = RunningProtocol::start_with_path(
            &replacement_request,
            succeeded_home.path(),
            Some(&active_probe_path),
        );
        assert_ready_line(&recovered.read_line());
        recovered.exchange(RELEASE);
        assert!(recovered.close().success());

        let started_home = tempfile::tempdir().expect("temporary started state home");
        let started_lock = started_home.path().join("satelle/bootstrap.lock");
        let started_claim = write_stale_started_claim(&started_lock);
        fs::create_dir(started_claim.join(format!("execution_started.{attempt}")))
            .expect("record exact execution start");
        let active_probe_path = path_with_active_daemon_probe(started_home.path());
        let mut contender = RunningProtocol::start_with_path(
            &replacement_request,
            started_home.path(),
            Some(&active_probe_path),
        );
        assert_eq!(contender.read_line(), BUSY);
        assert_eq!(contender.close().code(), Some(75));
        assert_eq!(
            fs::read_to_string(only_claim(&started_lock).join("operation_id"))
                .expect("started claim remains fenced")
                .trim(),
            "operation-1"
        );
    }

    #[cfg(unix)]
    #[test]
    fn failed_daemon_start_recovers_only_with_exact_inactive_postconditions() {
        let attempt = "0123456789abcdef0123456789abcdef";
        let other_attempt = "fedcba9876543210fedcba9876543210";
        let replacement_request =
            Request::new("operation-2", OperationKind::MissingDaemonRepair, None)
                .expect("valid replacement");

        for terminal in ["execution_failed", "execution_succeeded"] {
            let terminal_home = tempfile::tempdir().expect("temporary terminal start home");
            let terminal_root = terminal_home.path().join("satelle");
            let terminal_lock = terminal_root.join("bootstrap.lock");
            let terminal_claim =
                write_stale_mutation_claim(&terminal_lock, "daemon_start", attempt);
            fs::create_dir(terminal_claim.join(format!("execution_started.{attempt}")))
                .expect("record exact daemon start execution");
            fs::create_dir(terminal_claim.join(format!("{terminal}.{attempt}")))
                .expect("record exact launcher terminal");
            let inactive_probe_path = path_with_inactive_daemon_probe(terminal_home.path());
            let mut recovered = RunningProtocol::start_with_path(
                &replacement_request,
                terminal_home.path(),
                Some(&inactive_probe_path),
            );
            let response = recovered.read_line();
            let recovery =
                fs::read_to_string(terminal_root.join("bootstrap-recovery-operation-1.json"))
                    .expect("daemon start recovery record");
            assert!(
                response.starts_with(READY),
                "unexpected response {response:?} with recovery evidence {recovery}"
            );
            assert_ready_line(&response);
            for probe in [
                "process_probe",
                "binary_probe",
                "service_probe",
                "daemon_probe",
            ] {
                assert!(recovery.contains(&format!("\"{probe}\":false")));
            }
            recovered.exchange(RELEASE);
            assert!(recovered.close().success());
        }

        let started_home = tempfile::tempdir().expect("temporary started-only home");
        let started_lock = started_home.path().join("satelle/bootstrap.lock");
        let started_claim = write_stale_mutation_claim(&started_lock, "daemon_start", attempt);
        fs::create_dir(started_claim.join(format!("execution_started.{attempt}")))
            .expect("record unterminated daemon start");
        let inactive_probe_path = path_with_inactive_daemon_probe(started_home.path());
        let mut started_contender = RunningProtocol::start_with_path(
            &replacement_request,
            started_home.path(),
            Some(&inactive_probe_path),
        );
        assert_eq!(started_contender.read_line(), BUSY);
        assert_eq!(started_contender.close().code(), Some(75));

        let unknown_home = tempfile::tempdir().expect("temporary unknown probe home");
        let unknown_lock = unknown_home.path().join("satelle/bootstrap.lock");
        let unknown_claim = write_stale_mutation_claim(&unknown_lock, "daemon_start", attempt);
        fs::create_dir(unknown_claim.join(format!("execution_started.{attempt}"))).unwrap();
        fs::create_dir(unknown_claim.join(format!("execution_failed.{attempt}"))).unwrap();
        let unknown_probe_path = path_with_unknown_daemon_probe(unknown_home.path());
        let mut unknown_contender = RunningProtocol::start_with_path(
            &replacement_request,
            unknown_home.path(),
            Some(&unknown_probe_path),
        );
        assert_eq!(unknown_contender.read_line(), BUSY);
        assert_eq!(unknown_contender.close().code(), Some(75));

        let racing_home = tempfile::tempdir().expect("temporary racing probe home");
        let racing_lock = racing_home.path().join("satelle/bootstrap.lock");
        let racing_claim = write_stale_mutation_claim(&racing_lock, "daemon_start", attempt);
        fs::create_dir(racing_claim.join(format!("execution_started.{attempt}"))).unwrap();
        fs::create_dir(racing_claim.join(format!("execution_failed.{attempt}"))).unwrap();
        let racing_probe_path = path_with_racing_daemon_probe(racing_home.path());
        let mut racing_contender = RunningProtocol::start_with_path(
            &replacement_request,
            racing_home.path(),
            Some(&racing_probe_path),
        );
        assert_eq!(racing_contender.read_line(), BUSY);
        assert_eq!(racing_contender.close().code(), Some(75));
        assert!(
            only_claim(&racing_lock)
                .join(format!("execution_failed.{attempt}"))
                .exists()
        );

        let active_home = tempfile::tempdir().expect("temporary active start home");
        let active_lock = active_home.path().join("satelle/bootstrap.lock");
        let active_claim = write_stale_mutation_claim(&active_lock, "daemon_start", attempt);
        fs::create_dir(active_claim.join(format!("execution_started.{attempt}")))
            .expect("record active daemon start execution");
        fs::create_dir(active_claim.join(format!("execution_failed.{attempt}")))
            .expect("record active launcher terminal");
        let active_probe_path = path_with_active_daemon_probe(active_home.path());
        let mut active_contender = RunningProtocol::start_with_path(
            &replacement_request,
            active_home.path(),
            Some(&active_probe_path),
        );
        assert_eq!(active_contender.read_line(), BUSY);
        assert_eq!(active_contender.close().code(), Some(75));

        for durable in [false, true] {
            let committed_home = tempfile::tempdir().expect("temporary committed start home");
            let committed_lock = committed_home.path().join("satelle/bootstrap.lock");
            let committed_claim =
                write_stale_mutation_claim(&committed_lock, "daemon_start", attempt);
            fs::create_dir(committed_claim.join(format!("execution_started.{attempt}"))).unwrap();
            if durable {
                fs::create_dir(committed_claim.join(format!("execution_succeeded.{attempt}")))
                    .unwrap();
            }
            fs::create_dir(committed_claim.join(format!("execution_committed.{attempt}"))).unwrap();
            let active_probe_path = path_with_active_daemon_probe(committed_home.path());
            let mut recovered = RunningProtocol::start_with_path(
                &replacement_request,
                committed_home.path(),
                Some(&active_probe_path),
            );
            assert_ready_line(&recovered.read_line());
            recovered.exchange(RELEASE);
            assert!(recovered.close().success());
        }

        for invalid_terminals in [
            ["execution_succeeded", "execution_failed"],
            ["execution_failed", "execution_committed"],
        ] {
            let invalid_home = tempfile::tempdir().expect("temporary invalid terminal home");
            let invalid_lock = invalid_home.path().join("satelle/bootstrap.lock");
            let invalid_claim = write_stale_mutation_claim(&invalid_lock, "daemon_start", attempt);
            fs::create_dir(invalid_claim.join(format!("execution_started.{attempt}"))).unwrap();
            for terminal in invalid_terminals {
                fs::create_dir(invalid_claim.join(format!("{terminal}.{attempt}"))).unwrap();
            }
            let inactive_probe_path = path_with_inactive_daemon_probe(invalid_home.path());
            let mut invalid_contender = RunningProtocol::start_with_path(
                &replacement_request,
                invalid_home.path(),
                Some(&inactive_probe_path),
            );
            assert_eq!(invalid_contender.read_line(), BUSY);
            assert_eq!(invalid_contender.close().code(), Some(75));
        }

        let other_phase_home = tempfile::tempdir().expect("temporary other phase home");
        let other_phase_lock = other_phase_home.path().join("satelle/bootstrap.lock");
        let other_phase_claim =
            write_stale_mutation_claim(&other_phase_lock, "durable_token_verification", attempt);
        fs::create_dir(other_phase_claim.join(format!("execution_started.{attempt}")))
            .expect("record other commit-required execution");
        let inactive_probe_path = path_with_inactive_daemon_probe(other_phase_home.path());
        let mut other_phase_contender = RunningProtocol::start_with_path(
            &replacement_request,
            other_phase_home.path(),
            Some(&inactive_probe_path),
        );
        assert_eq!(other_phase_contender.read_line(), BUSY);
        assert_eq!(other_phase_contender.close().code(), Some(75));

        let mismatched_home = tempfile::tempdir().expect("temporary mismatched marker home");
        let mismatched_lock = mismatched_home.path().join("satelle/bootstrap.lock");
        let mismatched_claim =
            write_stale_mutation_claim(&mismatched_lock, "daemon_start", attempt);
        fs::create_dir(mismatched_claim.join(format!("execution_started.{other_attempt}")))
            .expect("record mismatched execution marker");
        let inactive_probe_path = path_with_inactive_daemon_probe(mismatched_home.path());
        let mut mismatched_contender = RunningProtocol::start_with_path(
            &replacement_request,
            mismatched_home.path(),
            Some(&inactive_probe_path),
        );
        assert_eq!(mismatched_contender.read_line(), BUSY);
        assert_eq!(mismatched_contender.close().code(), Some(75));
    }

    #[cfg(unix)]
    #[test]
    fn retirement_sentinel_reconciles_every_valid_crash_point() {
        let attempt = "0123456789abcdef0123456789abcdef";
        let replacement_request =
            Request::new("operation-2", OperationKind::MissingDaemonRepair, None)
                .expect("valid replacement");
        let crash_points: &[(&str, &[&str])] = &[
            ("cache_promotion", &["execution_succeeded"]),
            ("cache_promotion", &[]),
            ("durable_token_verification", &["execution_committed"]),
            ("durable_token_verification", &[]),
            (
                "daemon_start",
                &["execution_succeeded", "execution_committed"],
            ),
            ("daemon_start", &["execution_succeeded"]),
            ("daemon_start", &["execution_committed"]),
            ("daemon_start", &[]),
        ];

        for (phase, terminals) in crash_points {
            let state_home = tempfile::tempdir().expect("temporary retirement crash home");
            let lock_root = state_home.path().join("satelle/bootstrap.lock");
            let claim = write_stale_mutation_claim(&lock_root, phase, attempt);
            fs::create_dir(claim.join(format!("execution_retiring.{attempt}")))
                .expect("record retirement commit point");
            for terminal in *terminals {
                fs::create_dir(claim.join(format!("{terminal}.{attempt}")))
                    .expect("record remaining terminal marker");
            }

            let mut replacement = RunningProtocol::start(&replacement_request, state_home.path());
            assert_ready_line(&replacement.read_line());
            replacement.exchange(RELEASE);
            assert!(replacement.close().success());
        }
    }

    #[cfg(unix)]
    #[test]
    fn retirement_sentinel_rejects_conflicting_foreign_and_malformed_evidence() {
        let attempt = "0123456789abcdef0123456789abcdef";
        let other_attempt = "fedcba9876543210fedcba9876543210";
        let replacement_request =
            Request::new("operation-2", OperationKind::MissingDaemonRepair, None)
                .expect("valid replacement");

        let started_home = tempfile::tempdir().expect("temporary conflicting sentinel home");
        let started_lock = started_home.path().join("satelle/bootstrap.lock");
        let started_claim = write_stale_mutation_claim(&started_lock, "cache_promotion", attempt);
        for marker in [
            "execution_started",
            "execution_retiring",
            "execution_succeeded",
        ] {
            fs::create_dir(started_claim.join(format!("{marker}.{attempt}"))).unwrap();
        }
        let mut contender = RunningProtocol::start(&replacement_request, started_home.path());
        assert_eq!(contender.read_line(), BUSY);
        assert_eq!(contender.close().code(), Some(75));

        let foreign_home = tempfile::tempdir().expect("temporary foreign sentinel home");
        let foreign_lock = foreign_home.path().join("satelle/bootstrap.lock");
        let foreign_claim = write_stale_mutation_claim(&foreign_lock, "cache_promotion", attempt);
        fs::create_dir(foreign_claim.join(format!("execution_started.{attempt}"))).unwrap();
        fs::create_dir(foreign_claim.join(format!("execution_succeeded.{attempt}"))).unwrap();
        fs::create_dir(foreign_claim.join(format!("execution_retiring.{other_attempt}"))).unwrap();
        let mut contender = RunningProtocol::start(&replacement_request, foreign_home.path());
        assert_eq!(contender.read_line(), BUSY);
        assert_eq!(contender.close().code(), Some(75));

        let file_home = tempfile::tempdir().expect("temporary file sentinel home");
        let file_lock = file_home.path().join("satelle/bootstrap.lock");
        let file_claim = write_stale_mutation_claim(&file_lock, "cache_promotion", attempt);
        fs::write(
            file_claim.join(format!("execution_retiring.{attempt}")),
            b"not a marker",
        )
        .unwrap();
        let mut contender = RunningProtocol::start(&replacement_request, file_home.path());
        assert_eq!(contender.read_line(), BUSY);
        assert_eq!(contender.close().code(), Some(75));

        let link_home = tempfile::tempdir().expect("temporary linked sentinel home");
        let link_lock = link_home.path().join("satelle/bootstrap.lock");
        let link_claim = write_stale_mutation_claim(&link_lock, "cache_promotion", attempt);
        std::os::unix::fs::symlink(
            link_claim.join("state"),
            link_claim.join(format!("execution_retiring.{attempt}")),
        )
        .unwrap();
        let mut contender = RunningProtocol::start(&replacement_request, link_home.path());
        assert_eq!(contender.read_line(), BUSY);
        assert_eq!(contender.close().code(), Some(75));

        let failed_home = tempfile::tempdir().expect("temporary failed sentinel home");
        let failed_lock = failed_home.path().join("satelle/bootstrap.lock");
        let failed_claim = write_stale_mutation_claim(&failed_lock, "daemon_start", attempt);
        fs::create_dir(failed_claim.join(format!("execution_retiring.{attempt}"))).unwrap();
        fs::create_dir(failed_claim.join(format!("execution_failed.{attempt}"))).unwrap();
        let mut contender = RunningProtocol::start(&replacement_request, failed_home.path());
        assert_eq!(contender.read_line(), BUSY);
        assert_eq!(contender.close().code(), Some(75));
    }

    #[cfg(unix)]
    #[test]
    fn stale_recovery_preserves_same_attempt_markers_invalid_for_the_phase() {
        let attempt = "0123456789abcdef0123456789abcdef";
        let replacement_request =
            Request::new("operation-2", OperationKind::MissingDaemonRepair, None)
                .expect("valid replacement");

        for (phase, invalid_marker) in [
            ("durable_token_verification", "execution_succeeded"),
            ("cache_promotion", "execution_committed"),
        ] {
            let state_home = tempfile::tempdir().expect("temporary invalid marker home");
            let lock_root = state_home.path().join("satelle/bootstrap.lock");
            let claim = write_stale_mutation_claim(&lock_root, phase, attempt);
            fs::create_dir(claim.join(format!("execution_started.{attempt}")))
                .expect("record execution start");
            let terminal_marker = if phase == "durable_token_verification" {
                "execution_committed"
            } else {
                "execution_succeeded"
            };
            fs::create_dir(claim.join(format!("{terminal_marker}.{attempt}")))
                .expect("record phase terminal marker");
            fs::create_dir(claim.join(format!("{invalid_marker}.{attempt}")))
                .expect("inject same-attempt invalid marker");

            let inactive_probe_path = path_with_inactive_daemon_probe(state_home.path());
            let mut contender = RunningProtocol::start_with_path(
                &replacement_request,
                state_home.path(),
                Some(&inactive_probe_path),
            );
            assert_eq!(contender.read_line(), BUSY);
            assert_eq!(contender.close().code(), Some(75));
            let preserved = only_claim(&lock_root);
            for marker in ["execution_started", terminal_marker, invalid_marker] {
                assert!(
                    preserved.join(format!("{marker}.{attempt}")).exists(),
                    "{phase} must preserve {marker}"
                );
            }
        }
    }

    #[cfg(unix)]
    #[test]
    fn phase_advance_retires_only_exact_terminal_attempt_evidence() {
        let first_attempt = "0123456789abcdef0123456789abcdef";
        let second_attempt = "fedcba9876543210fedcba9876543210";

        let sequential_home = tempfile::tempdir().expect("temporary sequential phase home");
        let sequential_root = sequential_home.path().join("satelle");
        let sequential_lock = sequential_root.join("bootstrap.lock");
        let mut owner = RunningProtocol::start(&request(), sequential_home.path());
        assert_ready_line(&owner.read_line());
        owner.exchange(
            &mutation_started_line("cache_promotion", first_attempt)
                .expect("valid first mutation phase"),
        );
        owner.exchange(
            &mutation_executing_line("cache_promotion", first_attempt)
                .expect("valid first execution"),
        );
        fs::create_dir(
            only_claim(&sequential_lock).join(format!("execution_succeeded.{first_attempt}")),
        )
        .expect("record first terminal postcondition");
        owner.exchange(
            &mutation_started_line("daemon_start", second_attempt)
                .expect("valid second mutation phase"),
        );
        let advanced_claim = only_claim(&sequential_lock);
        assert!(
            !advanced_claim
                .join(format!("execution_started.{first_attempt}"))
                .exists()
        );
        assert!(
            !advanced_claim
                .join(format!("execution_succeeded.{first_attempt}"))
                .exists()
        );
        owner.exchange(
            &mutation_executing_line("daemon_start", second_attempt)
                .expect("valid daemon start execution"),
        );
        fs::create_dir(
            only_claim(&sequential_lock).join(format!("execution_failed.{second_attempt}")),
        )
        .expect("record failed daemon launcher terminal");
        assert!(owner.close().success());
        fs::write(
            only_claim(&sequential_lock).join("heartbeat_at"),
            "2000-01-01T00:00:00Z\n",
        )
        .expect("age sequential claim heartbeat");
        let inactive_probe_path = path_with_inactive_daemon_probe(sequential_home.path());
        let replacement_request =
            Request::new("operation-2", OperationKind::MissingDaemonRepair, None)
                .expect("valid replacement");
        let mut recovered = RunningProtocol::start_with_path(
            &replacement_request,
            sequential_home.path(),
            Some(&inactive_probe_path),
        );
        assert_ready_line(&recovered.read_line());
        recovered.exchange(RELEASE);
        assert!(recovered.close().success());

        let committed_home = tempfile::tempdir().expect("temporary committed phase home");
        let committed_lock = committed_home.path().join("satelle/bootstrap.lock");
        let mut committed = RunningProtocol::start(&request(), committed_home.path());
        assert_ready_line(&committed.read_line());
        committed.exchange(
            &mutation_started_line("durable_token_verification", first_attempt)
                .expect("valid durable verification phase"),
        );
        committed.exchange(
            &mutation_executing_line("durable_token_verification", first_attempt)
                .expect("valid durable verification execution"),
        );
        committed.exchange(
            &mutation_committed_line("durable_token_verification", first_attempt)
                .expect("valid durable verification commit"),
        );
        committed.exchange(
            &mutation_started_line("maintenance_handoff_begin", second_attempt)
                .expect("valid maintenance phase"),
        );
        let committed_claim = only_claim(&committed_lock);
        assert!(
            !committed_claim
                .join(format!("execution_started.{first_attempt}"))
                .exists()
        );
        assert!(
            !committed_claim
                .join(format!("execution_committed.{first_attempt}"))
                .exists()
        );
        committed.exchange(RELEASE);
        assert!(committed.close().success());

        let extra_home = tempfile::tempdir().expect("temporary extra marker home");
        let extra_lock = extra_home.path().join("satelle/bootstrap.lock");
        let mut extra = RunningProtocol::start(&request(), extra_home.path());
        assert_ready_line(&extra.read_line());
        extra.exchange(
            &mutation_started_line("durable_token_verification", first_attempt)
                .expect("valid durable verification phase"),
        );
        extra.exchange(
            &mutation_executing_line("durable_token_verification", first_attempt)
                .expect("valid durable verification execution"),
        );
        fs::create_dir(
            only_claim(&extra_lock).join(format!("execution_succeeded.{first_attempt}")),
        )
        .expect("inject unattested success marker");
        extra.exchange(
            &mutation_committed_line("durable_token_verification", first_attempt)
                .expect("valid durable verification commit"),
        );
        writeln!(
            extra.stdin,
            "{}",
            mutation_started_line("maintenance_handoff_begin", second_attempt)
                .expect("valid attempted maintenance phase")
        )
        .expect("write extra-marker phase advance");
        extra
            .stdin
            .flush()
            .expect("flush extra-marker phase advance");
        assert_eq!(extra.read_line(), "");
        assert_eq!(extra.close().code(), Some(75));
        let preserved_extra = only_claim(&extra_lock);
        assert!(
            preserved_extra
                .join(format!("execution_succeeded.{first_attempt}"))
                .exists()
        );

        let partial_home = tempfile::tempdir().expect("temporary partial retirement home");
        let partial_lock = partial_home.path().join("satelle/bootstrap.lock");
        let mut partial = RunningProtocol::start(&request(), partial_home.path());
        assert_ready_line(&partial.read_line());
        partial.exchange(
            &mutation_started_line("cache_promotion", first_attempt)
                .expect("valid partial-retirement phase"),
        );
        partial.exchange(
            &mutation_executing_line("cache_promotion", first_attempt)
                .expect("valid partial-retirement execution"),
        );
        let partial_claim = only_claim(&partial_lock);
        let partial_terminal = partial_claim.join(format!("execution_succeeded.{first_attempt}"));
        fs::create_dir(&partial_terminal).expect("record partial-retirement terminal marker");
        fs::write(partial_terminal.join("unexpected"), b"preserve")
            .expect("make terminal marker nonempty");
        writeln!(
            partial.stdin,
            "{}",
            mutation_started_line("daemon_start", second_attempt)
                .expect("valid partial-retirement advance")
        )
        .expect("write partial-retirement advance");
        partial
            .stdin
            .flush()
            .expect("flush partial-retirement advance");
        assert_eq!(partial.read_line(), "");
        assert_eq!(partial.close().code(), Some(75));
        let preserved_partial = only_claim(&partial_lock);
        assert!(
            !preserved_partial
                .join(format!("execution_started.{first_attempt}"))
                .exists()
        );
        assert!(
            preserved_partial
                .join(format!("execution_retiring.{first_attempt}"))
                .exists()
        );
        assert_eq!(
            fs::read(partial_terminal.join("unexpected")).expect("preserved terminal evidence"),
            b"preserve"
        );

        let uncertain_home = tempfile::tempdir().expect("temporary uncertain phase home");
        let uncertain_lock = uncertain_home.path().join("satelle/bootstrap.lock");
        let mut uncertain = RunningProtocol::start(&request(), uncertain_home.path());
        assert_ready_line(&uncertain.read_line());
        uncertain.exchange(
            &mutation_started_line("durable_token_verification", first_attempt)
                .expect("valid commit-required phase"),
        );
        uncertain.exchange(
            &mutation_executing_line("durable_token_verification", first_attempt)
                .expect("valid uncertain execution"),
        );
        writeln!(
            uncertain.stdin,
            "{}",
            mutation_started_line("cache_promotion", second_attempt)
                .expect("valid attempted phase advance")
        )
        .expect("write uncertain phase advance");
        uncertain
            .stdin
            .flush()
            .expect("flush uncertain phase advance");
        assert_eq!(uncertain.read_line(), "");
        assert_eq!(uncertain.close().code(), Some(75));
        let preserved_uncertain = only_claim(&uncertain_lock);
        assert_eq!(
            fs::read_to_string(preserved_uncertain.join("mutation_phase"))
                .expect("preserved prior phase")
                .trim(),
            "durable_token_verification"
        );
        assert!(
            preserved_uncertain
                .join(format!("execution_started.{first_attempt}"))
                .exists()
        );

        let foreign_home = tempfile::tempdir().expect("temporary foreign marker home");
        let foreign_lock = foreign_home.path().join("satelle/bootstrap.lock");
        let mut foreign = RunningProtocol::start(&request(), foreign_home.path());
        assert_ready_line(&foreign.read_line());
        let foreign_claim = only_claim(&foreign_lock);
        let foreign_marker = foreign_claim.join(format!("execution_started.{second_attempt}"));
        fs::create_dir(&foreign_marker).expect("inject foreign marker");
        writeln!(
            foreign.stdin,
            "{}",
            mutation_started_line("cache_promotion", first_attempt)
                .expect("valid first phase attempt")
        )
        .expect("write foreign marker phase advance");
        foreign
            .stdin
            .flush()
            .expect("flush foreign marker phase advance");
        assert_eq!(foreign.read_line(), "");
        assert_eq!(foreign.close().code(), Some(75));
        assert!(foreign_marker.exists());
        assert_eq!(
            fs::read_to_string(only_claim(&foreign_lock).join("state"))
                .expect("foreign marker claim state")
                .trim(),
            "recovery_pending"
        );
    }

    #[cfg(unix)]
    #[test]
    fn posix_protocol_rejects_unknown_stale_operation_kind() {
        let state_home = tempfile::tempdir().expect("temporary state home");
        let lock_root = state_home.path().join("satelle/bootstrap.lock");
        let stale_claim = lock_root.join("claim.operation-1.stale");
        let attempt = "0123456789abcdef0123456789abcdef";
        write_claim(
            &stale_claim,
            "operation-1",
            "2000-01-01T00:00:00Z",
            "recovery_pending",
        );
        fs::write(stale_claim.join("operation_kind"), "unknown_operation\n")
            .expect("write unknown operation kind");
        fs::write(stale_claim.join("mutation_phase"), "cache_promotion\n")
            .expect("write mutation phase");
        fs::write(stale_claim.join("mutation_attempt"), format!("{attempt}\n"))
            .expect("write mutation attempt");
        fs::create_dir(stale_claim.join(format!("execution_started.{attempt}")))
            .expect("record mutation start");
        fs::create_dir(stale_claim.join(format!("execution_succeeded.{attempt}")))
            .expect("record mutation success");

        let mut contender = RunningProtocol::start(
            &Request::new("operation-2", OperationKind::MissingDaemonRepair, None)
                .expect("valid contender"),
            state_home.path(),
        );
        assert_eq!(contender.read_line(), BUSY);
        assert_eq!(contender.close().code(), Some(75));
        assert_eq!(
            fs::read_to_string(only_claim(&lock_root).join("operation_id"))
                .expect("preserved operation id")
                .trim(),
            "operation-1"
        );
    }

    #[cfg(unix)]
    #[test]
    fn posix_protocol_preserves_stale_uncertain_mutation_as_busy() {
        let state_home = tempfile::tempdir().expect("temporary state home");
        let state_root = state_home.path().join("satelle");
        let lock_root = state_root.join("bootstrap.lock");
        let mut uncertain = RunningProtocol::start(&request(), state_home.path());
        assert_ready_line(&uncertain.read_line());
        let attempt = "0123456789abcdef0123456789abcdef";
        uncertain.exchange(
            &mutation_started_line("cache_promotion", attempt).expect("valid mutation phase"),
        );
        fs::create_dir(only_claim(&lock_root).join(format!("execution_started.{attempt}")))
            .expect("record remote mutation start");
        assert!(uncertain.close().success());
        fs::write(
            only_claim(&lock_root).join("heartbeat_at"),
            "2000-01-01T00:00:00Z\n",
        )
        .expect("age heartbeat");

        let mut contender = RunningProtocol::start(
            &Request::new("operation-2", OperationKind::MissingDaemonRepair, None)
                .expect("valid contender"),
            state_home.path(),
        );
        assert_eq!(contender.read_line(), BUSY);
        assert_eq!(contender.close().code(), Some(75));
        assert_eq!(
            fs::read_to_string(only_claim(&lock_root).join("operation_id"))
                .expect("preserved operation id")
                .trim(),
            "operation-1"
        );
        assert!(
            state_root
                .join("bootstrap-recovery-operation-1.json")
                .exists()
        );

        let old_claim = only_claim(&lock_root);
        fs::create_dir(old_claim.join(format!("execution_succeeded.{attempt}")))
            .expect("record the exact phase postcondition");
        let mut reconciler = RunningProtocol::start(
            &Request::new("operation-3", OperationKind::MissingDaemonRepair, None)
                .expect("valid reconciler"),
            state_home.path(),
        );
        assert_ready_line(&reconciler.read_line());
        assert_eq!(
            fs::read_to_string(only_claim(&lock_root).join("operation_id"))
                .expect("reconciled replacement operation")
                .trim(),
            "operation-3"
        );
        reconciler.exchange(RELEASE);
        assert!(reconciler.close().success());
    }

    #[cfg(unix)]
    #[test]
    fn posix_protocol_releases_a_definite_prestart_failure_cleanly() {
        let state_home = tempfile::tempdir().expect("temporary state home");
        let state_root = state_home.path().join("satelle");
        let lock_root = state_root.join("bootstrap.lock");
        let attempt = "0123456789abcdef0123456789abcdef";
        let mut owner = RunningProtocol::start(&request(), state_home.path());
        assert_ready_line(&owner.read_line());
        owner.exchange(&mutation_started_line("cache_upload", attempt).unwrap());
        assert!(owner.close().success());
        assert!(claim_directories(&lock_root).is_empty());
        let record = fs::read_to_string(state_root.join("bootstrap-operation-operation-1.json"))
            .expect("clean failure record");
        assert!(record.contains("\"terminal_state\":\"clean_failed\""));
    }

    #[cfg(unix)]
    #[test]
    fn posix_protocol_reconciles_only_the_exact_successful_generation() {
        let state_home = tempfile::tempdir().expect("temporary state home");
        let state_root = state_home.path().join("satelle");
        let lock_root = state_root.join("bootstrap.lock");
        let attempt = "0123456789abcdef0123456789abcdef";
        let mut owner = RunningProtocol::start(&request(), state_home.path());
        assert_ready_line(&owner.read_line());
        owner.exchange(&mutation_started_line("cache_promotion", attempt).unwrap());
        let claim = only_claim(&lock_root);
        fs::create_dir(claim.join(format!("execution_started.{attempt}"))).unwrap();
        fs::create_dir(claim.join(format!("execution_succeeded.{attempt}"))).unwrap();
        assert!(owner.close().success());
        assert!(claim_directories(&lock_root).is_empty());
        let record = fs::read_to_string(state_root.join("bootstrap-operation-operation-1.json"))
            .expect("reconciled failure record");
        assert!(record.contains("\"terminal_state\":\"reconciled_failed\""));
    }

    #[cfg(unix)]
    #[test]
    fn posix_protocol_commits_the_exact_maintenance_handoff_attempt() {
        let state_home = tempfile::tempdir().expect("temporary state home");
        let lock_root = state_home.path().join("satelle/bootstrap.lock");
        let attempt = "0123456789abcdef0123456789abcdef";
        let phase = "maintenance_handoff_complete";
        let mut owner = RunningProtocol::start(&request(), state_home.path());
        assert_ready_line(&owner.read_line());
        owner.exchange(&mutation_started_line(phase, attempt).unwrap());
        owner.exchange(&mutation_executing_line(phase, attempt).unwrap());
        owner.exchange(&mutation_committed_line(phase, attempt).unwrap());
        assert!(
            only_claim(&lock_root)
                .join(format!("execution_committed.{attempt}"))
                .is_dir()
        );
        owner.exchange(RELEASE);
        assert!(owner.close().success());
    }

    #[cfg(unix)]
    #[test]
    fn posix_protocol_reconciles_committed_maintenance_begin_if_controller_closes() {
        let state_home = tempfile::tempdir().expect("temporary state home");
        let state_root = state_home.path().join("satelle");
        let lock_root = state_root.join("bootstrap.lock");
        let attempt = "0123456789abcdef0123456789abcdef";
        let phase = "maintenance_handoff_begin";
        let mut owner = RunningProtocol::start(&request(), state_home.path());
        assert_ready_line(&owner.read_line());
        owner.exchange(&mutation_started_line(phase, attempt).unwrap());
        owner.exchange(&mutation_executing_line(phase, attempt).unwrap());
        owner.exchange(&mutation_committed_line(phase, attempt).unwrap());
        assert!(
            only_claim(&lock_root)
                .join(format!("execution_committed.{attempt}"))
                .is_dir()
        );

        assert!(owner.close().success());
        assert!(claim_directories(&lock_root).is_empty());
        let record = fs::read_to_string(state_root.join("bootstrap-operation-operation-1.json"))
            .expect("reconciled failure record");
        assert!(record.contains("\"terminal_state\":\"reconciled_failed\""));
    }

    #[test]
    fn operation_kinds_are_closed_and_exact() {
        assert_eq!(OperationKind::InitialSetup.as_str(), "initial_setup");
        assert_eq!(
            OperationKind::MissingDaemonRepair.as_str(),
            "missing_daemon_repair"
        );
        assert_eq!(OperationKind::ServiceStop.as_str(), "service_stop");
        assert_eq!(OperationKind::ServiceRestart.as_str(), "service_restart");
    }

    #[test]
    fn service_stop_request_scripts_persist_stop_specific_operation_kind() {
        let request = Request::new("service-stop-operation", OperationKind::ServiceStop, None)
            .expect("valid service stop request");

        for script in [request.posix_command(), request.windows_script()] {
            assert!(script.contains("service_stop"));
            assert!(!script.contains("service_restart"));
        }
    }
}
