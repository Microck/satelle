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
    HostBinaryReplacement,
}

impl OperationKind {
    pub(super) const fn as_str(self) -> &'static str {
        match self {
            Self::InitialSetup => "initial_setup",
            Self::MissingDaemonRepair => "missing_daemon_repair",
            Self::HostBinaryReplacement => "host_binary_replacement",
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
function Record-Recovery([string]$Observed, [string]$Reason, [bool]$Process, [bool]$Binary, [bool]$Service, [bool]$Daemon) {{
  $record = Join-Path $stateRoot ('bootstrap-recovery-' + $Observed + '.json')
  @{{schema_version='satelle.bootstrap-recovery.v1';operation_id=$Observed;reason=$Reason;process_probe=$Process;binary_probe=$Binary;service_probe=$Service;daemon_probe=$Daemon;observed_at=[DateTimeOffset]::UtcNow.ToString('O')}} |
    ConvertTo-Json -Compress | Set-Content -LiteralPath $record -Encoding UTF8
  Set-OwnerOnly $record
}}
function Finalize-InterruptedClaim {{
  $closingPath = $claimPath + '.closing'
  try {{ [IO.Directory]::Move($claimPath, $closingPath) }} catch {{ return }}
  $currentStarted = $mutationAttempt -and
    (Test-Path -LiteralPath (Join-Path $closingPath ('execution_started.' + $mutationAttempt)) -PathType Leaf)
  $currentReconciled = -not $currentStarted
  if ($currentStarted) {{
    $requiresCommit = $mutationPhase -in @('daemon_start', 'durable_token_verification', 'maintenance_handoff_begin', 'maintenance_handoff_complete')
    $marker = if ($requiresCommit) {{ 'execution_committed.' }} else {{ 'execution_succeeded.' }}
    $currentReconciled = Test-Path -LiteralPath (Join-Path $closingPath ($marker + $mutationAttempt)) -PathType Leaf
  }}
  if ($currentReconciled) {{
    $failure = Join-Path $stateRoot ('bootstrap-operation-' + $operationId + '.json')
    $anyStarted = @(Get-ChildItem -LiteralPath $closingPath -File -Filter 'execution_started.*' -ErrorAction SilentlyContinue).Count -gt 0
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
    $executionSucceeded = $false
    $executionCommitted = $false
    if ($claimState -ne 'live') {{
      $claimOperationKind = (Get-Content -LiteralPath (Join-Path $item.FullName 'operation_kind') -Raw).Trim()
      $mutationPhase = (Get-Content -LiteralPath (Join-Path $item.FullName 'mutation_phase') -Raw).Trim()
      $mutationAttempt = (Get-Content -LiteralPath (Join-Path $item.FullName 'mutation_attempt') -Raw).Trim()
      if ($claimOperationKind -notin @('initial_setup', 'missing_daemon_repair', 'host_binary_replacement') -or
          $mutationPhase -notin @('cache_directory_creation', 'cache_upload', 'cache_staging_permissions', 'cache_promotion', 'daemon_start', 'state_owner_release', 'durable_token_verification', 'maintenance_handoff_begin', 'maintenance_handoff_complete') -or
          $mutationAttempt -notmatch '^[0-9a-f]{{32}}$') {{ Fail-Busy }}
      $executionStarted = Test-Path -LiteralPath (Join-Path $item.FullName ('execution_started.' + $mutationAttempt)) -PathType Leaf
      $executionSucceeded = Test-Path -LiteralPath (Join-Path $item.FullName ('execution_succeeded.' + $mutationAttempt)) -PathType Leaf
      $executionCommitted = Test-Path -LiteralPath (Join-Path $item.FullName ('execution_committed.' + $mutationAttempt)) -PathType Leaf
    }}
  }} catch {{ Fail-Busy }}
  if (([DateTimeOffset]::UtcNow - $heartbeatTime).TotalSeconds -le {STALE_AFTER_SECONDS}) {{ Fail-Busy }}
  if ($claimState -notin @('live', 'mutation_started', 'recovery_pending')) {{ Fail-Busy }}
  $processActive = [bool](Get-CimInstance Win32_Process -ErrorAction SilentlyContinue | Where-Object {{ $_.Name -match '^satelle(.exe)?$' -and $_.CommandLine -match 'host start' }} | Select-Object -First 1)
  $binaryPresent = [bool](Get-ChildItem -LiteralPath $cacheRoot -File -Recurse -ErrorAction SilentlyContinue | Where-Object {{ $_.Name -match '^satelle(-[0-9a-f]+)?.exe$' }} | Select-Object -First 1)
  $serviceActive = [bool](Get-Service -Name 'SatelleHost' -ErrorAction SilentlyContinue | Where-Object {{ $_.Status -ne 'Stopped' }})
  $daemonActive = $false
  try {{
    $response = Invoke-WebRequest -Uri 'http://127.0.0.1:3001/v1/capabilities' -Method Get -TimeoutSec 2 -UseBasicParsing
    $daemonActive = @([int]$response.StatusCode) -in @(200, 401, 403, 429)
  }} catch {{
    if ($_.Exception.Response) {{ $daemonActive = @([int]$_.Exception.Response.StatusCode) -in @(200, 401, 403, 429) }}
  }}
  $requiresCommit = $mutationPhase -in @('daemon_start', 'durable_token_verification', 'maintenance_handoff_begin', 'maintenance_handoff_complete')
  Record-Recovery $observed 'stale heartbeat postcondition probes' $processActive $binaryPresent $serviceActive $daemonActive
  $terminalEvidence = ($requiresCommit -and $executionCommitted) -or
    ((-not $requiresCommit) -and $executionSucceeded)
  $reconciled = ($claimState -ceq 'live') -or (-not $executionStarted) -or $terminalEvidence
  if (-not $reconciled) {{ Fail-Busy }}
  if (($processActive -or $serviceActive -or $daemonActive) -and
      $executionStarted -and
      -not $terminalEvidence) {{ Fail-Busy }}
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
    $movedExecutionSucceeded = $false
    $movedExecutionCommitted = $false
    if ($movedState -ne 'live') {{
      $movedOperationKind = (Get-Content -LiteralPath (Join-Path $quarantinedClaim 'operation_kind') -Raw).Trim()
      $movedMutationPhase = (Get-Content -LiteralPath (Join-Path $quarantinedClaim 'mutation_phase') -Raw).Trim()
      $movedMutationAttempt = (Get-Content -LiteralPath (Join-Path $quarantinedClaim 'mutation_attempt') -Raw).Trim()
      $movedExecutionStarted = Test-Path -LiteralPath (Join-Path $quarantinedClaim ('execution_started.' + $movedMutationAttempt)) -PathType Leaf
      $movedExecutionSucceeded = Test-Path -LiteralPath (Join-Path $quarantinedClaim ('execution_succeeded.' + $movedMutationAttempt)) -PathType Leaf
      $movedExecutionCommitted = Test-Path -LiteralPath (Join-Path $quarantinedClaim ('execution_committed.' + $movedMutationAttempt)) -PathType Leaf
    }}
  }} catch {{
    Restore-Competitor $item.FullName $quarantineRoot $quarantinedClaim
    Fail-Busy
  }}
  if (($movedOperation -cne $observed) -or ($movedIdentity -cne $observedIdentity) -or ($movedHeartbeat -cne $heartbeat) -or
      ($movedState -cne $claimState) -or ($movedOperationKind -cne $claimOperationKind) -or
      ($movedMutationPhase -cne $mutationPhase) -or ($movedMutationAttempt -cne $mutationAttempt) -or
      ($movedExecutionStarted -ne $executionStarted) -or ($movedExecutionSucceeded -ne $executionSucceeded) -or
      ($movedExecutionCommitted -ne $executionCommitted)) {{
    Restore-Competitor $item.FullName $quarantineRoot $quarantinedClaim
    Fail-Busy
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
    if ($mutationStarted) {{
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
finalize_interrupted_claim() {{
  closing_path="$claim_path.closing"
  mv "$claim_path" "$closing_path" 2>/dev/null || return
  current_started=false
  [ -n "$mutation_attempt" ] && [ -d "$closing_path/execution_started.$mutation_attempt" ] && current_started=true
  current_reconciled=true
  if [ "$current_started" = true ]; then
    current_reconciled=false
    requires_commit=false
    case "$mutation_phase" in daemon_start|durable_token_verification|maintenance_handoff_begin|maintenance_handoff_complete) requires_commit=true;; esac
    if [ "$requires_commit" = true ]; then
      [ -d "$closing_path/execution_committed.$mutation_attempt" ] && current_reconciled=true
    else
      [ -d "$closing_path/execution_succeeded.$mutation_attempt" ] && current_reconciled=true
    fi
  fi
  if [ "$current_reconciled" = true ]; then
    any_started=false
    for started in "$closing_path"/execution_started.*; do [ -d "$started" ] && any_started=true; done
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
    if [ "$mutation_started" = true ]; then
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
  execution_succeeded=false
  execution_committed=false
  if [ "$claim_state" != live ]; then
    claim_operation_kind="$(cat "$competitor/operation_kind" 2>/dev/null)" || busy
    mutation_phase="$(cat "$competitor/mutation_phase" 2>/dev/null)" || busy
    mutation_attempt="$(cat "$competitor/mutation_attempt" 2>/dev/null)" || busy
    case "$claim_operation_kind" in initial_setup|missing_daemon_repair|host_binary_replacement) ;; *) busy;; esac
    case "$mutation_phase" in cache_directory_creation|cache_upload|cache_staging_permissions|cache_promotion|daemon_start|state_owner_release|durable_token_verification|maintenance_handoff_begin|maintenance_handoff_complete) ;; *) busy;; esac
    [ "${{#mutation_attempt}}" -eq 32 ] || busy
    case "$mutation_attempt" in *[!0-9a-f]*) busy;; esac
    [ -d "$competitor/execution_started.$mutation_attempt" ] && execution_started=true
    [ -d "$competitor/execution_succeeded.$mutation_attempt" ] && execution_succeeded=true
    [ -d "$competitor/execution_committed.$mutation_attempt" ] && execution_committed=true
  fi
  process_active=false
  if ps -eo pid=,comm=,args= 2>/dev/null | awk -v self="$$" -v parent="$PPID" '$1 != self && $1 != parent && ($2 == "satelle" || $2 == "satelle.exe") && $0 ~ /host start/ {{ found=1 }} END {{ exit !found }}'; then process_active=true; fi
  binary_present=false
  if [ -d "$cache_root" ] && find "$cache_root" -type f -name satelle -print -quit 2>/dev/null | grep . >/dev/null 2>&1; then binary_present=true; fi
  service_active=false
  if command -v systemctl >/dev/null 2>&1 && systemctl --user is-active --quiet satelle-host 2>/dev/null; then service_active=true; fi
  if command -v launchctl >/dev/null 2>&1 && launchctl print "gui/$(id -u)" 2>/dev/null | grep -F 'satelle-host' >/dev/null 2>&1; then service_active=true; fi
  daemon_active=false
  if command -v curl >/dev/null 2>&1; then
    status="$(curl -sS -o /dev/null -w '%{{http_code}}' --max-time 2 http://127.0.0.1:3001/v1/capabilities 2>/dev/null || true)"
    case "$status" in 200|401|403|429) daemon_active=true;; esac
  fi
  requires_commit=false
  case "$mutation_phase" in daemon_start|durable_token_verification|maintenance_handoff_begin|maintenance_handoff_complete) requires_commit=true;; esac
  record_recovery "$observed" "$process_active" "$binary_present" "$service_active" "$daemon_active"
  terminal_evidence=false
  if [ "$requires_commit" = true ] && [ "$execution_committed" = true ]; then
    terminal_evidence=true
  elif [ "$requires_commit" = false ] && [ "$execution_succeeded" = true ]; then
    terminal_evidence=true
  fi
  reconciled=false
  if [ "$claim_state" = live ] || [ "$execution_started" = false ] || [ "$terminal_evidence" = true ]; then
    reconciled=true
  fi
  [ "$reconciled" = true ] || busy
  if [ "$process_active" = true ] || [ "$service_active" = true ] || [ "$daemon_active" = true ]; then
    if [ "$execution_started" = true ]; then
      [ "$terminal_evidence" = true ] || busy
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
  moved_execution_succeeded=false
  moved_execution_committed=false
  if [ "$moved_state" != live ]; then
    moved_operation_kind="$(cat "$quarantined_claim/operation_kind" 2>/dev/null)" || {{ restore_competitor; busy; }}
    moved_mutation_phase="$(cat "$quarantined_claim/mutation_phase" 2>/dev/null)" || {{ restore_competitor; busy; }}
    moved_mutation_attempt="$(cat "$quarantined_claim/mutation_attempt" 2>/dev/null)" || {{ restore_competitor; busy; }}
    [ -d "$quarantined_claim/execution_started.$moved_mutation_attempt" ] && moved_execution_started=true
    [ -d "$quarantined_claim/execution_succeeded.$moved_mutation_attempt" ] && moved_execution_succeeded=true
    [ -d "$quarantined_claim/execution_committed.$moved_mutation_attempt" ] && moved_execution_committed=true
  fi
  if [ "$moved_operation" != "$observed" ] || [ "$moved_identity" != "$observed_identity" ] || [ "$moved_heartbeat" != "$heartbeat" ] ||
     [ "$moved_state" != "$claim_state" ] || [ "$moved_operation_kind" != "$claim_operation_kind" ] ||
     [ "$moved_mutation_phase" != "$mutation_phase" ] || [ "$moved_mutation_attempt" != "$mutation_attempt" ] ||
     [ "$moved_execution_started" != "$execution_started" ] || [ "$moved_execution_succeeded" != "$execution_succeeded" ] ||
     [ "$moved_execution_committed" != "$execution_committed" ]; then
    restore_competitor
    busy
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
            "execution_succeeded.",
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
            "Get-Service",
            "/v1/capabilities",
            "catch { Fail-Busy }",
            "Remove-OwnClaim",
            "execution_started.",
            "execution_succeeded.",
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
    fn windows_stale_recovery_operation_kind_allowlist_is_closed_and_accepts_replacement() {
        let script = request().windows_script();
        assert!(script.contains(
            "$claimOperationKind -notin @('initial_setup', 'missing_daemon_repair', 'host_binary_replacement')"
        ));
    }

    #[test]
    fn windows_active_daemon_fence_distinguishes_preexecution_and_started_claims() {
        let script = request().windows_script();
        assert!(script.contains(
            "$terminalEvidence = ($requiresCommit -and $executionCommitted) -or\n    ((-not $requiresCommit) -and $executionSucceeded)"
        ));
        assert!(script.contains(
            "if (($processActive -or $serviceActive -or $daemonActive) -and\n      $executionStarted -and\n      -not $terminalEvidence) { Fail-Busy }"
        ));
        assert!(
            script.contains(
                "$reconciled = ($claimState -ceq 'live') -or (-not $executionStarted) -or"
            )
        );
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
    fn path_with_active_daemon_probe(root: &std::path::Path) -> std::ffi::OsString {
        let bin = root.join("probe-bin");
        fs::create_dir(&bin).expect("create probe bin");
        let curl = bin.join("curl");
        fs::write(&curl, "#!/bin/sh\nprintf '200'\n").expect("write daemon probe");
        let mut permissions = fs::metadata(&curl)
            .expect("daemon probe metadata")
            .permissions();
        permissions.set_mode(0o700);
        fs::set_permissions(&curl, permissions).expect("make daemon probe executable");

        let inherited = std::env::var_os("PATH").unwrap_or_default();
        std::env::join_paths(std::iter::once(bin).chain(std::env::split_paths(&inherited)))
            .expect("prepend daemon probe to PATH")
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
    fn posix_protocol_recovers_stale_host_binary_replacement() {
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
        fs::write(
            stale_claim.join("operation_kind"),
            "host_binary_replacement\n",
        )
        .expect("write replacement operation kind");
        fs::write(stale_claim.join("mutation_phase"), "cache_promotion\n")
            .expect("write mutation phase");
        fs::write(stale_claim.join("mutation_attempt"), format!("{attempt}\n"))
            .expect("write mutation attempt");
        fs::create_dir(stale_claim.join(format!("execution_started.{attempt}")))
            .expect("record mutation start");
        fs::create_dir(stale_claim.join(format!("execution_succeeded.{attempt}")))
            .expect("record mutation success");

        let replacement_request =
            Request::new("operation-2", OperationKind::HostBinaryReplacement, None)
                .expect("valid replacement");
        let mut replacement = RunningProtocol::start(&replacement_request, state_home.path());
        assert_ready_line(&replacement.read_line());
        assert_eq!(
            fs::read_to_string(only_claim(&lock_root).join("operation_id"))
                .expect("replacement operation")
                .trim(),
            "operation-2"
        );

        replacement.exchange(RELEASE);
        assert!(replacement.close().success());
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
            &Request::new("operation-2", OperationKind::HostBinaryReplacement, None)
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
        assert_eq!(
            OperationKind::HostBinaryReplacement.as_str(),
            "host_binary_replacement"
        );
    }
}
