pub(super) const READY: &str = "satelle-bootstrap-lock-v2";
pub(super) const BUSY: &str = "satelle-bootstrap-busy-v1";
pub(super) const HEARTBEAT: &str = "satelle-bootstrap-heartbeat-v1";
pub(super) const RELEASE: &str = "satelle-bootstrap-release-v1";
pub(super) const MUTATION_STARTED: &str = "satelle-bootstrap-mutation-started-v1";
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
    $claimOperationKind = $null
    $mutationPhase = $null
    if ($claimState -ne 'live') {{
      $claimOperationKind = (Get-Content -LiteralPath (Join-Path $item.FullName 'operation_kind') -Raw).Trim()
      $mutationPhase = (Get-Content -LiteralPath (Join-Path $item.FullName 'mutation_phase') -Raw).Trim()
      if ($claimOperationKind -notin @('initial_setup', 'missing_daemon_repair') -or
          $mutationPhase -notin @('cache_directory_creation', 'cache_upload', 'cache_staging_permissions', 'cache_promotion', 'daemon_start', 'state_owner_release')) {{ Fail-Busy }}
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
  if ($processActive -or $serviceActive -or $daemonActive) {{ Fail-Busy }}
  Record-Recovery $observed 'stale heartbeat postcondition probes' $processActive $binaryPresent $serviceActive $daemonActive
  if ($claimState -ne 'live') {{ Fail-Busy }}
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
    $movedOperationKind = $null
    $movedMutationPhase = $null
    if ($movedState -ne 'live') {{
      $movedOperationKind = (Get-Content -LiteralPath (Join-Path $quarantinedClaim 'operation_kind') -Raw).Trim()
      $movedMutationPhase = (Get-Content -LiteralPath (Join-Path $quarantinedClaim 'mutation_phase') -Raw).Trim()
    }}
  }} catch {{
    Restore-Competitor $item.FullName $quarantineRoot $quarantinedClaim
    Fail-Busy
  }}
  if (($movedOperation -cne $observed) -or ($movedHeartbeat -cne $heartbeat) -or
      ($movedState -cne $claimState) -or ($movedOperationKind -cne $claimOperationKind) -or
      ($movedMutationPhase -cne $mutationPhase)) {{
    Restore-Competitor $item.FullName $quarantineRoot $quarantinedClaim
    Fail-Busy
  }}
  Remove-Item -LiteralPath $quarantineRoot -Recurse -Force
}}
foreach ($item in @(Get-ChildItem -LiteralPath $lockRoot -Force -ErrorAction Stop)) {{
  if (-not [StringComparer]::OrdinalIgnoreCase.Equals($item.FullName, $claimPath)) {{ Fail-Busy }}
}}
if (-not (Same-Owner)) {{ Fail-Busy }}
Write-Output '{READY}'
try {{
  while (($line = [Console]::In.ReadLine()) -ne $null) {{
    if (-not (Same-Owner)) {{ exit 75 }}
    if ($line -ceq '{HEARTBEAT}') {{
      Write-Value $claimPath 'heartbeat_at' ([DateTimeOffset]::UtcNow.ToString('O'))
      continue
    }}
    if ($line.StartsWith('{MUTATION_STARTED} ')) {{
      $phase = $line.Substring({mutation_prefix_length})
      if ($phase -notmatch '^[A-Za-z0-9_-]{{1,128}}$') {{ exit 64 }}
      Write-Value $claimPath 'state' 'mutation_started'
      Write-Value $claimPath 'mutation_phase' $phase
      $mutationStarted = $true
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
      Write-Value $claimPath 'state' 'recovery_pending'
      Write-Value $claimPath 'recovery_reason' 'controller channel closed after remote mutation'
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
cleanup() {{
  if [ -n "$pending_path" ] && [ -d "$pending_path" ]; then rm -rf "$pending_path"; fi
  if [ "$claim_published" = true ] && [ "$released" = false ] && same_owner; then
    if [ "$mutation_started" = true ]; then
      write_value "$claim_path" recovery_pending state
      write_value "$claim_path" 'controller channel closed after remote mutation' recovery_reason
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
  now_epoch="$(date -u +%s)"
  [ "$((now_epoch - heartbeat_epoch))" -gt {STALE_AFTER_SECONDS} ] || busy
  case "$claim_state" in live|mutation_started|recovery_pending) ;; *) busy;; esac
  claim_operation_kind=
  mutation_phase=
  if [ "$claim_state" != live ]; then
    claim_operation_kind="$(cat "$competitor/operation_kind" 2>/dev/null)" || busy
    mutation_phase="$(cat "$competitor/mutation_phase" 2>/dev/null)" || busy
    case "$claim_operation_kind" in initial_setup|missing_daemon_repair) ;; *) busy;; esac
    case "$mutation_phase" in cache_directory_creation|cache_upload|cache_staging_permissions|cache_promotion|daemon_start|state_owner_release) ;; *) busy;; esac
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
  if [ "$process_active" = true ] || [ "$service_active" = true ] || [ "$daemon_active" = true ]; then busy; fi
  record_recovery "$observed" "$process_active" "$binary_present" "$service_active" "$daemon_active"
  [ "$claim_state" = live ] || busy
  quarantine_root="$(mktemp -d "$state_root/bootstrap.quarantine.XXXXXX")" || busy
  chmod 700 "$quarantine_root"
  quarantined_claim="$quarantine_root/claim"
  if ! mv "$competitor" "$quarantined_claim" 2>/dev/null; then rmdir "$quarantine_root"; busy; fi
  moved_operation="$(read_operation "$quarantined_claim")" || {{ restore_competitor; busy; }}
  moved_heartbeat="$(cat "$quarantined_claim/heartbeat_at" 2>/dev/null)" || {{ restore_competitor; busy; }}
  moved_state="$(cat "$quarantined_claim/state" 2>/dev/null)" || {{ restore_competitor; busy; }}
  moved_operation_kind=
  moved_mutation_phase=
  if [ "$moved_state" != live ]; then
    moved_operation_kind="$(cat "$quarantined_claim/operation_kind" 2>/dev/null)" || {{ restore_competitor; busy; }}
    moved_mutation_phase="$(cat "$quarantined_claim/mutation_phase" 2>/dev/null)" || {{ restore_competitor; busy; }}
  fi
  if [ "$moved_operation" != "$observed" ] || [ "$moved_heartbeat" != "$heartbeat" ] ||
     [ "$moved_state" != "$claim_state" ] || [ "$moved_operation_kind" != "$claim_operation_kind" ] ||
     [ "$moved_mutation_phase" != "$mutation_phase" ]; then
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
printf '%s\n' '{READY}'
while IFS= read -r line; do
  same_owner || exit 75
  if [ "$line" = '{HEARTBEAT}' ]; then
    write_value "$claim_path" "$(date -u +%Y-%m-%dT%H:%M:%SZ)" heartbeat_at
    continue
  fi
  case "$line" in
    '{MUTATION_STARTED} '*)
      phase="${{line#'{MUTATION_STARTED} '}}"
      case "$phase" in *[!A-Za-z0-9_-]*|'') exit 64;; esac
      write_value "$claim_path" mutation_started state
      write_value "$claim_path" "$phase" mutation_phase
      mutation_started=true
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

pub(super) fn mutation_started_line(phase: &str) -> Result<String, InvalidRequest> {
    validated_token(phase.to_string(), "mutation phase")
        .map(|phase| format!("{MUTATION_STARTED} {phase}"))
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
            "recovery_pending",
            "clean_failed",
        ] {
            assert!(script.contains(required), "missing {required:?}");
        }
    }

    #[test]
    fn every_remote_mutation_protocol_line_has_one_closed_token() {
        assert_eq!(
            mutation_started_line("cache_promotion").unwrap(),
            "satelle-bootstrap-mutation-started-v1 cache_promotion"
        );
        assert!(mutation_started_line("invalid phase").is_err());
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
            let mut child = Command::new("sh")
                .arg("-c")
                .arg(request.posix_script())
                .env("XDG_STATE_HOME", state_home)
                .env("XDG_CACHE_HOME", state_home.join("cache"))
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .spawn()
                .expect("spawn Bootstrap Lock protocol");
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
    #[test]
    fn posix_protocol_serializes_owners_and_releases_cleanly() {
        let state_home = tempfile::tempdir().expect("temporary state home");
        let state_root = state_home.path().join("satelle");
        let lock_root = state_root.join("bootstrap.lock");
        let mut owner = RunningProtocol::start(&request(), state_home.path());
        assert_eq!(owner.read_line(), READY);
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
        assert_eq!(owner.read_line(), READY);
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
        assert_eq!(clean.read_line(), READY);
        assert!(clean.close().success());
        assert!(claim_directories(&lock_root).is_empty());
        let clean_record =
            fs::read_to_string(state_root.join("bootstrap-operation-operation-1.json"))
                .expect("clean failure record");
        assert!(clean_record.contains("\"terminal_state\":\"clean_failed\""));

        let mut uncertain = RunningProtocol::start(&request(), state_home.path());
        assert_eq!(uncertain.read_line(), READY);
        uncertain
            .exchange(&mutation_started_line("cache_promotion").expect("valid mutation phase"));
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
        assert_eq!(replacement.read_line(), READY);
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
    fn posix_protocol_preserves_stale_uncertain_mutation_as_busy() {
        let state_home = tempfile::tempdir().expect("temporary state home");
        let state_root = state_home.path().join("satelle");
        let lock_root = state_root.join("bootstrap.lock");
        let mut uncertain = RunningProtocol::start(&request(), state_home.path());
        assert_eq!(uncertain.read_line(), READY);
        uncertain
            .exchange(&mutation_started_line("cache_promotion").expect("valid mutation phase"));
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
