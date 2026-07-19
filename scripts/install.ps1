[CmdletBinding()]
param(
  [string]$Version,
  [string]$BinDir = $(if ($env:SATELLE_BIN_DIR) { $env:SATELLE_BIN_DIR } else { Join-Path $HOME ".local\bin" }),
  [switch]$Uninstall
)

$ErrorActionPreference = "Stop"
$Repository = "Microck/satelle"
$BinaryPath = Join-Path $BinDir "satelle.exe"
$ReceiptPath = Join-Path $BinDir ".satelle-install.json"
$LockPath = Join-Path $BinDir ".satelle-install.lock"

function Enter-InstallLock {
  New-Item -ItemType Directory -Path $BinDir -Force | Out-Null
  try {
    New-Item -ItemType Directory -Path $LockPath -ErrorAction Stop | Out-Null
  } catch {
    throw "another Satelle install operation holds $LockPath; remove it only after confirming no installer is running"
  }
}

function Exit-InstallLock {
  Remove-Item -LiteralPath $LockPath -Force -ErrorAction SilentlyContinue
}

# Use the argument list API so paths never pass through another command-line parser. Reading
# both streams asynchronously also prevents a verbose gh failure from blocking WaitForExit.
function Invoke-BoundedGh {
  param([string[]]$Arguments)

  $StartInfo = [System.Diagnostics.ProcessStartInfo]::new()
  $StartInfo.FileName = $GhPath
  $StartInfo.UseShellExecute = $false
  $StartInfo.RedirectStandardOutput = $true
  $StartInfo.RedirectStandardError = $true
  foreach ($Argument in $Arguments) {
    $StartInfo.ArgumentList.Add($Argument)
  }

  $Process = [System.Diagnostics.Process]::new()
  $Process.StartInfo = $StartInfo
  try {
    if (-not $Process.Start()) {
      throw "could not start gh"
    }
    $StandardOutput = $Process.StandardOutput.ReadToEndAsync()
    $StandardError = $Process.StandardError.ReadToEndAsync()
    if (-not $Process.WaitForExit(300000)) {
      $Process.Kill($true)
      $Process.WaitForExit()
      throw "gh execution exceeded 300 seconds"
    }
    $Output = $StandardOutput.GetAwaiter().GetResult()
    $ErrorOutput = $StandardError.GetAwaiter().GetResult()
    if ($Process.ExitCode -ne 0) {
      throw "gh failed with exit code $($Process.ExitCode): $($ErrorOutput.Trim())"
    }
    return $Output
  } finally {
    $Process.Dispose()
  }
}

function Assert-SatellePathsPayload {
  param([object]$Paths)

  $StringFields = @(
    "host",
    "config_file",
    "cache_root",
    "state_root",
    "sqlite_store",
    "operator_log_root",
    "recording_root",
    "project_config_file",
    "install_receipt"
  )
  $SourceFields = @(
    "config_file",
    "cache_root",
    "state_root",
    "sqlite_store",
    "operator_log_root",
    "recording_root",
    "project_config_file",
    "install_receipt"
  )
  $AllowedPathSources = @("os_default", "satelle_home", "explicit_environment", "project_discovery")
  if ($Paths.schema_version -ne "satelle.paths.v1") {
    throw "release binary failed the satelle.paths.v1 smoke test"
  }
  foreach ($Field in $StringFields) {
    if ($Paths.PSObject.Properties.Name -notcontains $Field -or $Paths.$Field -isnot [string]) {
      throw "release binary failed the satelle.paths.v1 smoke test"
    }
  }
  if ($Paths.PSObject.Properties.Name -notcontains "sources" -or $Paths.sources -isnot [PSCustomObject]) {
    throw "release binary failed the satelle.paths.v1 smoke test"
  }
  foreach ($Field in $SourceFields) {
    if (
      $Paths.sources.PSObject.Properties.Name -notcontains $Field -or
      $Paths.sources.$Field -isnot [string] -or
      $AllowedPathSources -notcontains $Paths.sources.$Field
    ) {
      throw "release binary failed the satelle.paths.v1 smoke test"
    }
  }
}

if ($Uninstall) {
  Enter-InstallLock
  try {
    if (-not (Test-Path -LiteralPath $ReceiptPath -PathType Leaf)) {
      throw "Satelle install receipt not found at $ReceiptPath"
    }
    if (Test-Path -LiteralPath $BinaryPath) {
      Remove-Item -LiteralPath $BinaryPath -Force -ErrorAction Stop
    }
    Remove-Item -LiteralPath $ReceiptPath -Force -ErrorAction Stop
    Write-Output "Uninstalled Satelle from $BinaryPath"
  } finally {
    Exit-InstallLock
  }
  exit 0
}

$GhPath = Get-Command gh -CommandType Application -ErrorAction SilentlyContinue |
  Select-Object -First 1 -ExpandProperty Source
if (-not $GhPath) {
  throw "gh is required to verify the signed release tag and Sigstore attestation"
}
if (-not $Version) {
  $Version = (Invoke-BoundedGh @(
    "api",
    "repos/$Repository/releases/latest",
    "--jq",
    ".tag_name"
  )).Trim().TrimStart("v")
}
if ($Version -notmatch '^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$') {
  throw "invalid Satelle version: $Version"
}

$Architecture = [System.Runtime.InteropServices.RuntimeInformation]::OSArchitecture.ToString()
$Target = switch ($Architecture) {
  "X64" { "win32-x64-msvc" }
  "Arm64" { "win32-arm64-msvc" }
  default { throw "unsupported Satelle installer architecture: $Architecture" }
}
$Archive = "satelle-v$Version-$Target.zip"
$DownloadBase = "https://github.com/$Repository/releases/download/v$Version"
$TemporaryRoot = Join-Path ([System.IO.Path]::GetTempPath()) ("satelle-install-" + [guid]::NewGuid())
$LockHeld = $false

try {
  New-Item -ItemType Directory -Path $TemporaryRoot | Out-Null
  Enter-InstallLock
  $LockHeld = $true
  $ArchivePath = Join-Path $TemporaryRoot $Archive
  $ChecksumsPath = Join-Path $TemporaryRoot "SHA256SUMS"
  Invoke-WebRequest -Uri "$DownloadBase/$Archive" -OutFile $ArchivePath `
    -ConnectionTimeoutSeconds 10 -OperationTimeoutSeconds 300
  Invoke-WebRequest -Uri "$DownloadBase/SHA256SUMS" -OutFile $ChecksumsPath `
    -ConnectionTimeoutSeconds 10 -OperationTimeoutSeconds 300

  $ChecksumText = [System.IO.File]::ReadAllText($ChecksumsPath)
  if (-not $ChecksumText.EndsWith("`n", [System.StringComparison]::Ordinal) -or $ChecksumText.Contains("`r")) {
    throw "SHA256SUMS must be canonical LF-delimited records"
  }
  $Entries = @()
  $PreviousChecksumName = $null
  foreach ($Line in $ChecksumText.Substring(0, $ChecksumText.Length - 1).Split("`n")) {
    if ($Line -notmatch '^([0-9a-f]{64})  (\S+)$') {
      throw "SHA256SUMS must be canonical LF-delimited records"
    }
    $ChecksumName = $Matches[2]
    if (
      $ChecksumName -eq "." -or
      $ChecksumName -eq ".." -or
      $ChecksumName -eq "SHA256SUMS" -or
      [System.IO.Path]::GetFileName($ChecksumName) -ne $ChecksumName -or
      ($null -ne $PreviousChecksumName -and [System.StringComparer]::Ordinal.Compare($PreviousChecksumName, $ChecksumName) -ge 0)
    ) {
      throw "SHA256SUMS must contain unique sorted canonical filenames"
    }
    $PreviousChecksumName = $ChecksumName
    if ($ChecksumName -eq $Archive) { $Entries += $Line }
  }
  if ($Entries.Count -ne 1) {
    throw "SHA256SUMS must contain exactly one canonical entry for $Archive"
  }
  $ExpectedDigest = $Entries[0].Substring(0, 64)
  $ActualDigest = (Get-FileHash -LiteralPath $ArchivePath -Algorithm SHA256).Hash.ToLowerInvariant()
  if ($ActualDigest -ne $ExpectedDigest) {
    throw "$Archive does not match SHA256SUMS"
  }

  $TagRef = (Invoke-BoundedGh @(
    "api",
    "repos/$Repository/git/ref/tags/v$Version"
  ) | ConvertFrom-Json).object
  if ($TagRef.type -ne "tag") {
    throw "release tag v$Version is not an annotated tag"
  }
  $Tag = Invoke-BoundedGh @(
    "api",
    "repos/$Repository/git/tags/$($TagRef.sha)"
  ) | ConvertFrom-Json
  if (-not $Tag.verification.verified -or $Tag.object.type -ne "commit") {
    throw "release tag v$Version is not signed, verified, and commit-backed"
  }
  $SourceDigest = $Tag.object.sha

  Invoke-BoundedGh @(
    "attestation",
    "verify",
    $ArchivePath,
    "--repo",
    $Repository,
    "--signer-workflow",
    "$Repository/.github/workflows/release.yml",
    "--source-ref",
    "refs/tags/v$Version",
    "--source-digest",
    $SourceDigest,
    "--signer-digest",
    $SourceDigest,
    "--cert-oidc-issuer",
    "https://token.actions.githubusercontent.com",
    "--deny-self-hosted-runners",
    "--format",
    "json"
  ) | Out-Null

  $ExtractRoot = Join-Path $TemporaryRoot "extracted"
  Add-Type -AssemblyName System.IO.Compression.FileSystem
  $Zip = [System.IO.Compression.ZipFile]::OpenRead($ArchivePath)
  try {
    if ($Zip.Entries.Count -ne 1 -or $Zip.Entries[0].FullName -ne "satelle.exe") {
      throw "$Archive must contain only satelle.exe at its root"
    }
  } finally {
    $Zip.Dispose()
  }
  Expand-Archive -LiteralPath $ArchivePath -DestinationPath $ExtractRoot
  $Members = @(Get-ChildItem -LiteralPath $ExtractRoot -Force)
  if ($Members.Count -ne 1 -or $Members[0].Name -ne "satelle.exe" -or $Members[0].PSIsContainer) {
    throw "$Archive must contain only satelle.exe at its root"
  }
  $VersionOutput = & $Members[0].FullName --version
  if ($LASTEXITCODE -ne 0 -or $VersionOutput -ne "satelle $Version") {
    throw "release binary version does not match v$Version"
  }
  $PathsOutput = & $Members[0].FullName paths --json
  if ($LASTEXITCODE -ne 0) {
    throw "release binary failed the satelle.paths.v1 smoke test"
  }
  $Paths = $PathsOutput | ConvertFrom-Json
  Assert-SatellePathsPayload $Paths

  New-Item -ItemType Directory -Path $BinDir -Force | Out-Null
  $InstallingPath = Join-Path $BinDir ".satelle.installing.$PID.exe"
  $StagedReceiptPath = Join-Path $BinDir ".satelle-receipt.installing.$PID"
  $PreviousBinaryPath = Join-Path $BinDir ".satelle.previous.$PID.exe"
  $PreviousReceiptPath = Join-Path $BinDir ".satelle-receipt.previous.$PID"
  $Receipt = [ordered]@{
    install_method = "satelle-install-script"
    binary_path = $BinaryPath
    version = $Version
    target = $Target
    artifact_digest = $ActualDigest
    installed_at = [DateTime]::UtcNow.ToString("yyyy-MM-ddTHH:mm:ssZ")
  } | ConvertTo-Json
  $HadBinary = $false
  $HadReceipt = $false
  $CommitStarted = $false
  try {
    Copy-Item -LiteralPath $Members[0].FullName -Destination $InstallingPath
    [System.IO.File]::WriteAllText($StagedReceiptPath, $Receipt, (New-Object System.Text.UTF8Encoding($false)))
    $HadBinary = Test-Path -LiteralPath $BinaryPath
    $HadReceipt = Test-Path -LiteralPath $ReceiptPath
    if ($HadBinary) { Copy-Item -LiteralPath $BinaryPath -Destination $PreviousBinaryPath }
    if ($HadReceipt) { Copy-Item -LiteralPath $ReceiptPath -Destination $PreviousReceiptPath }
    $CommitStarted = $true
    Move-Item -LiteralPath $InstallingPath -Destination $BinaryPath -Force
    Move-Item -LiteralPath $StagedReceiptPath -Destination $ReceiptPath -Force
  } catch {
    if ($CommitStarted) {
      Remove-Item -LiteralPath $BinaryPath, $ReceiptPath -Force -ErrorAction SilentlyContinue
      if ($HadBinary) { Move-Item -LiteralPath $PreviousBinaryPath -Destination $BinaryPath -Force }
      if ($HadReceipt) { Move-Item -LiteralPath $PreviousReceiptPath -Destination $ReceiptPath -Force }
    }
    throw
  } finally {
    Remove-Item -LiteralPath $InstallingPath, $StagedReceiptPath, $PreviousBinaryPath, $PreviousReceiptPath -Force -ErrorAction SilentlyContinue
  }
  Write-Output "Installed Satelle $Version at $BinaryPath"
} finally {
  Remove-Item -LiteralPath $TemporaryRoot -Recurse -Force -ErrorAction SilentlyContinue
  if ($LockHeld) { Exit-InstallLock }
}
