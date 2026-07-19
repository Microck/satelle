#!/bin/sh
set -eu

repository="Microck/satelle"
release_base="https://github.com/$repository/releases"
version=""
bin_dir="${SATELLE_BIN_DIR:-${XDG_BIN_HOME:-$HOME/.local/bin}}"
uninstall=0

usage() {
  printf '%s\n' "usage: install.sh [--version X.Y.Z] [--bin-dir PATH] [--uninstall]"
}

while [ "$#" -gt 0 ]; do
  case "$1" in
    --version)
      [ "$#" -ge 2 ] || { usage >&2; exit 64; }
      version=$2
      shift 2
      ;;
    --bin-dir)
      [ "$#" -ge 2 ] || { usage >&2; exit 64; }
      bin_dir=$2
      shift 2
      ;;
    --uninstall)
      uninstall=1
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      usage >&2
      exit 64
      ;;
  esac
done

if printf '%s' "$bin_dir" | LC_ALL=C grep -q '[[:cntrl:]]'; then
  printf '%s\n' "install path contains an unsupported control character" >&2
  exit 64
fi

binary_path="$bin_dir/satelle"
receipt_path="$bin_dir/.satelle-install.json"
lock_path="$bin_dir/.satelle-install.lock"
temporary_root=""
install_path=""
staged_receipt_path=""
previous_binary_path=""
previous_receipt_path=""
lock_held=0
commit_started=0
had_binary=0
had_receipt=0
active_command_pid=""
active_wait_pid=""

rollback_install() {
  rm -f "$binary_path" "$receipt_path" "$install_path" "$staged_receipt_path"
  if [ "$had_binary" -eq 1 ] && [ -f "$previous_binary_path" ]; then
    mv -f "$previous_binary_path" "$binary_path"
  fi
  if [ "$had_receipt" -eq 1 ] && [ -f "$previous_receipt_path" ]; then
    mv -f "$previous_receipt_path" "$receipt_path"
  fi
  commit_started=0
}

cleanup() {
  if [ -n "$active_wait_pid" ]; then
    kill "$active_wait_pid" 2>/dev/null || :
    wait "$active_wait_pid" 2>/dev/null || :
    active_wait_pid=""
  fi
  if [ -n "$active_command_pid" ]; then
    kill -TERM "$active_command_pid" 2>/dev/null || :
    kill -KILL "$active_command_pid" 2>/dev/null || :
    wait "$active_command_pid" 2>/dev/null || :
    active_command_pid=""
  fi
  if [ "$commit_started" -eq 1 ]; then
    rollback_install
  fi
  for cleanup_path in "$install_path" "$staged_receipt_path" "$previous_binary_path" "$previous_receipt_path"; do
    [ -z "$cleanup_path" ] || rm -f "$cleanup_path"
  done
  [ -z "$temporary_root" ] || rm -rf "$temporary_root"
  if [ "$lock_held" -eq 1 ]; then
    rmdir "$lock_path" 2>/dev/null || :
    lock_held=0
  fi
}

terminate() {
  status=$1
  trap - EXIT HUP INT TERM
  cleanup
  exit "$status"
}

trap cleanup EXIT
trap 'terminate 129' HUP
trap 'terminate 130' INT
trap 'terminate 143' TERM

acquire_install_lock() {
  mkdir -p "$bin_dir"
  if ! mkdir "$lock_path" 2>/dev/null; then
    printf '%s\n' "another Satelle install operation holds $lock_path; remove it only after confirming no installer is running" >&2
    exit 1
  fi
  lock_held=1
}

# Keep both the command and polling sleep as direct children so every signal path can reap
# them before cleanup releases the installation lock.
run_with_timeout() {
  timeout_seconds=$1
  shift
  "$@" &
  active_command_pid=$!
  elapsed_ticks=0
  timeout_ticks=$((timeout_seconds * 10))

  while kill -0 "$active_command_pid" 2>/dev/null; do
    if [ "$elapsed_ticks" -ge "$timeout_ticks" ]; then
      kill -TERM "$active_command_pid" 2>/dev/null || :
      grace_ticks=0
      while kill -0 "$active_command_pid" 2>/dev/null && [ "$grace_ticks" -lt 50 ]; do
        sleep 0.1 &
        active_wait_pid=$!
        wait "$active_wait_pid" 2>/dev/null || :
        active_wait_pid=""
        grace_ticks=$((grace_ticks + 1))
      done
      kill -KILL "$active_command_pid" 2>/dev/null || :
      wait "$active_command_pid" 2>/dev/null || :
      active_command_pid=""
      return 124
    fi

    sleep 0.1 &
    active_wait_pid=$!
    wait "$active_wait_pid" 2>/dev/null || :
    active_wait_pid=""
    elapsed_ticks=$((elapsed_ticks + 1))
  done

  if wait "$active_command_pid"; then
    command_status=0
  else
    command_status=$?
  fi
  active_command_pid=""
  return "$command_status"
}

if [ "$uninstall" -eq 1 ]; then
  acquire_install_lock
  [ -f "$receipt_path" ] || {
    printf '%s\n' "Satelle install receipt not found at $receipt_path" >&2
    exit 1
  }
  rm -f "$binary_path"
  rm -f "$receipt_path"
  printf '%s\n' "Uninstalled Satelle from $binary_path"
  exit 0
fi

command -v gh >/dev/null 2>&1 || {
  printf '%s\n' "gh is required to verify the signed release tag and Sigstore attestation" >&2
  exit 1
}
command -v jq >/dev/null 2>&1 || {
  printf '%s\n' "jq is required to validate the release binary JSON contract" >&2
  exit 1
}

validate_paths_output() {
  jq -e '
    def valid_path_source:
      type == "string" and
      (. == "os_default" or
       . == "satelle_home" or
       . == "explicit_environment" or
       . == "project_discovery");
    type == "object" and
    .schema_version == "satelle.paths.v1" and
    (.host | type == "string") and
    (.config_file | type == "string") and
    (.cache_root | type == "string") and
    (.state_root | type == "string") and
    (.sqlite_store | type == "string") and
    (.operator_log_root | type == "string") and
    (.recording_root | type == "string") and
    (.project_config_file | type == "string") and
    (.install_receipt | type == "string") and
    (.sources | type == "object") and
    (.sources.config_file | valid_path_source) and
    (.sources.cache_root | valid_path_source) and
    (.sources.state_root | valid_path_source) and
    (.sources.sqlite_store | valid_path_source) and
    (.sources.operator_log_root | valid_path_source) and
    (.sources.recording_root | valid_path_source) and
    (.sources.project_config_file | valid_path_source) and
    (.sources.install_receipt | valid_path_source)
  ' >/dev/null
}

temporary_root=$(mktemp -d "${TMPDIR:-/tmp}/satelle-install.XXXXXX")
acquire_install_lock

if [ -z "$version" ]; then
  latest_version_path="$temporary_root/latest-version"
  run_with_timeout 300 gh api "repos/$repository/releases/latest" --jq '.tag_name' >"$latest_version_path"
  version=$(cat "$latest_version_path")
  version=${version#v}
fi
case "$version" in
  ''|*[!0-9A-Za-z.-]*) printf '%s\n' "invalid Satelle version: $version" >&2; exit 64 ;;
esac
printf '%s' "$version" | grep -Eq '^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$' || {
  printf '%s\n' "invalid Satelle version: $version" >&2
  exit 64
}

system=$(uname -s)
machine=$(uname -m)
case "$system:$machine" in
  Linux:x86_64|Linux:amd64) target="linux-x64-gnu" ;;
  Linux:aarch64|Linux:arm64) target="linux-arm64-gnu" ;;
  Darwin:x86_64|Darwin:amd64) target="darwin-x64" ;;
  Darwin:arm64|Darwin:aarch64) target="darwin-arm64" ;;
  *) printf '%s\n' "unsupported Satelle installer target: $system/$machine" >&2; exit 1 ;;
esac

archive="satelle-v$version-$target.tar.gz"
download_url="$release_base/download/v$version"

download() {
  source_url=$1
  destination=$2
  if command -v curl >/dev/null 2>&1; then
    run_with_timeout 300 curl -fsSL --connect-timeout 10 --max-time 300 -o "$destination" "$source_url"
  elif command -v wget >/dev/null 2>&1; then
    run_with_timeout 300 wget -q --connect-timeout=10 --read-timeout=30 -O "$destination" "$source_url"
  else
    printf '%s\n' "curl or wget is required" >&2
    exit 1
  fi
}

archive_path="$temporary_root/$archive"
checksums_path="$temporary_root/SHA256SUMS"
download "$download_url/$archive" "$archive_path"
download "$download_url/SHA256SUMS" "$checksums_path"

last_checksum_byte=$(tail -c 1 "$checksums_path" | od -An -t x1 | tr -d '[:space:]')
[ "$last_checksum_byte" = "0a" ] || {
  printf '%s\n' "SHA256SUMS must be canonical LF-delimited records" >&2
  exit 1
}
checksum_entry=$(LC_ALL=C awk -v archive="$archive" '
  function reject() { invalid = 1; exit }
  {
    if (length($0) < 67) reject()
    digest = substr($0, 1, 64)
    separator = substr($0, 65, 2)
    name = substr($0, 67)
    if (digest ~ /[^0-9a-f]/ ||
      separator != "  " ||
      name == "" ||
      name == "." ||
      name == ".." ||
      name == "SHA256SUMS" ||
      name ~ /[[:space:]]/ ||
      index(name, "/") != 0 ||
      index(name, "\\") != 0 ||
      (previous != "" && name <= previous)) reject()
    previous = name
    if (name == archive) {
      found += 1
      selected = digest
    }
  }
  END {
    if (invalid || found != 1) exit 1
    print selected
  }
' "$checksums_path") || {
  printf '%s\n' "SHA256SUMS must be canonical and contain exactly one entry for $archive" >&2
  exit 1
}
if command -v sha256sum >/dev/null 2>&1; then
  actual_digest=$(sha256sum "$archive_path" | awk '{ print $1 }')
else
  actual_digest=$(shasum -a 256 "$archive_path" | awk '{ print $1 }')
fi
[ "$actual_digest" = "$checksum_entry" ] || {
  printf '%s\n' "$archive does not match SHA256SUMS" >&2
  exit 1
}

tag_ref_path="$temporary_root/tag-ref"
run_with_timeout 300 gh api "repos/$repository/git/ref/tags/v$version" \
  --jq '.object.type + " " + .object.sha' >"$tag_ref_path"
tag_ref=$(cat "$tag_ref_path")
tag_type=${tag_ref%% *}
tag_digest=${tag_ref#* }
[ "$tag_type" = "tag" ] && printf '%s' "$tag_digest" | grep -Eq '^[0-9a-f]{40}([0-9a-f]{24})?$' || {
  printf '%s\n' "release tag v$version is not an annotated tag" >&2
  exit 1
}
source_digest_path="$temporary_root/source-digest"
run_with_timeout 300 gh api "repos/$repository/git/tags/$tag_digest" \
  --jq 'select(.verification.verified == true and .object.type == "commit") | .object.sha' \
  >"$source_digest_path"
source_digest=$(cat "$source_digest_path")
printf '%s' "$source_digest" | grep -Eq '^[0-9a-f]{40}([0-9a-f]{24})?$' || {
  printf '%s\n' "release tag v$version is not signed, verified, and commit-backed" >&2
  exit 1
}

run_with_timeout 300 gh attestation verify "$archive_path" \
  --repo "$repository" \
  --signer-workflow "$repository/.github/workflows/release.yml" \
  --source-ref "refs/tags/v$version" \
  --source-digest "$source_digest" \
  --signer-digest "$source_digest" \
  --cert-oidc-issuer "https://token.actions.githubusercontent.com" \
  --deny-self-hosted-runners \
  --format json >/dev/null

extract_root="$temporary_root/extracted"
mkdir "$extract_root"
archive_members=$(tar -tzf "$archive_path")
[ "$archive_members" = "satelle" ] || {
  printf '%s\n' "$archive must contain only satelle at its root" >&2
  exit 1
}
tar -xzf "$archive_path" -C "$extract_root"
[ -f "$extract_root/satelle" ] && [ ! -L "$extract_root/satelle" ] || {
  printf '%s\n' "$archive must contain only satelle at its root" >&2
  exit 1
}
chmod 755 "$extract_root/satelle"
if ! version_output=$("$extract_root/satelle" --version); then
  printf '%s\n' "release binary version does not match v$version" >&2
  exit 1
fi
[ "$version_output" = "satelle $version" ] || {
  printf '%s\n' "release binary version does not match v$version" >&2
  exit 1
}
if ! paths_output=$("$extract_root/satelle" paths --json); then
  printf '%s\n' "release binary failed the satelle.paths.v1 smoke test" >&2
  exit 1
fi
printf '%s' "$paths_output" | validate_paths_output || {
  printf '%s\n' "release binary failed the satelle.paths.v1 smoke test" >&2
  exit 1
}

mkdir -p "$bin_dir"
install_path="$bin_dir/.satelle.installing.$$"
staged_receipt_path="$bin_dir/.satelle-receipt.installing.$$"
previous_binary_path="$bin_dir/.satelle.previous.$$"
previous_receipt_path="$bin_dir/.satelle-receipt.previous.$$"
cp "$extract_root/satelle" "$install_path"
chmod 755 "$install_path"
installed_at=$(date -u '+%Y-%m-%dT%H:%M:%SZ')
escaped_binary_path=$(printf '%s' "$binary_path" | sed 's/\\/\\\\/g; s/"/\\"/g')
cat >"$staged_receipt_path" <<EOF
{
  "install_method": "satelle-install-script",
  "binary_path": "$escaped_binary_path",
  "version": "$version",
  "target": "$target",
  "artifact_digest": "$actual_digest",
  "installed_at": "$installed_at"
}
EOF
chmod 600 "$staged_receipt_path"

had_binary=0
had_receipt=0
if [ -e "$binary_path" ]; then
  cp -p "$binary_path" "$previous_binary_path"
  had_binary=1
fi
if [ -e "$receipt_path" ]; then
  cp -p "$receipt_path" "$previous_receipt_path"
  had_receipt=1
fi

commit_started=1
if mv -f "$install_path" "$binary_path" && mv -f "$staged_receipt_path" "$receipt_path"; then
  commit_started=0
  rm -f "$previous_binary_path" "$previous_receipt_path"
else
  rollback_install
  printf '%s\n' "Satelle installation could not commit the binary and receipt" >&2
  exit 1
fi
printf '%s\n' "Installed Satelle $version at $binary_path"
