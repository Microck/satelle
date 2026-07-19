"use strict";

const assert = require("node:assert/strict");
const { execFileSync, spawn, spawnSync } = require("node:child_process");
const { createHash } = require("node:crypto");
const { once } = require("node:events");
const {
  chmodSync,
  existsSync,
  mkdtempSync,
  mkdirSync,
  readFileSync,
  rmSync,
  writeFileSync,
} = require("node:fs");
const { tmpdir } = require("node:os");
const path = require("node:path");
const test = require("node:test");

const repositoryRoot = path.resolve(__dirname, "../..");
const { createReleaseContext } = require(path.join(
  repositoryRoot,
  "npm",
  "scripts",
  "release.cjs",
));

function sha256(filePath) {
  return createHash("sha256").update(readFileSync(filePath)).digest("hex");
}

function writeExecutable(filePath, source) {
  writeFileSync(filePath, source, { mode: 0o755 });
  chmodSync(filePath, 0o755);
}

async function waitForPath(filePath, timeoutMilliseconds = 5_000) {
  const deadline = Date.now() + timeoutMilliseconds;
  while (!existsSync(filePath)) {
    assert.ok(Date.now() < deadline, `timed out waiting for ${filePath}`);
    await new Promise((resolve) => setTimeout(resolve, 20));
  }
}

test("release integrity metadata is canonical, complete, and fail-closed", (context) => {
  const root = mkdtempSync(path.join(tmpdir(), "satelle-checksums-"));
  context.after(() => rmSync(root, { recursive: true, force: true }));
  writeFileSync(path.join(root, "b.zip"), "windows");
  writeFileSync(path.join(root, "a.tar.gz"), "unix");

  const release = createReleaseContext(repositoryRoot);
  const manifest = release.writeSha256Sums(root, ["b.zip", "a.tar.gz"]);
  assert.equal(
    readFileSync(manifest.path, "utf8"),
    `${sha256(path.join(root, "a.tar.gz"))}  a.tar.gz\n${sha256(path.join(root, "b.zip"))}  b.zip\n`,
  );
  assert.deepEqual(release.verifySha256Sums(root, manifest.path), ["a.tar.gz", "b.zip"]);

  writeFileSync(path.join(root, "a.tar.gz"), "changed");
  assert.throws(
    () => release.verifySha256Sums(root, manifest.path),
    (error) => error.code === "release-checksum-mismatch",
  );
  writeFileSync(manifest.path, `${"0".repeat(64)}  ../escape\n`);
  assert.throws(
    () => release.verifySha256Sums(root, manifest.path),
    (error) => error.code === "release-checksum-invalid",
  );
});

test("attestation policy pins repository, workflow, tag, digests, issuer, and hosted runners", () => {
  const release = createReleaseContext(repositoryRoot);
  const digest = "a".repeat(40);
  assert.deepEqual(
    release.attestationVerificationArguments("archive.tar.gz", {
      version: "0.1.0",
      sourceDigest: digest,
      signerDigest: digest,
      bundlePath: "archive.sigstore.jsonl",
    }),
    [
      "attestation",
      "verify",
      "archive.tar.gz",
      "--repo",
      "Microck/satelle",
      "--signer-workflow",
      "Microck/satelle/.github/workflows/release.yml",
      "--source-ref",
      "refs/tags/v0.1.0",
      "--source-digest",
      digest,
      "--signer-digest",
      digest,
      "--cert-oidc-issuer",
      "https://token.actions.githubusercontent.com",
      "--deny-self-hosted-runners",
      "--bundle",
      "archive.sigstore.jsonl",
      "--format",
      "json",
    ],
  );
  assert.throws(
    () => release.attestationVerificationArguments("archive.tar.gz", {
      version: "0.1.0",
      sourceDigest: "bad",
      signerDigest: digest,
    }),
    (error) => error.code === "release-attestation-policy-invalid",
  );
  assert.throws(
    () => release.attestationVerificationArguments("archive.tar.gz", {
      version: "0.1.0-rc.1",
      sourceDigest: digest,
      signerDigest: digest,
    }),
    (error) => error.code === "release-attestation-policy-invalid",
  );
});

test("Windows drive-style npm archive paths reach tar only as basenames", {
  skip: process.platform !== "win32",
}, (context) => {
  const destination = mkdtempSync(path.join(tmpdir(), "satelle-windows-tar-path-"));
  context.after(() => rmSync(destination, { recursive: true, force: true }));
  const tarInvocations = [];
  const release = createReleaseContext(repositoryRoot, {
    observeTarInvocation(invocation) {
      tarInvocations.push(invocation);
    },
  });

  assert.match(path.resolve(destination), /^[A-Za-z]:[\\/]/);
  release.stageLaunchers(destination);
  assert.ok(tarInvocations.length > 0);
  for (const { argumentsList, cwd } of tarInvocations) {
    assert.equal(path.isAbsolute(cwd), true);
    assert.doesNotMatch(argumentsList.join("\0"), /[A-Za-z]:/);
    assert.equal(path.dirname(argumentsList[1]), ".");
  }
});

test("release workflow is dry-run safe and owns six-target release validation", () => {
  const workflow = readFileSync(
    path.join(repositoryRoot, ".github", "workflows", "release.yml"),
    "utf8",
  ).replaceAll("\r\n", "\n");
  for (const target of [
    "linux-arm64-gnu",
    "linux-x64-gnu",
    "darwin-arm64",
    "darwin-x64",
    "win32-arm64-msvc",
    "win32-x64-msvc",
  ]) {
    assert.match(workflow, new RegExp(target));
  }
  assert.match(workflow, /workflow_dispatch:/);
  assert.match(workflow, /npm publish[^\n]*--dry-run/);
  assert.doesNotMatch(workflow, /npm publish(?![^\n]*--dry-run)/);
  assert.doesNotMatch(workflow, /^\s+(?:validated|dist)\/npm-.*\.tgz \\?$/m);
  assert.match(workflow, /\.\/dist\/npm-satelle-scoped\.tgz/);
  assert.match(workflow, /\.\/dist\/npm-satelle-unscoped\.tgz/);
  assert.match(workflow, /dist\/npm-satelle-scoped\.tgz/);
  assert.match(workflow, /dist\/npm-satelle-unscoped\.tgz/);
  assert.doesNotMatch(workflow, /gh release (?:create|upload|edit)/);
  assert.match(workflow, /actions\/attest-build-provenance@/);
  assert.match(
    workflow,
    /attest:\n[\s\S]*?if: startsWith\(github\.ref, 'refs\/tags\/v'\)\n\s+needs: \[collect, lifecycle\]/,
  );
  assert.match(workflow, /test "\$source_digest" = "\$GITHUB_SHA"/);
  assert.match(workflow, /permissions:\n\s+attestations: write\n\s+contents: read\n\s+id-token: write/);
  assert.match(workflow, /scripts\/install\.sh" --version/);
  assert.match(workflow, /: > "\$policy_log"/);
  assert.match(workflow, /installer upgrade failed/);
  assert.match(workflow, /shasum -a 256 -c/);
  assert.match(workflow, /validate-native-release-archives/);
  assert.match(workflow, /SHA256SUMS/);
  const checkoutUses = workflow.match(/uses: actions\/checkout@[^\n]+/g) ?? [];
  const hardenedCheckoutUses = workflow.match(
    /uses: actions\/checkout@[^\n]+\n\s+with:\n\s+persist-credentials: false/g,
  ) ?? [];
  assert.equal(checkoutUses.length, 4);
  assert.equal(hardenedCheckoutUses.length, checkoutUses.length);
});

test("Unix installer bounds network commands and releases its lock on TERM", {
  skip: process.platform === "win32",
}, async (context) => {
  const installerPath = path.join(repositoryRoot, "scripts", "install.sh");
  const installer = readFileSync(installerPath, "utf8");
  assert.match(installer, /curl[^\n]*--connect-timeout 10[^\n]*--max-time 300/);
  assert.match(installer, /wget[^\n]*--connect-timeout=10[^\n]*--read-timeout=30/);
  assert.match(installer, /run_with_timeout 300 gh api/);
  assert.match(installer, /run_with_timeout 300 gh attestation verify/);

  const root = mkdtempSync(path.join(tmpdir(), "satelle-installer-signal-"));
  context.after(() => rmSync(root, { recursive: true, force: true }));
  const commands = path.join(root, "commands");
  const bin = path.join(root, "bin");
  mkdirSync(commands);
  writeExecutable(
    path.join(commands, "curl"),
    "#!/bin/sh\ntrap '' TERM\nwhile :; do sleep 1; done\n",
  );
  writeExecutable(path.join(commands, "gh"), "#!/bin/sh\nexit 0\n");
  writeExecutable(path.join(commands, "jq"), "#!/bin/sh\nexit 0\n");

  const installerProcess = spawn(
    "/bin/sh",
    [installerPath, "--version", "0.1.0", "--bin-dir", bin],
    {
      env: { ...process.env, PATH: `${commands}:${process.env.PATH}` },
      stdio: "ignore",
    },
  );
  context.after(() => {
    if (installerProcess.exitCode === null) installerProcess.kill("SIGKILL");
  });

  const lockPath = path.join(bin, ".satelle-install.lock");
  await waitForPath(lockPath);
  installerProcess.kill("SIGTERM");
  const [exitCode, signal] = await once(installerProcess, "exit");
  assert.equal(signal, null);
  assert.equal(exitCode, 143);
  assert.equal(existsSync(lockPath), false);
});

test("Unix installer performs verified install, upgrade, smoke, receipt, and uninstall", {
  skip: process.platform === "win32",
}, (context) => {
  const root = mkdtempSync(path.join(tmpdir(), "satelle-installer-"));
  context.after(() => rmSync(root, { recursive: true, force: true }));
  const fixtures = path.join(root, "fixtures");
  const commands = path.join(root, "commands");
  const bin = path.join(root, "bin");
  mkdirSync(fixtures);
  mkdirSync(commands);
  mkdirSync(bin);
  const target = process.platform === "darwin"
    ? `darwin-${process.arch === "arm64" ? "arm64" : "x64"}`
    : `linux-${process.arch === "arm64" ? "arm64" : "x64"}-gnu`;

  const completePathsPayload = {
    schema_version: "satelle.paths.v1",
    host: "local-demo",
    config_file: "/fixture/config.toml",
    cache_root: "/fixture/cache",
    state_root: "/fixture/state",
    sqlite_store: "/fixture/state/satelle.sqlite3",
    operator_log_root: "/fixture/state/logs",
    recording_root: "/fixture/state/recordings",
    project_config_file: "/fixture/project/satelle.toml",
    install_receipt: "/fixture/state/install-receipt.json",
    sources: {
      config_file: "satelle_home",
      cache_root: "satelle_home",
      state_root: "satelle_home",
      sqlite_store: "satelle_home",
      operator_log_root: "satelle_home",
      recording_root: "satelle_home",
      project_config_file: "project_discovery",
      install_receipt: "satelle_home",
    },
  };
  const makeRelease = (version, {
    versionExit = 0,
    pathsPayload = completePathsPayload,
    pathsExit = 0,
  } = {}) => {
    const stage = path.join(root, `stage-${version}`);
    mkdirSync(stage);
    const pathsJson = JSON.stringify(pathsPayload).replaceAll("'", "'\\''");
    writeExecutable(path.join(stage, "satelle"), `#!/bin/sh\nif [ "$1" = "--version" ]; then echo "satelle ${version}"; exit ${versionExit}; elif [ "$1" = "paths" ] && [ "$2" = "--json" ]; then printf '%s\\n' '${pathsJson}'; exit ${pathsExit}; else exit 64; fi\n`);
    const archive = `satelle-v${version}-${target}.tar.gz`;
    execFileSync("tar", ["-czf", path.join(fixtures, archive), "-C", stage, "satelle"]);
    const digest = sha256(path.join(fixtures, archive));
    writeFileSync(path.join(fixtures, `SHA256SUMS-${version}`), `${digest}  ${archive}\n`);
  };
  makeRelease("0.1.0");
  makeRelease("0.2.0");
  makeRelease("0.3.0", { versionExit: 1 });
  makeRelease("0.4.0", { pathsPayload: { schema_version: "satelle.paths.v1" } });
  makeRelease("0.5.0", { pathsExit: 1 });
  makeRelease("0.6.0", {
    pathsPayload: {
      ...completePathsPayload,
      sources: { config_file: "satelle_home" },
    },
  });
  makeRelease("0.7.0", {
    pathsPayload: {
      ...completePathsPayload,
      sources: { ...completePathsPayload.sources, cache_root: 42 },
    },
  });
  makeRelease("0.8.0", {
    pathsPayload: {
      ...completePathsPayload,
      sources: { ...completePathsPayload.sources, state_root: "legacy_default" },
    },
  });

  writeExecutable(path.join(commands, "curl"), `#!/bin/sh\nout=''\nurl=''\nwhile [ "$#" -gt 0 ]; do case "$1" in -o) out="$2"; shift 2;; http*) url="$1"; shift;; *) shift;; esac; done\nname=\${url##*/}\ncase "$name" in SHA256SUMS) version=\$(printf '%s' "$url" | sed -n 's#.*releases/download/v\\([^/]*\\)/.*#\\1#p'); cp "$SATELLE_FIXTURES/SHA256SUMS-$version" "$out";; *) cp "$SATELLE_FIXTURES/$name" "$out";; esac\n`);
  writeExecutable(path.join(commands, "gh"), `#!/bin/sh\nprintf '%s\\n' "$*" >> "$SATELLE_GH_LOG"\nif [ "$1" = api ]; then case "$2" in */git/ref/tags/*) echo 'tag ${"b".repeat(40)}';; */git/tags/*) echo '${"a".repeat(40)}';; *) echo 'v0.1.0';; esac; fi\n`);

  const runInstaller = (...argumentsList) => spawnSync(
    "/bin/sh",
    [path.join(repositoryRoot, "scripts", "install.sh"), ...argumentsList],
    {
      encoding: "utf8",
      env: {
        ...process.env,
        PATH: `${commands}:${process.env.PATH}`,
        SATELLE_FIXTURES: fixtures,
        SATELLE_GH_LOG: path.join(root, "gh.log"),
      },
    },
  );

  const archive = `satelle-v0.1.0-${target}.tar.gz`;
  const checksumPath = path.join(fixtures, "SHA256SUMS-0.1.0");
  const canonicalChecksum = `${sha256(path.join(fixtures, archive))}  ${archive}\n`;
  const malformedManifests = [
    ["bad-delimiter", canonicalChecksum.replace("  ", " ")],
    ["crlf", canonicalChecksum.replaceAll("\n", "\r\n")],
    ["missing-final-lf", canonicalChecksum.slice(0, -1)],
    ["duplicate", `${canonicalChecksum}${canonicalChecksum}`],
    ["unsorted", `${"0".repeat(64)}  zzz.tar.gz\n${canonicalChecksum}`],
    ["malformed-unrelated", `malformed\n${canonicalChecksum}`],
  ];
  for (const [name, manifest] of malformedManifests) {
    writeFileSync(checksumPath, manifest);
    const invalidBin = path.join(root, `invalid-${name}`);
    const invalidResult = runInstaller("--version", "0.1.0", "--bin-dir", invalidBin);
    assert.notEqual(invalidResult.status, 0, `${name} unexpectedly passed`);
    assert.match(invalidResult.stderr, /SHA256SUMS must be canonical/);
    assert.equal(existsSync(path.join(invalidBin, "satelle")), false);
  }
  writeFileSync(checksumPath, canonicalChecksum);

  const missingJqResult = spawnSync(
    "/bin/sh",
    [path.join(repositoryRoot, "scripts", "install.sh"), "--version", "0.1.0", "--bin-dir", bin],
    {
      encoding: "utf8",
      env: {
        ...process.env,
        PATH: commands,
        SATELLE_FIXTURES: fixtures,
        SATELLE_GH_LOG: path.join(root, "gh.log"),
      },
    },
  );
  assert.notEqual(missingJqResult.status, 0);
  assert.match(missingJqResult.stderr, /jq is required to validate the release binary JSON contract/);
  assert.equal(existsSync(path.join(bin, "satelle")), false);

  const prereleaseResult = runInstaller("--version", "0.1.0-rc.1", "--bin-dir", bin);
  assert.equal(prereleaseResult.status, 64);
  assert.match(prereleaseResult.stderr, /invalid Satelle version/);

  const failedSmokeBin = path.join(root, "failed-version-smoke");
  const failedSmokeResult = runInstaller("--version", "0.3.0", "--bin-dir", failedSmokeBin);
  assert.notEqual(failedSmokeResult.status, 0);
  assert.match(failedSmokeResult.stderr, /release binary version does not match/);
  assert.equal(existsSync(path.join(failedSmokeBin, "satelle")), false);

  for (const [version, smokeFailure] of [
    ["0.4.0", "incomplete paths output"],
    ["0.5.0", "nonzero paths exit"],
    ["0.6.0", "incomplete paths sources"],
    ["0.7.0", "wrongly typed paths source"],
    ["0.8.0", "invalid paths source enum"],
  ]) {
    const failedPathsBin = path.join(root, `failed-paths-smoke-${version}`);
    const failedPathsResult = runInstaller("--version", version, "--bin-dir", failedPathsBin);
    assert.notEqual(failedPathsResult.status, 0, `${smokeFailure} unexpectedly passed`);
    assert.match(failedPathsResult.stderr, /failed the satelle\.paths\.v1 smoke test/);
    assert.equal(existsSync(path.join(failedPathsBin, "satelle")), false);
  }

  let result = runInstaller("--version", "0.1.0", "--bin-dir", bin);
  assert.equal(result.status, 0, result.stderr);
  assert.equal(execFileSync(path.join(bin, "satelle"), ["--version"], { encoding: "utf8" }), "satelle 0.1.0\n");
  let receipt = JSON.parse(readFileSync(path.join(bin, ".satelle-install.json"), "utf8"));
  assert.equal(receipt.install_method, "satelle-install-script");
  assert.equal(receipt.version, "0.1.0");
  assert.equal(receipt.target, target);
  assert.equal(receipt.binary_path, path.join(bin, "satelle"));
  assert.match(receipt.artifact_digest, /^[0-9a-f]{64}$/);
  assert.ok(receipt.installed_at);

  result = runInstaller("--version", "0.2.0", "--bin-dir", bin);
  assert.equal(result.status, 0, result.stderr);
  assert.equal(execFileSync(path.join(bin, "satelle"), ["--version"], { encoding: "utf8" }), "satelle 0.2.0\n");
  const ghLog = readFileSync(path.join(root, "gh.log"), "utf8");
  for (const policy of [
    "--repo Microck/satelle",
    "--signer-workflow Microck/satelle/.github/workflows/release.yml",
    "--source-ref refs/tags/v0.2.0",
    "--deny-self-hosted-runners",
  ]) assert.match(ghLog, new RegExp(policy.replaceAll("/", "\\/")));

  const lockPath = path.join(bin, ".satelle-install.lock");
  mkdirSync(lockPath);
  result = runInstaller("--uninstall", "--bin-dir", bin);
  assert.notEqual(result.status, 0);
  assert.match(result.stderr, /another Satelle install operation holds/);
  assert.equal(existsSync(path.join(bin, "satelle")), true);
  assert.equal(existsSync(path.join(bin, ".satelle-install.json")), true);
  rmSync(lockPath, { recursive: true });

  result = runInstaller("--uninstall", "--bin-dir", bin);
  assert.equal(result.status, 0, result.stderr);
  assert.equal(existsSync(path.join(bin, "satelle")), false);
  assert.equal(existsSync(path.join(bin, ".satelle-install.json")), false);
});

test("PowerShell installer exposes the same fail-closed lifecycle contract", () => {
  const installer = readFileSync(path.join(repositoryRoot, "scripts", "install.ps1"), "utf8");
  for (const token of [
    "Version",
    "BinDir",
    "Uninstall",
    "SHA256SUMS",
    "Invoke-BoundedGh",
    "--deny-self-hosted-runners",
    "satelle.paths.v1",
    ".satelle-install.json",
    ".satelle-install.lock",
    "[System.IO.File]::ReadAllText",
    "StringComparer]::Ordinal",
  ]) assert.ok(installer.includes(token), `PowerShell installer is missing ${token}`);
  assert.doesNotMatch(installer, /\$PROFILE|SetEnvironmentVariable/);
  assert.doesNotMatch(installer, /utf8NoBOM/);
  assert.match(installer, /System\.Text\.UTF8Encoding\(\$false\)/);
  assert.match(installer, /WaitForExit\(300000\)/);
  assert.equal((installer.match(/ConnectionTimeoutSeconds 10/g) ?? []).length, 2);
  assert.equal((installer.match(/OperationTimeoutSeconds 300/g) ?? []).length, 2);
  assert.match(installer, /StagedReceiptPath/);
  assert.match(installer, /PreviousBinaryPath/);
  assert.match(
    installer,
    /\$VersionOutput = & \$Members\[0\]\.FullName --version\s+if \(\$LASTEXITCODE -ne 0 -or \$VersionOutput -ne "satelle \$Version"\)/,
  );
  assert.match(
    installer,
    /\$PathsOutput = & \$Members\[0\]\.FullName paths --json\s+if \(\$LASTEXITCODE -ne 0\) \{[\s\S]*?\}\s+\$Paths = \$PathsOutput \| ConvertFrom-Json\s+Assert-SatellePathsPayload \$Paths/,
  );
  for (const field of [
    "host",
    "config_file",
    "cache_root",
    "state_root",
    "sqlite_store",
    "operator_log_root",
    "recording_root",
    "project_config_file",
    "install_receipt",
    "sources",
  ]) assert.ok(installer.includes(`"${field}"`), `PowerShell paths verifier is missing ${field}`);
  assert.match(
    installer,
    /\$SourceFields\s*=\s*@\([\s\S]*?"config_file"[\s\S]*?"cache_root"[\s\S]*?"state_root"[\s\S]*?"sqlite_store"[\s\S]*?"operator_log_root"[\s\S]*?"recording_root"[\s\S]*?"project_config_file"[\s\S]*?"install_receipt"[\s\S]*?\)/,
  );
  assert.match(installer, /\$AllowedPathSources\s*=\s*@\("os_default", "satelle_home", "explicit_environment", "project_discovery"\)/);
});

test("PowerShell installer rejects nonzero and malformed nested paths payloads", {
  skip: process.platform === "win32",
}, (context) => {
  const root = mkdtempSync(path.join(tmpdir(), "satelle-pwsh-paths-"));
  context.after(() => rmSync(root, { recursive: true, force: true }));
  const fixtures = path.join(root, "fixtures");
  const commands = path.join(root, "commands");
  mkdirSync(fixtures);
  mkdirSync(commands);
  writeExecutable(
    path.join(commands, "gh"),
    `#!/bin/sh
if [ "$1" = "api" ]; then
  case "$2" in
    */git/ref/tags/*) echo '{"object":{"type":"tag","sha":"${"b".repeat(40)}"}}' ;;
    */git/tags/*) echo '{"verification":{"verified":true},"object":{"type":"commit","sha":"${"a".repeat(40)}"}}' ;;
  esac
  exit 0
fi
echo '[{}]'
`,
  );
  const target = `win32-${process.arch === "arm64" ? "arm64" : "x64"}-msvc`;
  const sourceFields = [
    "config_file",
    "cache_root",
    "state_root",
    "sqlite_store",
    "operator_log_root",
    "recording_root",
    "project_config_file",
    "install_receipt",
  ];
  const completePathsPayload = {
    schema_version: "satelle.paths.v1",
    host: "local-demo",
    config_file: "C:\\fixture\\config.toml",
    cache_root: "C:\\fixture\\cache",
    state_root: "C:\\fixture\\state",
    sqlite_store: "C:\\fixture\\state\\satelle.sqlite3",
    operator_log_root: "C:\\fixture\\state\\logs",
    recording_root: "C:\\fixture\\state\\recordings",
    project_config_file: "C:\\fixture\\project\\satelle.toml",
    install_receipt: "C:\\fixture\\state\\install-receipt.json",
    sources: Object.fromEntries(sourceFields.map((field) => [field, "satelle_home"])),
  };
  completePathsPayload.sources.project_config_file = "project_discovery";

  const cases = [
    { name: "nonzero-exit-before-json", pathsOutput: "not-json", pathsExit: 23 },
    { name: "malformed-json", pathsOutput: "{" },
    { name: "missing-sources", payload: { ...completePathsPayload, sources: undefined } },
    { name: "wrong-type-sources", payload: { ...completePathsPayload, sources: [] } },
  ];
  for (const field of sourceFields) {
    const missing = structuredClone(completePathsPayload);
    delete missing.sources[field];
    cases.push({ name: `missing-${field}`, payload: missing });

    const wrongType = structuredClone(completePathsPayload);
    wrongType.sources[field] = 42;
    cases.push({ name: `wrong-type-${field}`, payload: wrongType });

    const invalidEnum = structuredClone(completePathsPayload);
    invalidEnum.sources[field] = "legacy_default";
    cases.push({ name: `invalid-enum-${field}`, payload: invalidEnum });
  }

  for (const [index, fixture] of cases.entries()) {
    const version = `1.0.${index + 1}`;
    const stage = path.join(root, `stage-${index}`);
    mkdirSync(stage);
    const executablePath = path.join(stage, "satelle.exe");
    const pathsOutput = fixture.pathsOutput ?? JSON.stringify(fixture.payload);
    const shellOutput = pathsOutput.replaceAll("'", "'\\''");
    writeExecutable(
      executablePath,
      `#!/bin/sh\nif [ "$1" = "--version" ]; then echo "satelle ${version}"; exit 0; fi\nif [ "$1" = "paths" ] && [ "$2" = "--json" ]; then printf '%s\\n' '${shellOutput}'; exit ${fixture.pathsExit ?? 0}; fi\nexit 64\n`,
    );
    const archive = `satelle-v${version}-${target}.zip`;
    execFileSync("zip", ["-q", "-j", path.join(fixtures, archive), executablePath]);
    writeFileSync(
      path.join(fixtures, `SHA256SUMS-${version}`),
      `${sha256(path.join(fixtures, archive))}  ${archive}\n`,
    );

    const bin = path.join(root, `bin-${index}`);
    const harnessPath = path.join(root, `harness-${index}.ps1`);
    const harness = `
$ErrorActionPreference = "Stop"
$FixtureRoot = ${JSON.stringify(fixtures)}
$Version = ${JSON.stringify(version)}
$BinDir = ${JSON.stringify(bin)}
$env:PATH = ${JSON.stringify(commands)} + [System.IO.Path]::PathSeparator + $env:PATH
function global:Invoke-WebRequest {
  param(
    [string]$Uri,
    [string]$OutFile,
    [int]$ConnectionTimeoutSeconds,
    [int]$OperationTimeoutSeconds
  )
  if ($ConnectionTimeoutSeconds -ne 10 -or $OperationTimeoutSeconds -ne 300) {
    throw "installer HTTP timeout policy mismatch"
  }
  $Name = [System.IO.Path]::GetFileName($Uri)
  $Source = if ($Name -eq "SHA256SUMS") { Join-Path $FixtureRoot "SHA256SUMS-$Version" } else { Join-Path $FixtureRoot $Name }
  Copy-Item -LiteralPath $Source -Destination $OutFile
}
& ${JSON.stringify(path.join(repositoryRoot, "scripts", "install.ps1"))} -Version $Version -BinDir $BinDir
`;
    writeFileSync(harnessPath, harness);
    const result = spawnSync("pwsh", ["-NoProfile", "-File", harnessPath], { encoding: "utf8" });
    assert.notEqual(
      result.status,
      0,
      `${fixture.name} unexpectedly passed\nstdout:\n${result.stdout}\nstderr:\n${result.stderr}`,
    );
    assert.equal(existsSync(path.join(bin, "satelle.exe")), false, fixture.name);
    if (fixture.name === "nonzero-exit-before-json") {
      assert.match(result.stderr, /failed the satelle\.paths\.v1 smoke test/);
      assert.doesNotMatch(result.stderr, /ConvertFrom-Json/);
    }
  }
});
