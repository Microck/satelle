"use strict";

const assert = require("node:assert/strict");
const { execFileSync, spawn, spawnSync } = require("node:child_process");
const { once } = require("node:events");
const {
  chmodSync,
  cpSync,
  existsSync,
  mkdtempSync,
  mkdirSync,
  readdirSync,
  readFileSync,
  rmSync,
  symlinkSync,
  truncateSync,
  writeFileSync,
} = require("node:fs");
const { tmpdir } = require("node:os");
const path = require("node:path");
const test = require("node:test");

const repositoryRoot = path.resolve(__dirname, "../..");
const releaseScriptPath = path.join(repositoryRoot, "npm", "scripts", "release.cjs");
const {
  ReleaseError,
  createReleaseContext,
} = require(releaseScriptPath);

const expectedTargets = [
  "darwin-arm64",
  "darwin-x64",
  "linux-arm64-gnu",
  "linux-x64-gnu",
  "win32-arm64-msvc",
  "win32-x64-msvc",
];

function hostTarget() {
  const architecture = process.arch === "arm64" ? "arm64" : "x64";
  if (process.platform === "win32") return `win32-${architecture}-msvc`;
  if (process.platform === "darwin") return `darwin-${architecture}`;
  return `linux-${architecture}-gnu`;
}

function readJson(filePath) {
  return JSON.parse(readFileSync(filePath, "utf8"));
}

function workspaceVersion() {
  const cargo = readFileSync(path.join(repositoryRoot, "Cargo.toml"), "utf8");
  const workspacePackage = cargo.match(/\[workspace\.package\]([\s\S]*?)(?:\n\[|$)/);
  const version = workspacePackage?.[1].match(/^version\s*=\s*"([^"]+)"/m)?.[1];
  assert.ok(version, "Cargo workspace version is missing");
  return version;
}

function writeSyntheticNative(filePath, target, size = 256) {
  const binary = Buffer.alloc(size);
  if (target.startsWith("linux-")) {
    Buffer.from([0x7f, 0x45, 0x4c, 0x46, 2, 1]).copy(binary);
    binary.writeUInt16LE(target.includes("arm64") ? 183 : 62, 18);
    binary.write("libc.so.6 /lib64/ld-linux", 64, "ascii");
  } else if (target.startsWith("darwin-")) {
    binary.writeUInt32LE(0xfeedfacf, 0);
    binary.writeUInt32LE(target.includes("arm64") ? 0x0100000c : 0x01000007, 4);
  } else {
    binary.write("MZ", 0, "ascii");
    binary.writeUInt32LE(128, 0x3c);
    binary.write("PE\0\0", 128, "ascii");
    binary.writeUInt16LE(target.includes("arm64") ? 0xaa64 : 0x8664, 132);
  }
  writeFileSync(filePath, binary);
  if (process.platform !== "win32") chmodSync(filePath, 0o755);
}

function compileVersionFixture(destination) {
  const sourcePath = path.join(destination, "version-fixture.c");
  const binaryPath = path.join(
    destination,
    process.platform === "win32" ? "version-fixture.exe" : "version-fixture",
  );
  writeFileSync(
    sourcePath,
    `#include <stdio.h>
#ifdef _WIN32
#include <fcntl.h>
#include <io.h>
#endif

int main(void) {
#ifdef _WIN32
  _setmode(_fileno(stdout), _O_BINARY);
#endif
  fputs("satelle ${workspaceVersion()}\\n", stdout);
}
`,
  );
  execFileSync("cc", [sourcePath, "-o", binaryPath]);
  return binaryPath;
}

function compileArtifactReplacingFixture(destination, sourceArtifact, targetArtifact) {
  const sourcePath = path.join(destination, "artifact-replacing-fixture.c");
  const binaryPath = path.join(destination, "artifact-replacing-fixture");
  writeFileSync(
    sourcePath,
    `#include <stdio.h>
#include <string.h>

static int replace_artifact(void) {
  FILE *source = fopen(${JSON.stringify(sourceArtifact)}, "rb");
  FILE *target = fopen(${JSON.stringify(targetArtifact)}, "wb");
  if (source == NULL || target == NULL) return 1;
  unsigned char buffer[8192];
  size_t count;
  while ((count = fread(buffer, 1, sizeof buffer, source)) > 0) {
    if (fwrite(buffer, 1, count, target) != count) return 1;
  }
  return fclose(source) != 0 || fclose(target) != 0;
}

int main(int argc, char **argv) {
  if (argc != 2 || strcmp(argv[1], "--version") != 0) return 1;
  if (replace_artifact() != 0) return 1;
  fputs("satelle ${workspaceVersion()}\\n", stdout);
  return 0;
}
`,
  );
  execFileSync("cc", [sourcePath, "-o", binaryPath]);
  return binaryPath;
}

function stageCompleteArtifactSet(
  release,
  destination,
  hostBinaryPath = compileVersionFixture(destination),
) {
  for (const target of expectedTargets) {
    const binaryPath = path.join(destination, `fixture-${target}`);
    if (target === hostTarget()) cpSync(hostBinaryPath, binaryPath);
    else writeSyntheticNative(binaryPath, target);
    chmodSync(binaryPath, 0o755);
    release.stageNative(target, binaryPath, destination);
  }
  release.stageLaunchers(destination);
}

function writeJson(filePath, value) {
  writeFileSync(filePath, `${JSON.stringify(value, null, 2)}\n`);
}

function rewriteNpmArchive(archivePath, destination, mutate) {
  const rewriteRoot = mkdtempSync(path.join(destination, "rewrite-"));
  execFileSync("tar", ["-xzf", archivePath, "-C", rewriteRoot]);
  const packageRoot = path.join(rewriteRoot, "package");
  mutate(packageRoot);
  const members = [];
  function collectFiles(directory, relativeDirectory) {
    for (const entry of readdirSync(directory, { withFileTypes: true })) {
      const absolutePath = path.join(directory, entry.name);
      const relativePath = path.join(relativeDirectory, entry.name);
      if (entry.isDirectory()) collectFiles(absolutePath, relativePath);
      else members.push(relativePath);
    }
  }
  collectFiles(packageRoot, "package");
  execFileSync("tar", ["-czf", archivePath, "-C", rewriteRoot, ...members]);
}

function fixtureRepository(context) {
  const fixtureRoot = mkdtempSync(path.join(tmpdir(), "satelle-release-fixture-"));
  context.after(() => rmSync(fixtureRoot, { recursive: true, force: true }));

  for (const fileName of ["Cargo.toml", "README.md"]) {
    cpSync(path.join(repositoryRoot, fileName), path.join(fixtureRoot, fileName));
  }
  mkdirSync(path.join(fixtureRoot, "npm"), { recursive: true });
  for (const directory of [
    "satelle",
    "satelle-unscoped",
    ...expectedTargets.map((target) => `satelle-${target}`),
  ]) {
    cpSync(
      path.join(repositoryRoot, "npm", directory),
      path.join(fixtureRoot, "npm", directory),
      { recursive: true },
    );
  }
  mkdirSync(path.join(fixtureRoot, "npm", "scripts"), { recursive: true });
  cpSync(
    path.join(repositoryRoot, "npm", "scripts", "verify-native-package.cjs"),
    path.join(fixtureRoot, "npm", "scripts", "verify-native-package.cjs"),
  );
  return fixtureRoot;
}

function expectReleaseError(code) {
  return (error) => error instanceof ReleaseError && error.code === code;
}

test("release check returns the canonical package and archive ownership plan", () => {
  const release = createReleaseContext(repositoryRoot);
  const plan = release.check();
  const version = workspaceVersion();

  assert.equal(plan.schemaVersion, "satelle.release-plan.v1");
  assert.equal(plan.version, version);
  assert.deepEqual(plan.targets, expectedTargets);
  assert.deepEqual(plan.publicationOrder, [
    ...expectedTargets.map((target) => `@microck/satelle-${target}`),
    "@microck/satelle",
    "satelle",
  ]);
  assert.deepEqual(
    plan.artifacts.map(({ archive }) => archive),
    expectedTargets.map((target) =>
      `satelle-v${version}-${target}.${target.startsWith("win32-") ? "zip" : "tar.gz"}`,
    ),
  );
  assert.deepEqual(
    plan.artifacts.map(({ npmArtifact }) => npmArtifact),
    expectedTargets.map((target) => `npm-${target}.tgz`),
  );

  plan.targets.length = 0;
  plan.publicationOrder.reverse();
  assert.deepEqual(release.check().targets, expectedTargets);
  assert.deepEqual(release.check().publicationOrder, [
    ...expectedTargets.map((target) => `@microck/satelle-${target}`),
    "@microck/satelle",
    "satelle",
  ]);
});

test("release check rejects a tag that diverges from workspace metadata", () => {
  const release = createReleaseContext(repositoryRoot);
  assert.throws(() => release.check("v9.9.9"), expectReleaseError("release-version-mismatch"));
});

test("release check rejects a missing optional dependency for a matrix target", (context) => {
  const fixtureRoot = fixtureRepository(context);
  const manifestPath = path.join(fixtureRoot, "npm", "satelle", "package.json");
  const manifest = readJson(manifestPath);
  delete manifest.optionalDependencies["@microck/satelle-linux-x64-gnu"];
  writeJson(manifestPath, manifest);

  assert.throws(
    () => createReleaseContext(fixtureRoot).check(),
    expectReleaseError("release-package-graph-mismatch"),
  );
});

test("release check rejects stray published install-time dependency edges", (context) => {
  for (const { directory, field } of [
    { directory: "satelle", field: "dependencies" },
    { directory: "satelle-linux-x64-gnu", field: "peerDependencies" },
  ]) {
    const fixtureRoot = fixtureRepository(context);
    const manifestPath = path.join(fixtureRoot, "npm", directory, "package.json");
    const manifest = readJson(manifestPath);
    manifest[field] = { "unexpected-package": "1.0.0" };
    writeJson(manifestPath, manifest);
    assert.throws(
      () => createReleaseContext(fixtureRoot).check(),
      expectReleaseError("release-package-graph-mismatch"),
      `${directory} ${field}`,
    );
  }
});

test("release check rejects version, executable, and publication metadata drift", (context) => {
  const cases = [
    {
      code: "release-version-mismatch",
      manifest: "satelle-darwin-arm64",
      mutate: (manifest) => ({ ...manifest, version: "0.2.0" }),
    },
    {
      code: "release-package-metadata-mismatch",
      manifest: "satelle-unscoped",
      mutate: (manifest) => ({ ...manifest, bin: { satelle: "bin/other.cjs" } }),
    },
    {
      code: "release-package-metadata-mismatch",
      manifest: "satelle-win32-x64-msvc",
      mutate: (manifest) => ({
        ...manifest,
        publishConfig: { ...manifest.publishConfig, provenance: false },
      }),
    },
    {
      code: "release-package-metadata-mismatch",
      manifest: "satelle-linux-arm64-gnu",
      mutate: (manifest) => ({ ...manifest, private: true }),
    },
  ];

  for (const releaseCase of cases) {
    const fixtureRoot = fixtureRepository(context);
    const manifestPath = path.join(
      fixtureRoot,
      "npm",
      releaseCase.manifest,
      "package.json",
    );
    writeJson(manifestPath, releaseCase.mutate(readJson(manifestPath)));
    assert.throws(
      () => createReleaseContext(fixtureRoot).check(),
      expectReleaseError(releaseCase.code),
      releaseCase.manifest,
    );
  }
});

test("release check rejects a mutating prepare lifecycle before it can run", (context) => {
  const fixtureRoot = fixtureRepository(context);
  const manifestPath = path.join(fixtureRoot, "npm", "satelle", "package.json");
  const prepareMarker = path.join(fixtureRoot, "prepare-ran");
  const manifest = readJson(manifestPath);
  manifest.scripts = {
    ...manifest.scripts,
    prepare: `node -e ${JSON.stringify(
      `require("node:fs").writeFileSync(${JSON.stringify(prepareMarker)}, "yes")`,
    )}`,
  };
  writeJson(manifestPath, manifest);

  assert.throws(
    () => createReleaseContext(fixtureRoot).check(),
    expectReleaseError("release-package-metadata-mismatch"),
  );
  assert.equal(existsSync(prepareMarker), false);
});

test("launcher packing ignores mutating prepack hooks", (context) => {
  const fixtureRoot = fixtureRepository(context);
  const destination = mkdtempSync(path.join(tmpdir(), "satelle-release-launcher-hooks-"));
  context.after(() => rmSync(destination, { recursive: true, force: true }));
  const markerPaths = [];
  for (const directory of ["satelle", "satelle-unscoped"]) {
    const manifestPath = path.join(fixtureRoot, "npm", directory, "package.json");
    const markerPath = path.join(fixtureRoot, `${directory}-prepack-ran`);
    markerPaths.push(markerPath);
    const manifest = readJson(manifestPath);
    manifest.scripts = {
      ...manifest.scripts,
      prepack: `node -e ${JSON.stringify(
        `require("node:fs").writeFileSync(${JSON.stringify(markerPath)}, "yes")`,
      )}`,
    };
    writeJson(manifestPath, manifest);
  }

  const artifacts = createReleaseContext(fixtureRoot).stageLaunchers(destination);
  assert.deepEqual(
    artifacts.map(({ package: packageName }) => packageName),
    ["@microck/satelle", "satelle"],
  );
  assert.deepEqual(markerPaths.map((markerPath) => existsSync(markerPath)), [false, false]);
});

test("artifact tar validation maps its deadline to a typed error", (context) => {
  const destination = mkdtempSync(path.join(tmpdir(), "satelle-release-tar-timeout-"));
  context.after(() => rmSync(destination, { recursive: true, force: true }));
  assert.throws(
    () => createReleaseContext(repositoryRoot, { tarCommandTimeoutMilliseconds: 1 })
      .stageLaunchers(destination),
    expectReleaseError("release-artifact-invalid"),
  );
});

test("release check rejects missing or contradictory pre-publication README guidance", (context) => {
  const missingGuidanceRoot = fixtureRepository(context);
  writeFileSync(path.join(missingGuidanceRoot, "README.md"), "# Satelle\n");

  assert.throws(
    () => createReleaseContext(missingGuidanceRoot).check(),
    expectReleaseError("release-readme-mismatch"),
  );

  for (const command of [
    "npm install --global satelle",
    "npm install --global \\\n  @microck/satelle",
    "pnpm --package=@microck/satelle dlx satelle",
  ]) {
    const contradictoryGuidanceRoot = fixtureRepository(context);
    writeFileSync(
      path.join(contradictoryGuidanceRoot, "README.md"),
      `${readFileSync(path.join(contradictoryGuidanceRoot, "README.md"), "utf8")}\n\`${command}\`\n`,
    );
    assert.throws(
      () => createReleaseContext(contradictoryGuidanceRoot).check(),
      expectReleaseError("release-readme-mismatch"),
      command,
    );
  }
});

test("native package assembly is real and leaves source packages unchanged", (context) => {
  // Shell metacharacters in a caller-owned path must remain ordinary argument bytes on Windows.
  const destination = mkdtempSync(path.join(tmpdir(), "satelle release & native-"));
  context.after(() => rmSync(destination, { recursive: true, force: true }));
  const target = hostTarget();
  const binaryName = target.startsWith("win32-") ? "satelle.exe" : "satelle";
  const binaryPath = path.join(destination, `fixture-${binaryName}`);
  writeSyntheticNative(binaryPath, target, 2 * 1024 * 1024);

  const release = createReleaseContext(repositoryRoot);
  assert.throws(
    () => release.stageNative("constructor", binaryPath, destination),
    expectReleaseError("release-target-unsupported"),
  );
  const artifact = release.stageNative(target, binaryPath, destination);
  const archivePath = path.join(destination, `npm-${target}.tgz`);

  assert.equal(artifact.file, `npm-${target}.tgz`);
  assert.equal(artifact.package, `@microck/satelle-${target}`);
  assert.equal(artifact.version, workspaceVersion());
  assert.equal(existsSync(archivePath), true);
  assert.equal(
    existsSync(path.join(repositoryRoot, "npm", `satelle-${target}`, "bin", binaryName)),
    false,
  );
  const wrongTarget = expectedTargets.find(
    (candidate) => candidate !== target && candidate.startsWith(target.split("-")[0]),
  );
  assert.throws(
    () => release.stageNative(wrongTarget, binaryPath, destination),
    expectReleaseError("release-binary-target-mismatch"),
  );

  const oversizedBinaryPath = path.join(destination, `oversized-${binaryName}`);
  writeFileSync(oversizedBinaryPath, "x");
  truncateSync(oversizedBinaryPath, 512 * 1024 * 1024 + 1);
  assert.throws(
    () => release.stageNative(target, oversizedBinaryPath, destination),
    expectReleaseError("release-binary-missing"),
  );

  const fixtureRoot = fixtureRepository(context);
  const relativeDestination = mkdtempSync(path.join(tmpdir(), "satelle-relative-pack-"));
  context.after(() => rmSync(relativeDestination, { recursive: true, force: true }));
  const relativeArtifact = createReleaseContext(fixtureRoot).stageNative(
    target,
    binaryPath,
    path.relative(process.cwd(), relativeDestination),
  );
  assert.equal(
    existsSync(path.join(relativeDestination, relativeArtifact.file)),
    true,
  );

  const archiveMembers = execFileSync("tar", ["-tzf", archivePath], { encoding: "utf8" });
  assert.match(archiveMembers, new RegExp(`package/bin/${binaryName.replace(".", "\\.")}`));
  assert.match(archiveMembers, /package\/package\.json/);
});

test("npm packaging timeouts use a typed release error", { timeout: 10_000 }, (context) => {
  const fixtureRoot = fixtureRepository(context);
  const destination = mkdtempSync(path.join(tmpdir(), "satelle-release-npm-timeout-"));
  context.after(() => rmSync(destination, { recursive: true, force: true }));
  const hangingNpmPath = path.join(destination, "hanging-npm.cjs");
  writeFileSync(hangingNpmPath, "while (true) {}\n");
  const inheritedNpmExecPath = process.env.npm_execpath;
  process.env.npm_execpath = hangingNpmPath;
  context.after(() => {
    if (inheritedNpmExecPath === undefined) delete process.env.npm_execpath;
    else process.env.npm_execpath = inheritedNpmExecPath;
  });

  const target = hostTarget();
  const binaryPath = path.join(
    destination,
    target.startsWith("win32-") ? "satelle.exe" : "satelle",
  );
  writeSyntheticNative(binaryPath, target);
  const startedAt = Date.now();
  assert.throws(
    () => createReleaseContext(fixtureRoot, { npmCommandTimeoutMilliseconds: 2_000 })
      .stageNative(target, binaryPath, destination),
    expectReleaseError("release-command-timeout"),
  );
  assert.ok(Date.now() - startedAt < 7_000, "npm timeout exceeded its configured bound");
});

test(
  "native package assembly preserves executable mode under a restrictive umask",
  { skip: process.platform === "win32" },
  (context) => {
    const destination = mkdtempSync(path.join(tmpdir(), "satelle-release-umask-"));
    context.after(() => rmSync(destination, { recursive: true, force: true }));
    const target = hostTarget();
    const binaryName = target.startsWith("win32-") ? "satelle.exe" : "satelle";
    const binaryPath = path.join(destination, `fixture-${binaryName}`);
    writeSyntheticNative(binaryPath, target);

    const originalUmask = process.umask(0o077);
    let artifact;
    try {
      artifact = createReleaseContext(repositoryRoot).stageNative(
        target,
        binaryPath,
        destination,
      );
    } finally {
      process.umask(originalUmask);
    }

    const archiveListing = execFileSync(
      "tar",
      ["-tvzf", path.join(destination, artifact.file)],
      { encoding: "utf8" },
    );
    const binaryEntry = archiveListing
      .split(/\r?\n/)
      .find((line) => line.endsWith(`package/bin/${binaryName}`));
    assert.match(binaryEntry, /^-rwxr-xr-x/);
  },
);

test(
  "native package assembly retains the bytes that passed target validation",
  { skip: process.platform === "win32" },
  async (context) => {
    const fixtureRoot = fixtureRepository(context);
    const destination = mkdtempSync(path.join(tmpdir(), "satelle-release-validation-race-"));
    context.after(() => rmSync(destination, { recursive: true, force: true }));
    const target = hostTarget();
    const binaryName = target.startsWith("win32-") ? "satelle.exe" : "satelle";
    const binaryPath = path.join(destination, `fixture-${binaryName}`);
    const replacementPath = path.join(destination, `replacement-${binaryName}`);
    writeSyntheticNative(binaryPath, target);
    const validatedBinary = readFileSync(binaryPath);
    const wrongTarget = expectedTargets.find(
      (candidate) => candidate !== target && candidate.startsWith(target.split("-")[0]),
    );
    writeSyntheticNative(replacementPath, wrongTarget);

    // A FIFO pauses metadata validation after the private binary snapshot. The independent
    // process then replaces the caller-owned path before allowing assembly to continue.
    const readmePath = path.join(fixtureRoot, "README.md");
    const readme = readFileSync(readmePath, "utf8");
    rmSync(readmePath);
    execFileSync("mkfifo", [readmePath]);
    const replacer = spawn(
      process.execPath,
      [
        "-e",
        `const { copyFileSync, writeFileSync } = require("node:fs");
setTimeout(() => {
  copyFileSync(process.argv[1], process.argv[2]);
  writeFileSync(process.argv[3], process.argv[4]);
}, 50);`,
        replacementPath,
        binaryPath,
        readmePath,
        readme,
      ],
      { stdio: "inherit" },
    );
    const replacerExit = once(replacer, "exit");
    context.after(() => {
      if (replacer.exitCode === null) replacer.kill("SIGKILL");
    });

    const release = createReleaseContext(fixtureRoot);
    const artifact = release.stageNative(target, binaryPath, destination);
    const [replacerExitCode] = await replacerExit;
    assert.equal(replacerExitCode, 0);
    assert.notDeepEqual(readFileSync(binaryPath), validatedBinary);
    assert.deepEqual(
      execFileSync("tar", [
        "-xOzf",
        path.join(destination, artifact.file),
        `package/bin/${binaryName}`,
      ]),
      validatedBinary,
    );
  },
);

test(
  "complete npm artifact validation writes canonical ownership metadata",
  { skip: process.platform === "win32" },
  (context) => {
    const destination = mkdtempSync(path.join(tmpdir(), "satelle-release-artifacts-"));
    context.after(() => rmSync(destination, { recursive: true, force: true }));

    const release = createReleaseContext(repositoryRoot);
    assert.throws(
      () => release.validateNpmArtifacts(destination),
      expectReleaseError("release-artifact-set-incomplete"),
    );
    stageCompleteArtifactSet(release, destination);
    const manifest = release.validateNpmArtifacts(destination, { writeManifest: true });

    assert.equal(manifest.schemaVersion, "satelle.npm-artifacts.v1");
    assert.equal(manifest.version, workspaceVersion());
    assert.equal(manifest.packages.length, 8);
    assert.deepEqual(
      manifest.packages.map(({ package: packageName }) => packageName),
      release.check().publicationOrder,
    );
    assert.equal(
      readFileSync(path.join(destination, "npm-artifacts.json"), "utf8"),
      `${JSON.stringify(manifest, null, 2)}\n`,
    );
    assert.deepEqual(release.validateNpmArtifacts(destination), manifest);

    const manifestPath = path.join(destination, "npm-artifacts.json");
    const victimPath = path.join(destination, "manifest-symlink-victim");
    writeFileSync(victimPath, "preserve me\n");
    rmSync(manifestPath);
    symlinkSync(victimPath, manifestPath);
    assert.deepEqual(
      release.validateNpmArtifacts(destination, { writeManifest: true }),
      manifest,
    );
    assert.equal(readFileSync(victimPath, "utf8"), "preserve me\n");

    rmSync(manifestPath);
    mkdirSync(manifestPath);
    writeFileSync(path.join(manifestPath, "sentinel"), "preserve me\n");
    assert.throws(
      () => release.validateNpmArtifacts(destination, { writeManifest: true }),
      expectReleaseError("release-integrity-write-failed"),
    );
    assert.equal(readFileSync(path.join(manifestPath, "sentinel"), "utf8"), "preserve me\n");
    assert.deepEqual(
      readdirSync(destination).filter((name) => name.startsWith(".npm-artifacts-")),
      [],
    );
    rmSync(manifestPath, { recursive: true });
    writeFileSync(manifestPath, `${JSON.stringify(manifest, null, 2)}\n`);

    const linuxX64Path = path.join(destination, "npm-linux-x64-gnu.tgz");
    const linuxX64Bytes = readFileSync(linuxX64Path);
    writeFileSync(
      linuxX64Path,
      readFileSync(path.join(destination, "npm-linux-arm64-gnu.tgz")),
    );
    assert.throws(
      () => release.validateNpmArtifacts(destination),
      expectReleaseError("release-artifact-metadata-mismatch"),
    );
    writeFileSync(linuxX64Path, linuxX64Bytes);

    for (const mode of [0o644, 0o700]) {
      rewriteNpmArchive(linuxX64Path, destination, (packageRoot) => {
        chmodSync(path.join(packageRoot, "bin", "satelle"), mode);
      });
      assert.throws(
        () => release.validateNpmArtifacts(destination),
        expectReleaseError("release-artifact-permission-mismatch"),
        mode.toString(8),
      );
      writeFileSync(linuxX64Path, linuxX64Bytes);
    }

    const scopedPath = path.join(destination, "npm-satelle-scoped.tgz");
    const scopedBytes = readFileSync(scopedPath);
    rewriteNpmArchive(scopedPath, destination, (packageRoot) => {
      const packedManifestPath = path.join(packageRoot, "package.json");
      const packedManifest = readJson(packedManifestPath);
      delete packedManifest.exports;
      writeJson(packedManifestPath, packedManifest);
    });
    assert.throws(
      () => release.validateNpmArtifacts(destination),
      expectReleaseError("release-artifact-metadata-mismatch"),
    );
    writeFileSync(scopedPath, scopedBytes);

    rewriteNpmArchive(scopedPath, destination, (packageRoot) => {
      writeFileSync(path.join(packageRoot, "payload.cjs"), "throw new Error('payload');\n");
    });
    assert.throws(
      () => release.validateNpmArtifacts(destination),
      expectReleaseError("release-artifact-invalid"),
    );
    writeFileSync(scopedPath, scopedBytes);

    rewriteNpmArchive(scopedPath, destination, (packageRoot) => {
      const packedManifestPath = path.join(packageRoot, "package.json");
      writeJson(packedManifestPath, { ...readJson(packedManifestPath), private: true });
    });
    assert.throws(
      () => release.validateNpmArtifacts(destination),
      expectReleaseError("release-artifact-metadata-mismatch"),
    );
    writeFileSync(scopedPath, scopedBytes);

    rewriteNpmArchive(scopedPath, destination, (packageRoot) => {
      writeFileSync(path.join(packageRoot, "bin", "satelle.cjs"), "x".repeat(1024 * 1024));
    });
    assert.throws(
      () => release.validateNpmArtifacts(destination),
      expectReleaseError("release-executable-mismatch"),
    );
    writeFileSync(scopedPath, scopedBytes);

    const tamperedBytes = Buffer.from(linuxX64Bytes);
    tamperedBytes[9] ^= 1;
    writeFileSync(linuxX64Path, tamperedBytes);
    assert.throws(
      () => release.validateNpmArtifacts(destination),
      expectReleaseError("release-integrity-mismatch"),
    );
  },
);

test("artifact validation rejects archives at the compressed size limit", (context) => {
  const destination = mkdtempSync(path.join(tmpdir(), "satelle-release-large-archive-"));
  context.after(() => rmSync(destination, { recursive: true, force: true }));
  const release = createReleaseContext(repositoryRoot);
  const artifactPath = path.join(destination, release.check().artifacts[0].npmArtifact);
  writeFileSync(artifactPath, "x");
  truncateSync(artifactPath, 512 * 1024 * 1024);

  assert.throws(
    () => release.validateNpmArtifacts(destination),
    expectReleaseError("release-artifact-invalid"),
  );
});

test("packed launcher validation ignores inherited global npm install mode", (context) => {
  const destination = mkdtempSync(path.join(tmpdir(), "satelle-release-global-npm-"));
  context.after(() => rmSync(destination, { recursive: true, force: true }));
  const inheritedGlobal = process.env.NPM_CONFIG_GLOBAL;
  process.env.NPM_CONFIG_GLOBAL = "true";
  context.after(() => {
    if (inheritedGlobal === undefined) delete process.env.NPM_CONFIG_GLOBAL;
    else process.env.NPM_CONFIG_GLOBAL = inheritedGlobal;
  });

  const release = createReleaseContext(repositoryRoot);
  release.stageNative(
    hostTarget(),
    compileVersionFixture(destination),
    destination,
  );
  release.stageLaunchers(destination);
  assert.doesNotThrow(() => release.validateLaunchers(destination));
});

test(
  "artifact validation rejects archives replaced during launcher smoke tests",
  { skip: process.platform === "win32" },
  (context) => {
    const fixtureRoot = fixtureRepository(context);
    const destination = mkdtempSync(path.join(tmpdir(), "satelle-release-artifact-race-"));
    context.after(() => rmSync(destination, { recursive: true, force: true }));
    const artifactPath = path.join(destination, "npm-linux-x64-gnu.tgz");
    const replacementPath = path.join(destination, "npm-linux-arm64-gnu.tgz");

    const release = createReleaseContext(fixtureRoot);
    const hostBinaryPath = compileArtifactReplacingFixture(
      destination,
      replacementPath,
      artifactPath,
    );
    stageCompleteArtifactSet(release, destination, hostBinaryPath);
    assert.throws(
      () => release.validateNpmArtifacts(destination),
      expectReleaseError("release-integrity-mismatch"),
    );
  },
);

test(
  "packed launcher validation terminates a hung executable",
  { skip: process.platform === "win32" },
  (context) => {
    const fixtureRoot = fixtureRepository(context);
    const destination = mkdtempSync(path.join(tmpdir(), "satelle-release-hung-launcher-"));
    context.after(() => rmSync(destination, { recursive: true, force: true }));
    writeFileSync(
      path.join(fixtureRoot, "npm", "satelle", "bin", "satelle.cjs"),
      "#!/usr/bin/env node\nwhile (true) {}\n",
    );

    const release = createReleaseContext(fixtureRoot);
    stageCompleteArtifactSet(release, destination);
    const startedAt = Date.now();
    assert.throws(
      () => release.validateNpmArtifacts(destination),
      expectReleaseError("release-executable-mismatch"),
    );
    assert.ok(Date.now() - startedAt < 10_000, "hung launcher exceeded its smoke-test bound");
  },
);

test("local release CLI exposes no public publishing or promotion command", () => {
  for (const command of ["publish-candidates", "promote", "validate-candidate"]) {
    const child = spawnSync(process.execPath, [releaseScriptPath, command], { encoding: "utf8" });
    assert.equal(child.status, 1, command);
    assert.deepEqual(JSON.parse(child.stderr), {
      code: "release-command-invalid",
      message: `unknown release command ${command}`,
    });
  }
});
