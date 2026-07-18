"use strict";

const assert = require("node:assert/strict");
const { execFileSync, spawn, spawnSync } = require("node:child_process");
const { createHash } = require("node:crypto");
const { once } = require("node:events");
const {
  appendFileSync,
  chmodSync,
  cpSync,
  existsSync,
  mkdtempSync,
  mkdirSync,
  readdirSync,
  readFileSync,
  renameSync,
  rmSync,
  statSync,
  symlinkSync,
  truncateSync,
  writeFileSync,
} = require("node:fs");
const { tmpdir } = require("node:os");
const path = require("node:path");
const test = require("node:test");
const { deflateRawSync, gzipSync } = require("node:zlib");

const repositoryRoot = path.resolve(__dirname, "../..");
const releaseScriptPath = path.join(repositoryRoot, "npm", "scripts", "release.cjs");
const {
  ReleaseError,
  createReleaseContext,
  zipInflateMaximumOutputLength,
} = require(releaseScriptPath);

const platformMatrix = readJson(
  path.join(repositoryRoot, "npm", "satelle", "platforms.json"),
);
const expectedTargets = Object.keys(platformMatrix).sort();

function hostTarget() {
  const architecture = process.arch === "arm64" ? "arm64" : "x64";
  if (process.platform === "win32") return `win32-${architecture}-msvc`;
  if (process.platform === "darwin") return `darwin-${architecture}`;
  return `linux-${architecture}-gnu`;
}

function readJson(filePath) {
  return JSON.parse(readFileSync(filePath, "utf8"));
}

function sha256(bytes) {
  return createHash("sha256").update(bytes).digest("hex");
}

function workspaceVersion() {
  const cargo = readFileSync(path.join(repositoryRoot, "Cargo.toml"), "utf8");
  const workspacePackage = cargo.match(/\[workspace\.package\]([\s\S]*?)(?:\n\[|$)/);
  const version = workspacePackage?.[1].match(/^version\s*=\s*"([^"]+)"/m)?.[1];
  assert.ok(version, "Cargo workspace version is missing");
  return version;
}

function writeSyntheticNative(filePath, target, size = 256) {
  const binary = Buffer.alloc(Math.max(size, target.startsWith("win32-") ? 1024 : 512));
  if (target.startsWith("linux-")) {
    const interpreter = target.includes("arm64")
      ? "/lib/ld-linux-aarch64.so.1\0"
      : "/lib64/ld-linux-x86-64.so.2\0";
    Buffer.from([0x7f, 0x45, 0x4c, 0x46, 2, 1, 1]).copy(binary);
    binary.writeUInt16LE(3, 16);
    binary.writeUInt16LE(target.includes("arm64") ? 183 : 62, 18);
    binary.writeUInt32LE(1, 20);
    binary.writeBigUInt64LE(0x1000n, 24);
    binary.writeBigUInt64LE(64n, 32);
    binary.writeUInt16LE(64, 52);
    binary.writeUInt16LE(56, 54);
    binary.writeUInt16LE(2, 56);

    binary.writeUInt32LE(1, 64);
    binary.writeUInt32LE(5, 68);
    binary.writeBigUInt64LE(0n, 72);
    binary.writeBigUInt64LE(0x1000n, 80);
    binary.writeBigUInt64LE(BigInt(binary.length), 96);
    binary.writeBigUInt64LE(BigInt(binary.length), 104);
    binary.writeBigUInt64LE(0x1000n, 112);

    binary.writeUInt32LE(3, 120);
    binary.writeBigUInt64LE(256n, 128);
    binary.writeBigUInt64LE(BigInt(interpreter.length), 152);
    binary.writeBigUInt64LE(BigInt(interpreter.length), 160);
    binary.write(interpreter, 256, "ascii");
  } else if (target.startsWith("darwin-")) {
    binary.writeUInt32LE(0xfeedfacf, 0);
    binary.writeUInt32LE(target.includes("arm64") ? 0x0100000c : 0x01000007, 4);
    binary.writeUInt32LE(2, 12);
    binary.writeUInt32LE(2, 16);
    binary.writeUInt32LE(96, 20);
    binary.writeUInt32LE(0x19, 32);
    binary.writeUInt32LE(72, 36);
    binary.write("__TEXT", 40, "ascii");
    binary.writeBigUInt64LE(0x100000000n, 56);
    binary.writeBigUInt64LE(BigInt(binary.length), 64);
    binary.writeBigUInt64LE(0n, 72);
    binary.writeBigUInt64LE(BigInt(binary.length), 80);
    binary.writeUInt32LE(5, 88);
    binary.writeUInt32LE(5, 92);
    binary.writeUInt32LE(0x80000028, 104);
    binary.writeUInt32LE(24, 108);
    binary.writeBigUInt64LE(256n, 112);
  } else {
    binary.write("MZ", 0, "ascii");
    binary.writeUInt32LE(128, 0x3c);
    binary.write("PE\0\0", 128, "ascii");
    binary.writeUInt16LE(target.includes("arm64") ? 0xaa64 : 0x8664, 132);
    binary.writeUInt16LE(1, 134);
    binary.writeUInt16LE(240, 148);
    binary.writeUInt16LE(0x0022, 150);
    binary.writeUInt16LE(0x20b, 152);
    binary.writeUInt32LE(0x1000, 168);
    binary.writeBigUInt64LE(0x140000000n, 176);
    binary.writeUInt32LE(0x1000, 184);
    binary.writeUInt32LE(0x200, 188);
    binary.writeUInt32LE(0x2000, 208);
    binary.writeUInt32LE(0x200, 212);
    binary.writeUInt32LE(16, 260);
    binary.write(".text", 392, "ascii");
    binary.writeUInt32LE(1, 400);
    binary.writeUInt32LE(0x1000, 404);
    binary.writeUInt32LE(0x200, 408);
    binary.writeUInt32LE(0x200, 412);
    binary.writeUInt32LE(0x60000020, 428);
    binary[512] = 0xc3;
  }
  writeFileSync(filePath, binary);
  if (process.platform !== "win32") chmodSync(filePath, 0o755);
}

function addSecondSyntheticPeSection(binary, virtualAddress, rawOffset) {
  const secondSection = Buffer.from(binary.subarray(392, 432));
  secondSection.copy(binary, 432);
  binary.writeUInt16LE(2, 134);
  binary.writeUInt32LE(virtualAddress, 444);
  binary.writeUInt32LE(rawOffset, 452);
}

function writeTarField(header, offset, length, value) {
  header.write(value, offset, length, "ascii");
}

function tarEntry({
  name,
  contents = Buffer.alloc(0),
  declaredSize,
  mode = 0o755,
  type = "0",
  link = "",
}) {
  const body = Buffer.from(contents);
  const header = Buffer.alloc(512);
  writeTarField(header, 0, 100, name);
  writeTarField(header, 100, 8, `${mode.toString(8).padStart(7, "0")}\0`);
  writeTarField(header, 108, 8, "0000000\0");
  writeTarField(header, 116, 8, "0000000\0");
  writeTarField(
    header,
    124,
    12,
    `${(declaredSize ?? (type === "0" ? body.length : 0)).toString(8).padStart(11, "0")}\0`,
  );
  writeTarField(header, 136, 12, "00000000000\0");
  header.fill(0x20, 148, 156);
  writeTarField(header, 156, 1, type);
  writeTarField(header, 157, 100, link);
  writeTarField(header, 257, 6, "ustar\0");
  writeTarField(header, 263, 2, "00");
  const checksum = [...header].reduce((total, byte) => total + byte, 0);
  writeTarField(header, 148, 8, `${checksum.toString(8).padStart(6, "0")}\0 `);
  const padding = Buffer.alloc((512 - (body.length % 512)) % 512);
  return Buffer.concat([header, body, padding]);
}

function writeTarGzArchive(archivePath, entries) {
  writeFileSync(
    archivePath,
    gzipSync(Buffer.concat([...entries.map(tarEntry), Buffer.alloc(1024)])),
  );
}

let testCrc32Table;
function testCrc32(bytes) {
  if (!testCrc32Table) {
    testCrc32Table = Array.from({ length: 256 }, (_, value) => {
      let entry = value;
      for (let bit = 0; bit < 8; bit += 1) {
        entry = (entry & 1) !== 0 ? (entry >>> 1) ^ 0xedb88320 : entry >>> 1;
      }
      return entry >>> 0;
    });
  }
  let digest = 0xffffffff;
  for (const byte of bytes) digest = (digest >>> 8) ^ testCrc32Table[(digest ^ byte) & 0xff];
  return (digest ^ 0xffffffff) >>> 0;
}

function zipExtraField(identifier, contents) {
  const body = Buffer.from(contents);
  const field = Buffer.alloc(4 + body.length);
  field.writeUInt16LE(identifier, 0);
  field.writeUInt16LE(body.length, 2);
  body.copy(field, 4);
  return field;
}

function writeZipArchive(archivePath, entries) {
  const localParts = [];
  const centralParts = [];
  let localOffset = 0;
  for (const entry of entries) {
    const name = Buffer.from(entry.name);
    const contents = Buffer.from(entry.contents ?? Buffer.alloc(0));
    const method = entry.method ?? 8;
    const compressed = method === 0 ? contents : deflateRawSync(contents);
    const checksum = entry.checksum ?? testCrc32(contents);
    const declaredSize = entry.declaredSize ?? contents.length;
    const localExtra = Buffer.from(entry.localExtra ?? entry.extra ?? Buffer.alloc(0));
    const centralExtra = Buffer.from(entry.centralExtra ?? entry.extra ?? Buffer.alloc(0));
    const typeMode = entry.type === "directory"
      ? 0o040000
      : entry.type === "symlink"
        ? 0o120000
        : entry.type === "fifo"
          ? 0o010000
          : 0o100000;
    const mode = typeMode | (entry.mode ?? (entry.type === "directory" ? 0o755 : 0o644));
    const flags = 0x0800;
    const local = Buffer.alloc(30);
    local.writeUInt32LE(0x04034b50, 0);
    local.writeUInt16LE(20, 4);
    local.writeUInt16LE(flags, 6);
    local.writeUInt16LE(method, 8);
    local.writeUInt32LE(checksum, 14);
    local.writeUInt32LE(compressed.length, 18);
    local.writeUInt32LE(declaredSize, 22);
    local.writeUInt16LE(name.length, 26);
    local.writeUInt16LE(localExtra.length, 28);
    localParts.push(local, name, localExtra, compressed);

    const central = Buffer.alloc(46);
    central.writeUInt32LE(0x02014b50, 0);
    central.writeUInt16LE((3 << 8) | 20, 4);
    central.writeUInt16LE(20, 6);
    central.writeUInt16LE(flags, 8);
    central.writeUInt16LE(method, 10);
    central.writeUInt32LE(checksum, 16);
    central.writeUInt32LE(compressed.length, 20);
    central.writeUInt32LE(declaredSize, 24);
    central.writeUInt16LE(name.length, 28);
    central.writeUInt16LE(centralExtra.length, 30);
    central.writeUInt32LE((mode << 16) >>> 0, 38);
    central.writeUInt32LE(localOffset, 42);
    centralParts.push(central, name, centralExtra);
    localOffset += local.length + name.length + localExtra.length + compressed.length;
  }
  const centralDirectory = Buffer.concat(centralParts);
  const end = Buffer.alloc(22);
  end.writeUInt32LE(0x06054b50, 0);
  end.writeUInt16LE(entries.length, 8);
  end.writeUInt16LE(entries.length, 10);
  end.writeUInt32LE(centralDirectory.length, 12);
  end.writeUInt32LE(localOffset, 16);
  writeFileSync(archivePath, Buffer.concat([...localParts, centralDirectory, end]));
}

function writeNativeReleaseArchive(archivePath, target, binary) {
  const executableName = platformMatrix[target].os === "win32" ? "satelle.exe" : "satelle";
  rmSync(archivePath, { force: true });
  if (platformMatrix[target].os !== "win32") {
    writeTarGzArchive(archivePath, [{ name: executableName, contents: binary }]);
    return;
  }
  writeZipArchive(archivePath, [
    { name: executableName, contents: binary, mode: 0o755 },
  ]);
}

function stageNativeReleaseSet(release, destination) {
  const plan = release.check();
  const binaries = new Map();
  for (const artifact of plan.artifacts) {
    const binaryPath = path.join(destination, `fixture-${artifact.target}`);
    writeSyntheticNative(binaryPath, artifact.target);
    const binary = readFileSync(binaryPath);
    const metadata = platformMatrix[artifact.target];
    const packageManifest = readFileSync(
      path.join(repositoryRoot, "npm", `satelle-${artifact.target}`, "package.json"),
    );
    writeTarGzArchive(path.join(destination, artifact.npmArtifact), [
      { name: "package/package.json", contents: packageManifest, mode: 0o644 },
      {
        name: `package/${metadata.binaryPath}`,
        contents: binary,
        mode: metadata.os === "win32" ? 0o644 : 0o755,
      },
    ]);
    writeNativeReleaseArchive(path.join(destination, artifact.archive), artifact.target, binary);
    binaries.set(artifact.target, binary);
  }
  return { binaries, plan };
}

function validationStaging(context, label = "case") {
  const root = mkdtempSync(path.join(tmpdir(), `satelle-native-validation-${label}-`));
  context.after(() => {
    if (!existsSync(root)) return;
    const makeOwnerWritable = (directory) => {
      chmodSync(directory, 0o700);
      for (const entry of readdirSync(directory, { withFileTypes: true })) {
        const entryPath = path.join(directory, entry.name);
        if (entry.isDirectory() && !entry.isSymbolicLink()) makeOwnerWritable(entryPath);
        else if (!entry.isSymbolicLink()) chmodSync(entryPath, 0o600);
      }
    };
    makeOwnerWritable(root);
    rmSync(root, { recursive: true, force: true });
  });
  return path.join(root, "validated");
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

function expectReleaseError(code, messageIncludes) {
  return (error) =>
    error instanceof ReleaseError &&
    error.code === code &&
    (messageIncludes === undefined || error.message.includes(messageIncludes));
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

test("packed launcher installation obeys the npm command deadline", { timeout: 10_000 }, (context) => {
  const destination = mkdtempSync(path.join(tmpdir(), "satelle-release-hung-install-"));
  context.after(() => rmSync(destination, { recursive: true, force: true }));
  const release = createReleaseContext(repositoryRoot, { npmCommandTimeoutMilliseconds: 2_000 });
  release.stageNative(
    hostTarget(),
    compileVersionFixture(destination),
    destination,
  );
  release.stageLaunchers(destination);
  const hangingNpmPath = path.join(destination, "hanging-install-npm.cjs");
  writeFileSync(hangingNpmPath, "while (true) {}\n");
  const inheritedNpmExecPath = process.env.npm_execpath;
  process.env.npm_execpath = hangingNpmPath;
  context.after(() => {
    if (inheritedNpmExecPath === undefined) delete process.env.npm_execpath;
    else process.env.npm_execpath = inheritedNpmExecPath;
  });

  const startedAt = Date.now();
  assert.throws(
    () => release.validateLaunchers(destination),
    expectReleaseError("release-command-timeout"),
  );
  assert.ok(Date.now() - startedAt < 7_000, "launcher install exceeded its npm command bound");
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

    let executionStartedAt;
    const release = createReleaseContext(fixtureRoot, {
      afterLauncherInstall() {
        executionStartedAt = Date.now();
      },
    });
    stageCompleteArtifactSet(release, destination);
    assert.throws(
      () => release.validateNpmArtifacts(destination),
      expectReleaseError("release-executable-mismatch"),
    );
    assert.ok(executionStartedAt !== undefined, "launcher execution boundary was not reached");
  },
);

test("native release archives use canonical names and match native npm executables", (context) => {
  const destination = mkdtempSync(path.join(tmpdir(), "satelle-native-release-archives-"));
  context.after(() => rmSync(destination, { recursive: true, force: true }));
  const release = createReleaseContext(repositoryRoot);
  const { plan } = stageNativeReleaseSet(release, destination);

  const validation = release.validateNativeReleaseArchives(
    destination,
    validationStaging(context, "canonical"),
  );
  assert.equal(validation.version, workspaceVersion());
  assert.deepEqual(
    validation.archives.map(({ target, archive, npmArtifact }) => ({
      target,
      archive,
      npmArtifact,
    })),
    plan.artifacts.map(({ target, archive, npmArtifact }) => ({
      target,
      archive,
      npmArtifact,
    })),
  );
  assert.equal(
    validation.archives.every(({ executableSha256 }) =>
      /^[0-9a-f]{64}$/.test(executableSha256)),
    true,
  );
  assert.equal(validation.stagingDirectory.includes("satelle-native-validation-canonical-"), true);
  for (const archive of validation.archives) {
    assert.equal(archive.archivePath, path.join(validation.stagingDirectory, "github", archive.archive));
    assert.equal(
      archive.npmArtifactPath,
      path.join(validation.stagingDirectory, "npm", archive.npmArtifact),
    );
    assert.equal(sha256(readFileSync(archive.archivePath)), archive.archiveSha256);
    assert.equal(sha256(readFileSync(archive.npmArtifactPath)), archive.npmArtifactSha256);
  }

  const [first] = plan.artifacts;
  const canonicalPath = path.join(destination, first.archive);
  for (const extraName of [
    `satelle-v${workspaceVersion()}-${first.target}.zip`,
    `satelle-v${workspaceVersion()}-unknown-target.tar.gz`,
    `satelle-v${workspaceVersion()}-${first.target}.tgz`,
    `satelle-v${workspaceVersion()}-${first.target}.tar.xz`,
  ]) {
    const extraPath = path.join(destination, extraName);
    cpSync(canonicalPath, extraPath);
    assert.throws(
      () => release.validateNativeReleaseArchives(
        destination,
        validationStaging(context, `extra-${path.extname(extraName).slice(1)}`),
      ),
      expectReleaseError("release-archive-set-incomplete"),
      extraName,
    );
    rmSync(extraPath);
  }
  const noncanonicalPath = path.join(destination, `satelle-${first.target}.archive`);
  cpSync(canonicalPath, noncanonicalPath);
  rmSync(canonicalPath);
  assert.throws(
    () => release.validateNativeReleaseArchives(
      destination,
      validationStaging(context, "noncanonical"),
    ),
    expectReleaseError("release-archive-set-incomplete"),
  );
});

test("native release archive validation rejects unsafe or malformed layouts", (context) => {
  const destination = mkdtempSync(path.join(tmpdir(), "satelle-native-release-layout-"));
  context.after(() => rmSync(destination, { recursive: true, force: true }));
  const release = createReleaseContext(repositoryRoot);
  const { binaries, plan } = stageNativeReleaseSet(release, destination);
  const artifact = plan.artifacts.find(({ target }) => target === "linux-x64-gnu");
  const archivePath = path.join(destination, artifact.archive);
  const originalArchive = readFileSync(archivePath);
  const binary = binaries.get(artifact.target);
  const sentinelPath = path.join(destination, "sentinel");
  writeFileSync(sentinelPath, "unchanged");

  const cases = [
    {
      name: "corrupt archive",
      mutate: () => writeFileSync(archivePath, "not an archive"),
    },
    {
      name: "path traversal member",
      mutate: () => writeTarGzArchive(archivePath, [
        { name: "satelle", contents: binary },
        { name: "../escape", contents: "escape", mode: 0o644 },
      ]),
    },
    {
      name: "leading dash member",
      mutate: () => writeTarGzArchive(archivePath, [
        { name: "satelle", contents: binary },
        { name: "--checkpoint-action=exec=touch sentinel", contents: "unsafe" },
      ]),
    },
    {
      name: "root executable symlink",
      mutate: () => writeTarGzArchive(archivePath, [
        { name: "satelle", type: "2", link: "elsewhere" },
      ]),
    },
    {
      name: "nested symlink",
      mutate: () => writeTarGzArchive(archivePath, [
        { name: "satelle", contents: binary },
        { name: "nested/link", type: "2", link: "../../escape" },
      ]),
    },
    {
      name: "hardlink",
      mutate: () => writeTarGzArchive(archivePath, [
        { name: "satelle", contents: binary },
        { name: "nested/hard", type: "1", link: "satelle" },
      ]),
    },
    {
      name: "FIFO",
      mutate: () => writeTarGzArchive(archivePath, [
        { name: "satelle", contents: binary },
        { name: "nested/pipe", type: "6" },
      ]),
    },
    {
      name: "device",
      mutate: () => writeTarGzArchive(archivePath, [
        { name: "satelle", contents: binary },
        { name: "nested/device", type: "3" },
      ]),
    },
    {
      name: "duplicate root executable",
      mutate: () => writeTarGzArchive(archivePath, [
        { name: "satelle", contents: binary },
        { name: "satelle", contents: binary },
      ]),
    },
    {
      name: "second root executable",
      mutate: () => writeTarGzArchive(archivePath, [
        { name: "satelle", contents: binary },
        { name: "helper", contents: binary },
      ]),
    },
    {
      name: "world-writable root executable",
      mutate: () => writeTarGzArchive(archivePath, [
        { name: "satelle", contents: binary, mode: 0o777 },
      ]),
    },
    {
      name: "setuid root executable",
      mutate: () => writeTarGzArchive(archivePath, [
        { name: "satelle", contents: binary, mode: 0o4755 },
      ]),
    },
    {
      name: "nested executable",
      mutate: () => writeTarGzArchive(archivePath, [
        { name: "nested/satelle", contents: binary },
      ]),
    },
    {
      name: "regular file with a trailing separator",
      mutate: () => writeTarGzArchive(archivePath, [
        { name: "satelle/", contents: binary },
      ]),
    },
    {
      name: "regular file with a backslash alias",
      mutate: () => writeTarGzArchive(archivePath, [
        { name: "satelle\\", contents: binary },
      ]),
    },
    {
      name: "declared body beyond archive",
      mutate: () => writeTarGzArchive(archivePath, [
        { name: "satelle", contents: binary, declaredSize: binary.length + 1024 },
      ]),
    },
  ];

  for (const { name, mutate } of cases) {
    mutate();
    assert.throws(
      () => release.validateNativeReleaseArchives(
        destination,
        validationStaging(context, `layout-${name.replaceAll(" ", "-")}`),
      ),
      expectReleaseError("release-archive-invalid"),
      name,
    );
    assert.equal(readFileSync(sentinelPath, "utf8"), "unchanged", name);
    writeFileSync(archivePath, originalArchive);
  }
});

test("native release archive validation rejects adversarial ZIP inventories", (context) => {
  const destination = mkdtempSync(path.join(tmpdir(), "satelle-native-release-zip-layout-"));
  context.after(() => rmSync(destination, { recursive: true, force: true }));
  const release = createReleaseContext(repositoryRoot);
  const { binaries, plan } = stageNativeReleaseSet(release, destination);
  const artifact = plan.artifacts.find(({ target }) => target === "win32-x64-msvc");
  const archivePath = path.join(destination, artifact.archive);
  const originalArchive = readFileSync(archivePath);
  const binary = binaries.get(artifact.target);
  const validExecutable = { name: "satelle.exe", contents: binary, mode: 0o755 };
  const unicodePathBody = Buffer.alloc(5 + Buffer.byteLength("nested/satelle.exe"));
  unicodePathBody[0] = 1;
  unicodePathBody.writeUInt32LE(testCrc32(Buffer.from(validExecutable.name)), 1);
  unicodePathBody.write("nested/satelle.exe", 5, "utf8");
  const asiUnixBody = Buffer.alloc(10 + Buffer.byteLength("nested/target"));
  asiUnixBody.writeUInt16LE(0o120777, 0);
  asiUnixBody.writeUInt32LE(Buffer.byteLength("nested/target"), 2);
  asiUnixBody.write("nested/target", 10, "utf8");
  const asiUnixExtraBody = Buffer.alloc(4 + asiUnixBody.length);
  asiUnixExtraBody.writeUInt32LE(testCrc32(asiUnixBody), 0);
  asiUnixBody.copy(asiUnixExtraBody, 4);
  const localTimestamp = Buffer.alloc(5, 0);
  localTimestamp[0] = 1;
  localTimestamp.writeUInt32LE(1, 1);
  const extendedLocalTimestamp = Buffer.alloc(13, 0);
  extendedLocalTimestamp[0] = 7;
  extendedLocalTimestamp.writeUInt32LE(1, 1);
  extendedLocalTimestamp.writeUInt32LE(2, 5);
  extendedLocalTimestamp.writeUInt32LE(3, 9);
  const centralTimestamp = Buffer.from(localTimestamp);
  centralTimestamp.writeUInt32LE(2, 1);
  const reservedLocalTimestamp = Buffer.from(localTimestamp);
  reservedLocalTimestamp[0] = 9;
  const centralAccessTimeOnly = Buffer.from([2]);
  const truncatedTimestampHeader = Buffer.from([0x55, 0x54, 0x05]);
  const truncatedTimestampBody = zipExtraField(0x5455, localTimestamp).subarray(0, -1);
  const timestampExtraCases = [
    {
      name: "empty local timestamp body",
      localExtra: zipExtraField(0x5455, Buffer.alloc(0)),
      centralExtra: Buffer.alloc(0),
      message: "malformed ZIP timestamp field",
    },
    {
      name: "zero local timestamp flags",
      localExtra: zipExtraField(0x5455, Buffer.from([0])),
      centralExtra: Buffer.alloc(0),
      message: "malformed ZIP timestamp field",
    },
    {
      name: "reserved local timestamp flag",
      localExtra: zipExtraField(0x5455, reservedLocalTimestamp),
      centralExtra: zipExtraField(0x5455, localTimestamp),
      message: "malformed ZIP timestamp field",
    },
    {
      name: "central timestamp without modification time",
      localExtra: zipExtraField(0x5455, localTimestamp),
      centralExtra: zipExtraField(0x5455, centralAccessTimeOnly),
      message: "malformed ZIP timestamp field",
    },
    {
      name: "overlong local timestamp body",
      localExtra: zipExtraField(0x5455, Buffer.concat([localTimestamp, Buffer.from([0])])),
      centralExtra: zipExtraField(0x5455, localTimestamp),
      message: "malformed ZIP timestamp field",
    },
    {
      name: "truncated local timestamp body",
      localExtra: zipExtraField(0x5455, extendedLocalTimestamp.subarray(0, 5)),
      centralExtra: zipExtraField(0x5455, localTimestamp),
      message: "malformed ZIP timestamp field",
    },
    {
      name: "overlong central timestamp body",
      localExtra: zipExtraField(0x5455, localTimestamp),
      centralExtra: zipExtraField(0x5455, Buffer.concat([localTimestamp, Buffer.from([0])])),
      message: "malformed ZIP timestamp field",
    },
    {
      name: "truncated central timestamp body",
      localExtra: zipExtraField(0x5455, localTimestamp),
      centralExtra: zipExtraField(0x5455, localTimestamp.subarray(0, -1)),
      message: "malformed ZIP timestamp field",
    },
    {
      name: "truncated local extra header",
      localExtra: truncatedTimestampHeader,
      centralExtra: Buffer.alloc(0),
      message: "out-of-bounds range",
    },
    {
      name: "truncated local extra body",
      localExtra: truncatedTimestampBody,
      centralExtra: Buffer.alloc(0),
      message: "out-of-bounds range",
    },
    {
      name: "duplicate local timestamp",
      localExtra: Buffer.concat([
        zipExtraField(0x5455, localTimestamp),
        zipExtraField(0x5455, localTimestamp),
      ]),
      centralExtra: zipExtraField(0x5455, localTimestamp),
      message: "repeats ZIP extra field 0x5455",
    },
    {
      name: "duplicate central timestamp",
      localExtra: zipExtraField(0x5455, localTimestamp),
      centralExtra: Buffer.concat([
        zipExtraField(0x5455, localTimestamp),
        zipExtraField(0x5455, localTimestamp),
      ]),
      message: "repeats ZIP extra field 0x5455",
    },
    {
      name: "local timestamp only",
      localExtra: zipExtraField(0x5455, localTimestamp),
      centralExtra: Buffer.alloc(0),
      message: "local and central ZIP metadata differ",
    },
    {
      name: "central timestamp only",
      localExtra: Buffer.alloc(0),
      centralExtra: zipExtraField(0x5455, localTimestamp),
      message: "local and central ZIP metadata differ",
    },
  ];
  const cases = [
    ["path traversal", [validExecutable, { name: "../escape", contents: "unsafe" }]],
    ["leading dash", [validExecutable, { name: "--unsafe", contents: "unsafe" }]],
    ["symlink", [validExecutable, { name: "nested/link", contents: "../../escape", type: "symlink" }]],
    ["FIFO", [validExecutable, { name: "nested/pipe", type: "fifo" }]],
    ["duplicate", [validExecutable, validExecutable]],
    ["trailing separator alias", [{ ...validExecutable, name: "satelle.exe/" }]],
    ["backslash alias", [{ ...validExecutable, name: "satelle.exe\\" }]],
    ["CMD executable alias", [validExecutable, { name: "helper.cmd", contents: "exit /b 0" }]],
    ["BAT executable alias", [validExecutable, { name: "helper.bat", contents: "exit /b 0" }]],
    ["COM executable alias", [validExecutable, { name: "helper.com", contents: "MZ" }]],
    ["trailing dot alias", [validExecutable, { ...validExecutable, name: "satelle.exe." }]],
    ["trailing space alias", [validExecutable, { ...validExecutable, name: "satelle.exe " }]],
    ["Unicode path alias", [{
      ...validExecutable,
      extra: zipExtraField(0x7075, unicodePathBody),
    }]],
    ["ASi Unix symlink", [{
      ...validExecutable,
      extra: zipExtraField(0x756e, asiUnixExtraBody),
    }]],
    ["mismatched local and central extras", [{
      ...validExecutable,
      localExtra: zipExtraField(0x5455, localTimestamp),
      centralExtra: zipExtraField(0x5455, centralTimestamp),
    }]],
    ...timestampExtraCases.map(({ name, localExtra, centralExtra, message }) => [
      name,
      [{ ...validExecutable, localExtra, centralExtra }],
      message,
    ]),
    ["corrupt checksum", [validExecutable, { name: "note", contents: "note", checksum: 1 }]],
    ["false expanded size", [{ ...validExecutable, declaredSize: binary.length - 1 }]],
  ];

  writeZipArchive(archivePath, [{
    ...validExecutable,
    localExtra: zipExtraField(0x5455, extendedLocalTimestamp),
    centralExtra: zipExtraField(0x5455, localTimestamp),
  }]);
  assert.doesNotThrow(() => release.validateNativeReleaseArchives(
    destination,
    validationStaging(context, "zip-matching-timestamp-extras"),
  ));
  writeFileSync(archivePath, originalArchive);

  for (const [name, entries, message] of cases) {
    writeZipArchive(archivePath, entries);
    assert.throws(
      () => release.validateNativeReleaseArchives(
        destination,
        validationStaging(context, `zip-${name.replaceAll(" ", "-")}`),
      ),
      expectReleaseError("release-archive-invalid", message),
      name,
    );
    writeFileSync(archivePath, originalArchive);
  }
});

test("native release archive limits bound inventory and decompression work", (context) => {
  const destination = mkdtempSync(path.join(tmpdir(), "satelle-native-release-limits-"));
  context.after(() => rmSync(destination, { recursive: true, force: true }));
  const stagingRelease = createReleaseContext(repositoryRoot);
  const { binaries, plan } = stageNativeReleaseSet(stagingRelease, destination);
  const artifact = plan.artifacts.find(({ target }) => target === "linux-x64-gnu");
  const archivePath = path.join(destination, artifact.archive);
  const originalArchive = readFileSync(archivePath);
  const binary = binaries.get(artifact.target);
  const cases = [
    {
      name: "member count",
      limits: { maximumMembers: 2 },
      entries: [
        { name: "satelle", contents: binary },
        { name: "one", contents: "1", mode: 0o644 },
        { name: "two", contents: "2", mode: 0o644 },
      ],
    },
    {
      name: "per-member bytes",
      limits: { maximumMemberBytes: binary.length },
      entries: [
        { name: "satelle", contents: binary },
        { name: "oversize", contents: Buffer.alloc(binary.length + 1), mode: 0o644 },
      ],
    },
    {
      name: "total expanded bytes",
      limits: { maximumExpandedBytes: binary.length + 8 },
      entries: [
        { name: "satelle", contents: binary },
        { name: "expansion", contents: Buffer.alloc(9), mode: 0o644 },
      ],
    },
  ];
  for (const { name, limits, entries } of cases) {
    writeTarGzArchive(archivePath, entries);
    const release = createReleaseContext(repositoryRoot, {
      nativeArchiveLimits: limits,
    });
    assert.throws(
      () => release.validateNativeReleaseArchives(
        destination,
        validationStaging(context, `limit-${name.replaceAll(" ", "-")}`),
      ),
      expectReleaseError("release-archive-limit-exceeded"),
      name,
    );
    writeFileSync(archivePath, originalArchive);
  }

  const windowsArtifact = plan.artifacts.find(({ target }) => target === "win32-x64-msvc");
  const windowsArchivePath = path.join(destination, windowsArtifact.archive);
  const originalWindowsArchive = readFileSync(windowsArchivePath);
  writeZipArchive(windowsArchivePath, [
    { name: "satelle.exe", contents: binaries.get(windowsArtifact.target), mode: 0o755 },
    { name: "expansion", contents: Buffer.alloc(2048), declaredSize: 1 },
  ]);
  assert.equal(
    zipInflateMaximumOutputLength(1, {
      maximumMemberBytes: 1024,
      maximumExpandedBytes: 2048,
    }),
    2,
    "the inflater must stop after the declared member size plus one byte",
  );
  const zipExpansionRelease = createReleaseContext(repositoryRoot);
  assert.throws(
    () => zipExpansionRelease.validateNativeReleaseArchives(
      destination,
      validationStaging(context, "zip-expansion"),
    ),
    expectReleaseError("release-archive-invalid"),
  );
  writeFileSync(windowsArchivePath, originalWindowsArchive);

  const timedRelease = createReleaseContext(repositoryRoot, {
    nativeArchiveValidationTimeoutMilliseconds: 1,
  });
  assert.throws(
    () => timedRelease.validateNativeReleaseArchives(
      destination,
      validationStaging(context, "deadline"),
    ),
    expectReleaseError("release-archive-timeout"),
  );

  const postInventoryTimedRelease = createReleaseContext(repositoryRoot, {
    nativeArchiveValidationTimeoutMilliseconds: 20,
    nativeArchivePostInventoryDelayMilliseconds: 100,
  });
  const startedAt = Date.now();
  assert.throws(
    () => postInventoryTimedRelease.validateNativeReleaseArchives(
      destination,
      validationStaging(context, "post-inventory-deadline"),
    ),
    expectReleaseError("release-archive-timeout"),
  );
  assert.ok(Date.now() - startedAt < 1_000, "post-inventory validation ignored its deadline");
});

test("PE32+ validation accepts supported relational layouts", (context) => {
  const destination = mkdtempSync(path.join(tmpdir(), "satelle-pe-relational-layout-"));
  context.after(() => rmSync(destination, { recursive: true, force: true }));
  const binaryPath = path.join(destination, "valid-two-section.exe");
  writeSyntheticNative(binaryPath, "win32-x64-msvc", 1536);
  const binary = readFileSync(binaryPath);
  const lowAlignmentBinary = Buffer.from(binary);
  lowAlignmentBinary.writeUInt32LE(0x200, 168);
  lowAlignmentBinary.writeUInt32LE(0x200, 184);
  lowAlignmentBinary.writeUInt32LE(0x200, 404);
  addSecondSyntheticPeSection(binary, 0x2000, 0x400);
  binary.writeUInt32LE(0x3000, 208);

  const release = createReleaseContext(repositoryRoot);
  assert.doesNotThrow(() => release.validateNativeBinary(
    "win32-x64-msvc",
    lowAlignmentBinary,
    "valid low-alignment PE32+ fixture",
  ));
  assert.doesNotThrow(() => release.validateNativeBinary(
    "win32-x64-msvc",
    binary,
    "valid two-section PE32+ fixture",
  ));
});

test("native release archive target identity comes from binary structure", (context) => {
  const destination = mkdtempSync(path.join(tmpdir(), "satelle-native-release-targets-"));
  context.after(() => rmSync(destination, { recursive: true, force: true }));
  const release = createReleaseContext(repositoryRoot);
  const { plan } = stageNativeReleaseSet(release, destination);
  const cases = [
    { target: "linux-x64-gnu", binaryTarget: "linux-arm64-gnu" },
    { target: "darwin-x64", binaryTarget: "darwin-arm64" },
    { target: "win32-x64-msvc", binaryTarget: "win32-arm64-msvc" },
  ];

  for (const { target, binaryTarget } of cases) {
    const artifact = plan.artifacts.find((candidate) => candidate.target === target);
    const archivePath = path.join(destination, artifact.archive);
    const originalArchive = readFileSync(archivePath);
    const binaryPath = path.join(destination, `wrong-${binaryTarget}`);
    writeSyntheticNative(binaryPath, binaryTarget);
    writeNativeReleaseArchive(archivePath, target, readFileSync(binaryPath));
    assert.throws(
      () => release.validateNativeReleaseArchives(
        destination,
        validationStaging(context, `target-${target}`),
      ),
      expectReleaseError("release-binary-target-mismatch"),
      `${target} accepted ${binaryTarget}`,
    );
    writeFileSync(archivePath, originalArchive);
  }

  const malformedCases = [
    {
      name: "ELF object with spoofed glibc string",
      target: "linux-x64-gnu",
      mutate(binary) {
        binary.writeUInt16LE(1, 16);
        binary.write("/lib64/ld-linux-x86-64.so.2", 320, "ascii");
      },
    },
    {
      name: "ELF out-of-bounds program table",
      target: "linux-x64-gnu",
      mutate(binary) {
        binary.writeBigUInt64LE(BigInt(binary.length + 1), 32);
      },
    },
    {
      name: "ELF oversized program header entries",
      target: "linux-x64-gnu",
      mutate(binary) {
        const interpreterHeader = Buffer.from(binary.subarray(120, 176));
        binary.fill(0, 120, 184);
        interpreterHeader.copy(binary, 128);
        binary.writeUInt16LE(64, 54);
      },
    },
    {
      name: "ELF oversized executable header",
      target: "linux-x64-gnu",
      mutate(binary) {
        binary.writeUInt16LE(65, 52);
      },
    },
    {
      name: "ELF program table overlaps executable header",
      target: "linux-x64-gnu",
      mutate(binary) {
        const programHeaders = Buffer.from(binary.subarray(64, 176));
        programHeaders.copy(binary, 60);
        binary.writeBigUInt64LE(60n, 32);
      },
    },
    {
      name: "ELF entry outside executable loads",
      target: "linux-x64-gnu",
      mutate(binary) {
        binary.writeBigUInt64LE(BigInt(0x1000 + binary.length + 1), 24);
      },
    },
    {
      name: "ELF entry is executable but not file-backed",
      target: "linux-x64-gnu",
      mutate(binary) {
        binary.writeBigUInt64LE(0x100n, 96);
        binary.writeBigUInt64LE(0x200n, 104);
        binary.writeBigUInt64LE(0x1180n, 24);
      },
    },
    {
      name: "ELF entry in a non-executable load",
      target: "linux-x64-gnu",
      mutate(binary) {
        binary.writeUInt32LE(4, 68);
      },
    },
    {
      name: "Mach-O dylib",
      target: "darwin-x64",
      mutate(binary) {
        binary.writeUInt32LE(6, 12);
      },
    },
    {
      name: "Mach-O out-of-bounds load commands",
      target: "darwin-x64",
      mutate(binary) {
        binary.writeUInt32LE(binary.length, 20);
      },
    },
    {
      name: "Mach-O unaligned load command",
      target: "darwin-x64",
      mutate(binary) {
        binary.writeUInt32LE(97, 20);
        binary.writeUInt32LE(25, 108);
      },
    },
    {
      name: "Mach-O four-byte-only aligned unknown command",
      target: "darwin-x64",
      mutate(binary) {
        const mainCommand = Buffer.from(binary.subarray(104, 128));
        binary.fill(0, 104, 140);
        binary.writeUInt32LE(3, 16);
        binary.writeUInt32LE(108, 20);
        binary.writeUInt32LE(0x12345678, 104);
        binary.writeUInt32LE(12, 108);
        mainCommand.copy(binary, 116);
      },
    },
    {
      name: "Mach-O segment command ignores declared sections",
      target: "darwin-x64",
      mutate(binary) {
        binary.writeUInt32LE(1, 96);
      },
    },
    {
      name: "Mach-O without an entry command",
      target: "darwin-x64",
      mutate(binary) {
        binary.writeUInt32LE(1, 16);
        binary.writeUInt32LE(72, 20);
      },
    },
    {
      name: "Mach-O entry outside executable segments",
      target: "darwin-x64",
      mutate(binary) {
        binary.writeBigUInt64LE(BigInt(binary.length + 1), 112);
      },
    },
    {
      name: "Mach-O entry in a non-executable segment",
      target: "darwin-x64",
      mutate(binary) {
        binary.writeUInt32LE(3, 92);
      },
    },
    {
      name: "Mach-O entry is executable but not file-backed",
      target: "darwin-x64",
      mutate(binary) {
        binary.writeBigUInt64LE(128n, 80);
        binary.writeBigUInt64LE(256n, 112);
      },
    },
    {
      name: "Mach-O file offset entry outside executable virtual memory",
      target: "darwin-x64",
      mutate(binary) {
        binary.fill(0, 32, 200);
        binary.writeUInt32LE(3, 16);
        binary.writeUInt32LE(168, 20);

        binary.writeUInt32LE(0x19, 32);
        binary.writeUInt32LE(72, 36);
        binary.write("__TEXT", 40, "ascii");
        binary.writeBigUInt64LE(0x100000000n, 56);
        binary.writeBigUInt64LE(BigInt(binary.length), 64);
        binary.writeBigUInt64LE(0n, 72);
        binary.writeBigUInt64LE(128n, 80);
        binary.writeUInt32LE(5, 88);
        binary.writeUInt32LE(1, 92);

        binary.writeUInt32LE(0x19, 104);
        binary.writeUInt32LE(72, 108);
        binary.write("__EXEC", 112, "ascii");
        binary.writeBigUInt64LE(0x200000000n, 128);
        binary.writeBigUInt64LE(BigInt(binary.length - 128), 136);
        binary.writeBigUInt64LE(128n, 144);
        binary.writeBigUInt64LE(BigInt(binary.length - 128), 152);
        binary.writeUInt32LE(5, 160);
        binary.writeUInt32LE(5, 164);

        binary.writeUInt32LE(0x80000028, 176);
        binary.writeUInt32LE(24, 180);
        binary.writeBigUInt64LE(256n, 184);
      },
    },
    {
      name: "Mach-O has LC_MAIN and LC_UNIXTHREAD entries",
      target: "darwin-x64",
      mutate(binary) {
        binary.writeUInt32LE(3, 16);
        binary.writeUInt32LE(104, 20);
        binary.writeUInt32LE(0x5, 128);
        binary.writeUInt32LE(8, 132);
      },
    },
    {
      name: "PE image without executable characteristics",
      target: "win32-x64-msvc",
      mutate(binary) {
        binary.writeUInt16LE(0, 150);
      },
    },
    {
      name: "PE image marked as a DLL",
      target: "win32-x64-msvc",
      mutate(binary) {
        binary.writeUInt16LE(binary.readUInt16LE(150) | 0x2000, 150);
      },
    },
    {
      name: "PE image uses PE32 optional header",
      target: "win32-x64-msvc",
      mutate(binary) {
        binary.writeUInt16LE(0x10b, 152);
      },
    },
    {
      name: "PE optional header omits declared data directories",
      target: "win32-x64-msvc",
      mutate(binary) {
        const sectionHeader = Buffer.from(binary.subarray(392, 432));
        sectionHeader.copy(binary, 264);
        binary.writeUInt16LE(112, 148);
      },
    },
    {
      name: "PE low-alignment file offset differs from its RVA",
      target: "win32-x64-msvc",
      mutate(binary) {
        binary.writeUInt32LE(0x200, 184);
      },
    },
    {
      name: "PE duplicate mapped and raw section ranges",
      target: "win32-x64-msvc",
      mutate(binary) {
        addSecondSyntheticPeSection(binary, 0x1000, 0x200);
      },
    },
    {
      name: "PE mapped sections have a gap",
      target: "win32-x64-msvc",
      size: 1536,
      mutate(binary) {
        addSecondSyntheticPeSection(binary, 0x3000, 0x400);
        binary.writeUInt32LE(0x4000, 208);
      },
    },
    {
      name: "PE mapped sections are not in ascending order",
      target: "win32-x64-msvc",
      size: 1536,
      mutate(binary) {
        binary.writeUInt32LE(0x2000, 168);
        binary.writeUInt32LE(0x2000, 404);
        addSecondSyntheticPeSection(binary, 0x1000, 0x400);
        binary.writeUInt32LE(0x3000, 208);
      },
    },
    {
      name: "PE raw section ranges overlap",
      target: "win32-x64-msvc",
      mutate(binary) {
        addSecondSyntheticPeSection(binary, 0x2000, 0x200);
        binary.writeUInt32LE(0x3000, 208);
      },
    },
    {
      name: "PE raw sections are out of RVA order",
      target: "win32-x64-msvc",
      size: 1536,
      mutate(binary) {
        binary.writeUInt32LE(0x400, 412);
        addSecondSyntheticPeSection(binary, 0x2000, 0x200);
        binary.writeUInt32LE(0x3000, 208);
      },
    },
    {
      name: "PE FileAlignment is zero",
      target: "win32-x64-msvc",
      mutate(binary) {
        binary.writeUInt32LE(0, 188);
      },
    },
    {
      name: "PE FileAlignment is not a power of two",
      target: "win32-x64-msvc",
      size: 1536,
      mutate(binary) {
        binary.writeUInt32LE(0x300, 188);
        binary.writeUInt32LE(0x300, 212);
        binary.writeUInt32LE(0x300, 408);
        binary.writeUInt32LE(0x300, 412);
      },
    },
    {
      name: "PE SectionAlignment is zero",
      target: "win32-x64-msvc",
      mutate(binary) {
        binary.writeUInt32LE(0, 184);
      },
    },
    {
      name: "PE SectionAlignment is below FileAlignment",
      target: "win32-x64-msvc",
      mutate(binary) {
        binary.writeUInt32LE(0x100, 184);
      },
    },
    {
      name: "PE SizeOfImage is zero",
      target: "win32-x64-msvc",
      mutate(binary) {
        binary.writeUInt32LE(0, 208);
      },
    },
    {
      name: "PE SizeOfImage is not section-aligned",
      target: "win32-x64-msvc",
      mutate(binary) {
        binary.writeUInt32LE(0x2001, 208);
      },
    },
    {
      name: "PE SizeOfHeaders is zero",
      target: "win32-x64-msvc",
      mutate(binary) {
        binary.writeUInt32LE(0, 212);
      },
    },
    {
      name: "PE SizeOfHeaders is not file-aligned",
      target: "win32-x64-msvc",
      mutate(binary) {
        binary.writeUInt32LE(0x201, 212);
      },
    },
    {
      name: "PE SizeOfHeaders does not cover the section table",
      target: "win32-x64-msvc",
      mutate(binary) {
        binary.writeUInt16LE(4, 134);
      },
    },
    {
      name: "PE SizeOfHeaders exceeds the file",
      target: "win32-x64-msvc",
      mutate(binary) {
        binary.writeUInt32LE(0x600, 212);
      },
    },
    {
      name: "PE section raw offset is not file-aligned",
      target: "win32-x64-msvc",
      size: 1536,
      mutate(binary) {
        binary.writeUInt32LE(0x300, 412);
      },
    },
    {
      name: "PE section raw size is not file-aligned",
      target: "win32-x64-msvc",
      mutate(binary) {
        binary.writeUInt32LE(0x100, 408);
      },
    },
    {
      name: "PE section raw range exceeds the file",
      target: "win32-x64-msvc",
      mutate(binary) {
        binary.writeUInt32LE(0x400, 412);
      },
    },
    {
      name: "PE section virtual address is not section-aligned",
      target: "win32-x64-msvc",
      mutate(binary) {
        binary.writeUInt32LE(0x1001, 168);
        binary.writeUInt32LE(0x1001, 404);
      },
    },
    {
      name: "PE mapped section exceeds SizeOfImage",
      target: "win32-x64-msvc",
      mutate(binary) {
        binary.writeUInt32LE(0x1001, 400);
      },
    },
    {
      name: "PE entry is outside executable sections",
      target: "win32-x64-msvc",
      mutate(binary) {
        binary.writeUInt32LE(0x1800, 168);
      },
    },
    {
      name: "PE entry is executable but not file-backed",
      target: "win32-x64-msvc",
      mutate(binary) {
        binary.writeUInt32LE(0x400, 400);
        binary.writeUInt32LE(0x100, 408);
        binary.writeUInt32LE(0x1180, 168);
      },
    },
    {
      name: "PE entry section is not executable",
      target: "win32-x64-msvc",
      mutate(binary) {
        binary.writeUInt32LE(0x40000020, 428);
      },
    },
    {
      name: "PE out-of-bounds header",
      target: "win32-x64-msvc",
      mutate(binary) {
        binary.writeUInt32LE(binary.length + 1, 0x3c);
      },
    },
  ];
  for (const { name, target, size, mutate } of malformedCases) {
    const artifact = plan.artifacts.find((candidate) => candidate.target === target);
    const archivePath = path.join(destination, artifact.archive);
    const originalArchive = readFileSync(archivePath);
    const binaryPath = path.join(destination, `malformed-${target}`);
    writeSyntheticNative(binaryPath, target, size);
    const malformed = readFileSync(binaryPath);
    mutate(malformed);
    writeNativeReleaseArchive(archivePath, target, malformed);
    assert.throws(
      () => release.validateNativeReleaseArchives(
        destination,
        validationStaging(context, `malformed-${name.replaceAll(" ", "-")}`),
      ),
      expectReleaseError("release-binary-target-mismatch"),
      name,
    );
    writeFileSync(archivePath, originalArchive);
  }

  const linuxArtifact = plan.artifacts.find(({ target }) => target === "linux-x64-gnu");
  const linuxArchivePath = path.join(destination, linuxArtifact.archive);
  const originalLinuxArchive = readFileSync(linuxArchivePath);
  const muslBinaryPath = path.join(destination, "musl-linux-x64");
  writeSyntheticNative(muslBinaryPath, linuxArtifact.target);
  const muslBinary = readFileSync(muslBinaryPath);
  const muslInterpreter = "/lib/ld-musl-x86_64.so.1\0";
  muslBinary.fill(0, 256, 320);
  muslBinary.write(muslInterpreter, 256, "ascii");
  muslBinary.writeBigUInt64LE(BigInt(muslInterpreter.length), 152);
  muslBinary.writeBigUInt64LE(BigInt(muslInterpreter.length), 160);
  writeNativeReleaseArchive(linuxArchivePath, linuxArtifact.target, muslBinary);
  assert.throws(
    () => release.validateNativeReleaseArchives(
      destination,
      validationStaging(context, "musl"),
    ),
    expectReleaseError("release-binary-target-mismatch"),
    "glibc archive accepted a musl binary",
  );
  writeFileSync(linuxArchivePath, originalLinuxArchive);
});

test("native release archive validation rejects one-byte npm drift", (context) => {
  const destination = mkdtempSync(path.join(tmpdir(), "satelle-native-release-drift-"));
  context.after(() => rmSync(destination, { recursive: true, force: true }));
  const release = createReleaseContext(repositoryRoot);
  const { binaries, plan } = stageNativeReleaseSet(release, destination);
  const artifact = plan.artifacts.find(({ target }) => target === "linux-x64-gnu");
  const driftedBinary = Buffer.from(binaries.get(artifact.target));
  driftedBinary[driftedBinary.length - 1] ^= 1;
  writeNativeReleaseArchive(
    path.join(destination, artifact.archive),
    artifact.target,
    driftedBinary,
  );

  assert.throws(
    () => release.validateNativeReleaseArchives(
      destination,
      validationStaging(context, "drift"),
    ),
    expectReleaseError("release-native-digest-mismatch"),
  );
});

test(
  "native release archive validation detects archive and npm replacement during snapshot",
  (context) => {
    const destination = mkdtempSync(path.join(tmpdir(), "satelle-native-release-race-"));
    context.after(() => rmSync(destination, { recursive: true, force: true }));
    const release = createReleaseContext(repositoryRoot);
    const { binaries, plan } = stageNativeReleaseSet(release, destination);
    const artifact = plan.artifacts.find(({ target }) => target === "linux-x64-gnu");
    const randomPadding = Buffer.allocUnsafe(8 * 1024 * 1024);
    let value = 0x9e3779b9;
    for (let index = 0; index < randomPadding.length; index += 1) {
      value ^= value << 13;
      value ^= value >>> 17;
      value ^= value << 5;
      randomPadding[index] = value;
    }

    const raceCases = [
      {
        label: "archive",
        sourcePath: path.join(destination, artifact.archive),
        enlarge(sourcePath) {
          writeTarGzArchive(sourcePath, [
            { name: "satelle", contents: binaries.get(artifact.target) },
            { name: "padding", contents: randomPadding, mode: 0o644 },
          ]);
        },
      },
      {
        label: "npm",
        sourcePath: path.join(destination, artifact.npmArtifact),
        enlarge(sourcePath, original) {
          writeFileSync(sourcePath, Buffer.concat([original, randomPadding]));
        },
      },
    ];

    for (const raceCase of raceCases) {
      const original = readFileSync(raceCase.sourcePath);
      for (const phase of [
        "source-chunk",
        "same-inode-append",
        "same-inode-truncate",
        "final-source-validation",
      ]) {
        const replacementPath = path.join(
          destination,
          `replacement-${raceCase.label}-${phase}`,
        );
        const displacedPath = path.join(destination, `displaced-${raceCase.label}-${phase}`);
        writeFileSync(replacementPath, original);
        if (["source-chunk", "same-inode-append", "same-inode-truncate"].includes(phase)) {
          raceCase.enlarge(raceCase.sourcePath, original);
        }
        const expectedBytes = statSync(raceCase.sourcePath).size;
        let observedBytes = 0;
        let observedZeroReads = 0;
        let sourceChunkObserved = false;
        const replaceSource = () => {
          renameSync(raceCase.sourcePath, displacedPath);
          renameSync(replacementPath, raceCase.sourcePath);
        };
        const raceRelease = createReleaseContext(repositoryRoot, {
          afterNativeArchiveSourceChunk({ label }) {
            if (label !== path.basename(raceCase.sourcePath)) return;
            if (phase === "source-chunk") replaceSource();
          },
          observeNativeArchiveSourceRead({ label, sourcePath, bytesRead, position }) {
            if (label !== path.basename(raceCase.sourcePath)) return;
            observedBytes += bytesRead;
            if (bytesRead === 0) {
              observedZeroReads += 1;
              assert.equal(observedZeroReads, 1, "snapshot retried a zero-byte source read");
              return;
            }
            if (sourceChunkObserved) return;
            sourceChunkObserved = true;
            if (phase === "same-inode-append") appendFileSync(sourcePath, randomPadding);
            if (phase === "same-inode-truncate") truncateSync(sourcePath, position);
          },
          beforeNativeArchiveFinalSourceValidation() {
            if (phase === "final-source-validation") replaceSource();
          },
        });
        assert.throws(
          () => raceRelease.validateNativeReleaseArchives(
            destination,
            validationStaging(context, `race-${raceCase.label}-${phase}`),
          ),
          expectReleaseError("release-integrity-mismatch"),
          `${raceCase.label} ${phase}`,
        );
        if (phase === "same-inode-append") {
          assert.equal(observedBytes, expectedBytes, "snapshot read beyond its opened source size");
        }
        if (phase === "same-inode-truncate") {
          assert.equal(observedZeroReads, 1, "snapshot did not reject its first zero-byte read");
        }
        if (existsSync(displacedPath)) rmSync(displacedPath);
        writeFileSync(raceCase.sourcePath, original);
      }
    }
  },
);

test("failed native release cleanup does not follow staging symlinks", {
  skip: process.platform === "win32",
}, (context) => {
  const destination = mkdtempSync(path.join(tmpdir(), "satelle-native-cleanup-symlink-"));
  context.after(() => rmSync(destination, { recursive: true, force: true }));
  const stagingRoot = validationStaging(context, "cleanup-symlink");
  const victim = mkdtempSync(path.join(tmpdir(), "satelle-native-cleanup-victim-"));
  context.after(() => {
    if (!existsSync(victim)) return;
    chmodSync(victim, 0o700);
    rmSync(victim, { recursive: true, force: true });
  });
  writeFileSync(path.join(victim, "sentinel"), "unchanged");
  chmodSync(victim, 0o555);
  const release = createReleaseContext(repositoryRoot, {
    beforeNativeArchiveFinalSourceValidation() {
      const githubRoot = path.join(stagingRoot, "github");
      rmSync(githubRoot, { recursive: true, force: true });
      symlinkSync(victim, githubRoot, "dir");
    },
  });
  stageNativeReleaseSet(release, destination);

  assert.throws(
    () => release.validateNativeReleaseArchives(destination, stagingRoot),
    expectReleaseError("release-integrity-mismatch"),
  );
  assert.equal(existsSync(stagingRoot), false);
  assert.equal(statSync(victim).mode & 0o777, 0o555);
  assert.equal(readFileSync(path.join(victim, "sentinel"), "utf8"), "unchanged");
});

test("native release validation uses one immutable policy snapshot", (context) => {
  const fixtureRoot = fixtureRepository(context);
  const destination = mkdtempSync(path.join(tmpdir(), "satelle-native-policy-snapshot-"));
  context.after(() => rmSync(destination, { recursive: true, force: true }));
  const linuxManifestPath = path.join(
    fixtureRoot,
    "npm",
    "satelle-linux-x64-gnu",
    "package.json",
  );
  const matrixPath = path.join(fixtureRoot, "npm", "satelle", "platforms.json");
  const release = createReleaseContext(fixtureRoot, {
    afterNativeArchiveSnapshots() {
      const manifest = readJson(linuxManifestPath);
      writeJson(linuxManifestPath, { ...manifest, cpu: ["arm64"] });
      const matrix = readJson(matrixPath);
      matrix["linux-x64-gnu"].cpu = "arm64";
      writeJson(matrixPath, matrix);
    },
  });
  stageNativeReleaseSet(release, destination);

  assert.doesNotThrow(() => release.validateNativeReleaseArchives(
    destination,
    validationStaging(context, "policy-snapshot"),
  ));
});

test("validated publication inputs remain bound after source replacement", (context) => {
  const destination = mkdtempSync(path.join(tmpdir(), "satelle-native-release-handoff-"));
  context.after(() => rmSync(destination, { recursive: true, force: true }));
  const release = createReleaseContext(repositoryRoot);
  stageNativeReleaseSet(release, destination);
  const validation = release.validateNativeReleaseArchives(
    destination,
    validationStaging(context, "handoff"),
  );
  const stagedBytes = validation.archives.map((archive) => ({
    archive,
    github: readFileSync(archive.archivePath),
    npm: readFileSync(archive.npmArtifactPath),
  }));

  for (const { archive } of stagedBytes) {
    writeFileSync(path.join(destination, archive.archive), "replaced archive");
    writeFileSync(path.join(destination, archive.npmArtifact), "replaced npm artifact");
  }

  for (const { archive, github, npm } of stagedBytes) {
    assert.deepEqual(readFileSync(archive.archivePath), github);
    assert.deepEqual(readFileSync(archive.npmArtifactPath), npm);
    assert.equal(sha256(github), archive.archiveSha256);
    assert.equal(sha256(npm), archive.npmArtifactSha256);
  }
});

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
