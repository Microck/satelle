#!/usr/bin/env node
"use strict";

const { createHash } = require("node:crypto");
const { execFileSync, spawnSync } = require("node:child_process");
const {
  closeSync,
  copyFileSync,
  existsSync,
  mkdirSync,
  mkdtempSync,
  openSync,
  readFileSync,
  readSync,
  renameSync,
  rmSync,
  statSync,
  writeFileSync,
} = require("node:fs");
const { tmpdir } = require("node:os");
const path = require("node:path");

const defaultRepositoryRoot = path.resolve(__dirname, "../..");
const maximumNativeBinaryBytes = 512 * 1024 * 1024;
const maximumNpmArtifactBytes = 512 * 1024 * 1024;
const launcherSmokeTimeoutMilliseconds = 5_000;
const defaultNpmCommandTimeoutMilliseconds = 300_000;
const defaultTarCommandTimeoutMilliseconds = 60_000;

class ReleaseError extends Error {
  constructor(code, message) {
    super(message);
    this.code = code;
  }
}

function fail(code, message) {
  throw new ReleaseError(code, message);
}

function readJson(filePath) {
  return JSON.parse(readFileSync(filePath, "utf8"));
}

function sameJson(left, right) {
  return JSON.stringify(left) === JSON.stringify(right);
}

function sortedObject(entries) {
  return Object.fromEntries(
    [...entries].sort(([left], [right]) => left.localeCompare(right)),
  );
}

function sha512Integrity(filePath) {
  const digest = createHash("sha512");
  const file = openSync(filePath, "r");
  const chunk = Buffer.allocUnsafe(1024 * 1024);
  try {
    let bytesRead;
    while ((bytesRead = readSync(file, chunk, 0, chunk.length, null)) !== 0) {
      digest.update(chunk.subarray(0, bytesRead));
    }
  } finally {
    closeSync(file);
  }
  return `sha512-${digest.digest("base64")}`;
}

function createReleaseContext(repositoryRoot = defaultRepositoryRoot, options = {}) {
  const npmRoot = path.join(repositoryRoot, "npm");
  const npmCommandTimeoutMilliseconds =
    options.npmCommandTimeoutMilliseconds ?? defaultNpmCommandTimeoutMilliseconds;
  const tarCommandTimeoutMilliseconds =
    options.tarCommandTimeoutMilliseconds ?? defaultTarCommandTimeoutMilliseconds;
  const matrix = readJson(path.join(npmRoot, "satelle", "platforms.json"));
  const targets = Object.keys(matrix).sort();
  const nativePackages = targets.map((target) => matrix[target].packageName);
  const topLevelPackages = ["@microck/satelle", "satelle"];
  const publicationOrder = [...nativePackages, ...topLevelPackages];

  function packageDirectory(packageName) {
    if (packageName === "@microck/satelle") return "satelle";
    if (packageName === "satelle") return "satelle-unscoped";
    const target = targets.find((candidate) => matrix[candidate].packageName === packageName);
    if (!target) fail("release-package-unknown", `unknown release package ${packageName}`);
    return `satelle-${target}`;
  }

  function packageManifestPath(packageName) {
    return path.join(npmRoot, packageDirectory(packageName), "package.json");
  }

  function readWorkspaceVersion() {
    const cargo = readFileSync(path.join(repositoryRoot, "Cargo.toml"), "utf8");
    const workspacePackage = cargo.match(/\[workspace\.package\]([\s\S]*?)(?:\n\[|$)/);
    const version = workspacePackage?.[1].match(/^version\s*=\s*"([^"]+)"/m)?.[1];
    if (!version) fail("release-version-missing", "Cargo workspace version is missing");
    return version;
  }

  function validatePublishMetadata(packageName, manifest) {
    if (
      manifest.private === true ||
      manifest.publishConfig?.access !== "public" ||
      manifest.publishConfig?.provenance !== true
    ) {
      fail(
        "release-package-metadata-mismatch",
        `${packageName} must enable public npm provenance`,
      );
    }
    for (const lifecycle of ["preinstall", "install", "postinstall", "prepare"]) {
      if (manifest.scripts?.[lifecycle] !== undefined) {
        fail(
          "release-package-metadata-mismatch",
          `${packageName} defines forbidden consumer lifecycle script ${lifecycle}`,
        );
      }
    }
  }

  function validatePackageGraph(version) {
    const manifests = new Map();
    for (const packageName of publicationOrder) {
      const manifest = readJson(packageManifestPath(packageName));
      manifests.set(packageName, manifest);
      if (manifest.name !== packageName) {
        fail(
          "release-package-metadata-mismatch",
          `${packageName} manifest declares ${manifest.name ?? "no package name"}`,
        );
      }
      if (manifest.version !== version) {
        fail(
          "release-version-mismatch",
          `${packageName} has version ${manifest.version}; expected ${version}`,
        );
      }
      validatePublishMetadata(packageName, manifest);
    }

    const scoped = manifests.get("@microck/satelle");
    const expectedOptionalDependencies = sortedObject(
      nativePackages.map((packageName) => [packageName, version]),
    );
    const actualOptionalDependencies = sortedObject(
      Object.entries(scoped.optionalDependencies ?? {}),
    );
    if (!sameJson(actualOptionalDependencies, expectedOptionalDependencies)) {
      fail(
        "release-package-graph-mismatch",
        "the scoped package optionalDependencies do not exactly match the native target matrix",
      );
    }
    if (scoped.dependencies !== undefined || scoped.peerDependencies !== undefined) {
      fail(
        "release-package-graph-mismatch",
        "@microck/satelle defines unexpected install-time dependency edges",
      );
    }
    if (
      scoped.bin?.satelle !== "bin/satelle.cjs" ||
      !sameJson(scoped.exports, { "./launcher": "./bin/satelle.cjs" }) ||
      !sameJson(scoped.files, ["bin/satelle.cjs", "lib/launcher.cjs", "platforms.json"])
    ) {
      fail(
        "release-package-metadata-mismatch",
        "@microck/satelle executable ownership does not match the canonical launcher",
      );
    }

    const unscoped = manifests.get("satelle");
    if (
      !sameJson(unscoped.dependencies, { "@microck/satelle": version }) ||
      unscoped.optionalDependencies !== undefined ||
      unscoped.peerDependencies !== undefined ||
      unscoped.bin?.satelle !== "bin/satelle.cjs" ||
      !sameJson(unscoped.files, ["bin/satelle.cjs"])
    ) {
      fail(
        "release-package-metadata-mismatch",
        "satelle must forward its executable to the exact canonical package version",
      );
    }

    for (const target of targets) {
      const targetMetadata = matrix[target];
      const manifest = manifests.get(targetMetadata.packageName);
      const expectedLibc = targetMetadata.libc ? [targetMetadata.libc] : undefined;
      if (
        manifest.dependencies !== undefined ||
        manifest.optionalDependencies !== undefined ||
        manifest.peerDependencies !== undefined
      ) {
        fail(
          "release-package-graph-mismatch",
          `${targetMetadata.packageName} defines unexpected install-time dependency edges`,
        );
      }
      if (
        !sameJson(manifest.os, [targetMetadata.os]) ||
        !sameJson(manifest.cpu, [targetMetadata.cpu]) ||
        !sameJson(manifest.libc, expectedLibc) ||
        !sameJson(manifest.files, [targetMetadata.binaryPath]) ||
        manifest.bin !== undefined ||
        manifest.scripts?.prepack !== "node ../scripts/verify-native-package.cjs"
      ) {
        fail(
          "release-package-metadata-mismatch",
          `${targetMetadata.packageName} does not match target ${target}`,
        );
      }
    }
  }

  function validateReadme() {
    const readmeSource = readFileSync(path.join(repositoryRoot, "README.md"), "utf8");
    const guidanceSource = readmeSource.replace(/\\\r?\n\s*/g, " ");
    const readme = readmeSource.replace(/^> ?/gm, "").replace(/\s+/g, " ");
    const requiredGuidance = [
      "Satelle is pre-release software. Build it from source.",
      "reserved by this repository are not published installation paths yet.",
      "Source builds are the only documented installation path until release publication is complete.",
    ];
    const publicNpmGuidance = [
      /\bnpm\s+(?:install|i|exec)\b[^\n`]*\b(?:@microck\/satelle|satelle)\b/i,
      /\bpnpm\s+(?:add|dlx)\b[^\n`]*\b(?:@microck\/satelle|satelle)\b/i,
      /\bpnpm\s+--package(?:=|\s+)(?:@microck\/satelle|satelle)\s+dlx\b/i,
      /\b(?:npx|bunx)\b[^\n`]*\b(?:@microck\/satelle|satelle)\b/i,
      /\bbun\s+add\b[^\n`]*\b(?:@microck\/satelle|satelle)\b/i,
    ];
    if (
      requiredGuidance.some((text) => !readme.includes(text)) ||
      publicNpmGuidance.some((pattern) => pattern.test(guidanceSource))
    ) {
      fail(
        "release-readme-mismatch",
        "README installation guidance must keep npm packages unavailable before publication",
      );
    }
  }

  function expectedVersion(tag) {
    const version = readWorkspaceVersion();
    if (tag !== undefined && tag !== `v${version}`) {
      fail(
        "release-version-mismatch",
        `release tag ${tag} does not match workspace version v${version}`,
      );
    }
    validatePackageGraph(version);
    validateReadme();
    return version;
  }

  function expectedArchiveName(version, target) {
    const extension = target.startsWith("win32-") ? "zip" : "tar.gz";
    return `satelle-v${version}-${target}.${extension}`;
  }

  function npmArtifactName(packageName) {
    if (packageName === "@microck/satelle") return "npm-satelle-scoped.tgz";
    if (packageName === "satelle") return "npm-satelle-unscoped.tgz";
    const target = targets.find((candidate) => matrix[candidate].packageName === packageName);
    return `npm-${target}.tgz`;
  }

  function check(tag) {
    const version = expectedVersion(tag);
    return {
      schemaVersion: "satelle.release-plan.v1",
      version,
      targets: [...targets],
      publicationOrder: [...publicationOrder],
      artifacts: targets.map((target) => ({
        target,
        package: matrix[target].packageName,
        archive: expectedArchiveName(version, target),
        npmArtifact: npmArtifactName(matrix[target].packageName),
      })),
    };
  }

  function resolveNpmCli() {
    const npmCli = [
      process.env.npm_execpath,
      path.join(path.dirname(process.execPath), "node_modules", "npm", "bin", "npm-cli.js"),
      path.resolve(
        path.dirname(process.execPath),
        "../lib/node_modules/npm/bin/npm-cli.js",
      ),
    ].find((candidate) => candidate && existsSync(candidate));
    if (!npmCli) {
      fail("release-npm-missing", "the npm CLI could not be resolved from the Node.js installation");
    }
    return npmCli;
  }

  function runNpm(
    argumentsList,
    cwd = repositoryRoot,
    timeoutMilliseconds = npmCommandTimeoutMilliseconds,
  ) {
    try {
      return execFileSync(
        process.execPath,
        [resolveNpmCli(), ...argumentsList],
        {
          cwd,
          encoding: "utf8",
          env: { ...process.env, npm_config_ignore_scripts: "false" },
          killSignal: "SIGKILL",
          shell: false,
          timeout: timeoutMilliseconds,
        },
      );
    } catch (error) {
      if (error.code === "ETIMEDOUT") {
        fail(
          "release-command-timeout",
          `npm ${argumentsList[0] ?? "command"} exceeded ${timeoutMilliseconds}ms`,
        );
      }
      throw error;
    }
  }

  function npmPack(packageRoot, destination, options = {}) {
    const packDestination = path.resolve(destination);
    mkdirSync(packDestination, { recursive: true });
    const output = runNpm([
      "pack",
      ...(options.ignoreScripts ? ["--ignore-scripts"] : []),
      "--json",
      "--silent",
      "--pack-destination",
      packDestination,
      packageRoot,
    ]);
    const [metadata] = JSON.parse(output);
    return { metadata, archivePath: path.join(packDestination, metadata.filename) };
  }

  function runTar(argumentsList, options = {}) {
    return execFileSync("tar", argumentsList, {
      ...options,
      killSignal: "SIGKILL",
      timeout: tarCommandTimeoutMilliseconds,
    });
  }

  function requireFile(filePath, code, message) {
    if (!filePath || !existsSync(filePath) || !statSync(filePath).isFile()) {
      fail(code, message);
    }
  }

  function validateNativeBinary(target, binary, label) {
    const metadata = matrix[target];
    let matches = false;
    if (metadata.os === "linux") {
      const expectedMachine = metadata.cpu === "arm64" ? 183 : 62;
      const machine = binary.length >= 20 ? binary.readUInt16LE(18) : undefined;
      matches =
        binary.subarray(0, 4).equals(Buffer.from([0x7f, 0x45, 0x4c, 0x46])) &&
        binary[4] === 2 &&
        binary[5] === 1 &&
        machine === expectedMachine &&
        !binary.includes("musl") &&
        (binary.includes("libc.so.6") || binary.includes("ld-linux"));
    } else if (metadata.os === "darwin") {
      const expectedCpu = metadata.cpu === "arm64" ? 0x0100000c : 0x01000007;
      matches =
        binary.length >= 8 &&
        binary.readUInt32LE(0) === 0xfeedfacf &&
        binary.readUInt32LE(4) === expectedCpu;
    } else {
      const peOffset = binary.length >= 64 ? binary.readUInt32LE(0x3c) : binary.length;
      const expectedMachine = metadata.cpu === "arm64" ? 0xaa64 : 0x8664;
      matches =
        binary.subarray(0, 2).toString("ascii") === "MZ" &&
        peOffset + 6 <= binary.length &&
        binary.subarray(peOffset, peOffset + 4).equals(Buffer.from("PE\0\0")) &&
        binary.readUInt16LE(peOffset + 4) === expectedMachine;
    }
    if (!matches) {
      fail(
        "release-binary-target-mismatch",
        `${label} does not match release target ${target}`,
      );
    }
  }

  function stageNative(target, binaryPath, destination) {
    if (!targets.includes(target)) {
      fail("release-target-unsupported", `unknown release target ${target}`);
    }
    const targetMetadata = matrix[target];
    requireFile(binaryPath, "release-binary-missing", `missing native binary ${binaryPath ?? ""}`);
    if (!destination) fail("release-destination-missing", "release destination is required");

    const assemblyRoot = mkdtempSync(path.join(tmpdir(), `satelle-${target}-`));
    try {
      const packageRoot = path.join(assemblyRoot, `satelle-${target}`);
      const packagedBinary = path.join(packageRoot, targetMetadata.binaryPath);
      mkdirSync(path.dirname(packagedBinary), { recursive: true });
      mkdirSync(path.join(assemblyRoot, "scripts"), { recursive: true });

      // Snapshot the caller-owned binary into the private assembly tree first. The
      // exact snapshot validated below is then packed without reopening the mutable
      // build output path, while copyFileSync retains native executable metadata.
      copyFileSync(binaryPath, packagedBinary);
      const binarySize = statSync(packagedBinary).size;
      if (binarySize === 0 || binarySize > maximumNativeBinaryBytes) {
        fail(
          "release-binary-missing",
          `native binary ${binaryPath} must be between 1 and ${maximumNativeBinaryBytes} bytes`,
        );
      }
      validateNativeBinary(target, readFileSync(packagedBinary), binaryPath);
      const version = expectedVersion(process.env.RELEASE_TAG);

      copyFileSync(packageManifestPath(targetMetadata.packageName), path.join(packageRoot, "package.json"));
      copyFileSync(
        path.join(npmRoot, "scripts", "verify-native-package.cjs"),
        path.join(assemblyRoot, "scripts", "verify-native-package.cjs"),
      );

      const packed = npmPack(packageRoot, destination);
      const stableName = npmArtifactName(targetMetadata.packageName);
      const stablePath = path.resolve(destination, stableName);
      validatePackedArtifact(targetMetadata.packageName, packed.archivePath, version);
      renameSync(packed.archivePath, stablePath);
      return {
        package: targetMetadata.packageName,
        version,
        target,
        file: stableName,
        integrity: sha512Integrity(stablePath),
      };
    } finally {
      rmSync(assemblyRoot, { recursive: true, force: true });
    }
  }

  function stageLaunchers(destination) {
    if (!destination) fail("release-destination-missing", "release destination is required");
    const version = expectedVersion(process.env.RELEASE_TAG);
    return topLevelPackages.map((packageName) => {
      const packed = npmPack(
        path.dirname(packageManifestPath(packageName)),
        destination,
        { ignoreScripts: true },
      );
      const stableName = npmArtifactName(packageName);
      const stablePath = path.resolve(destination, stableName);
      validatePackedArtifact(packageName, packed.archivePath, version);
      renameSync(packed.archivePath, stablePath);
      return {
        package: packageName,
        version,
        file: stableName,
        integrity: sha512Integrity(stablePath),
      };
    });
  }

  function validateNpmArtifacts(directory, options = {}) {
    if (!directory) fail("release-destination-missing", "release destination is required");
    const version = expectedVersion(process.env.RELEASE_TAG);
    const packages = publicationOrder.map((packageName) => {
      const file = npmArtifactName(packageName);
      const artifactPath = path.join(directory, file);
      requireFile(
        artifactPath,
        "release-artifact-set-incomplete",
        `missing release artifact ${file}`,
      );
      const artifactSize = statSync(artifactPath).size;
      if (artifactSize === 0) {
        fail("release-artifact-set-incomplete", `release artifact ${file} is empty`);
      }
      if (artifactSize >= maximumNpmArtifactBytes) {
        fail(
          "release-artifact-invalid",
          `release artifact ${file} must be smaller than ${maximumNpmArtifactBytes} bytes`,
        );
      }
      const integrity = sha512Integrity(artifactPath);
      validatePackedArtifact(packageName, artifactPath, version);
      const target = targets.find((candidate) => matrix[candidate].packageName === packageName);
      return {
        package: packageName,
        version,
        ...(target ? { target } : {}),
        file,
        integrity,
      };
    });
    validatePackedLaunchers(directory, version);
    for (const artifact of packages) {
      if (sha512Integrity(path.join(directory, artifact.file)) !== artifact.integrity) {
        fail(
          "release-integrity-mismatch",
          `release artifact ${artifact.file} changed during validation`,
        );
      }
    }
    const manifest = {
      schemaVersion: "satelle.npm-artifacts.v1",
      version,
      packages,
    };
    const manifestPath = path.join(directory, "npm-artifacts.json");
    const serialized = `${JSON.stringify(manifest, null, 2)}\n`;
    if (options.writeManifest) {
      const temporaryDirectory = mkdtempSync(path.join(directory, ".npm-artifacts-"));
      const temporaryPath = path.join(temporaryDirectory, "npm-artifacts.json");
      try {
        writeFileSync(temporaryPath, serialized, { flag: "wx", mode: 0o600 });
        renameSync(temporaryPath, manifestPath);
      } catch {
        fail(
          "release-integrity-write-failed",
          "npm-artifacts.json could not be atomically replaced",
        );
      } finally {
        rmSync(temporaryDirectory, { recursive: true, force: true });
      }
    }
    if (!existsSync(manifestPath)) {
      fail("release-integrity-missing", "npm-artifacts.json is missing");
    }
    if (readFileSync(manifestPath, "utf8") !== serialized) {
      fail("release-integrity-mismatch", "npm-artifacts.json does not match package bytes");
    }
    return manifest;
  }

  function localTarget() {
    let libc;
    if (process.platform === "linux") {
      const report = process.report?.getReport?.();
      if (report?.header?.glibcVersionRuntime) libc = "glibc";
      else if (report?.sharedObjects?.some((item) => item.toLowerCase().includes("musl"))) {
        libc = "musl";
      }
    }
    return targets.find((target) => {
      const metadata = matrix[target];
      return (
        metadata.os === process.platform &&
        metadata.cpu === process.arch &&
        (metadata.libc === undefined || metadata.libc === libc)
      );
    });
  }

  function validatePackedLaunchers(directory, version) {
    const smokeRoot = mkdtempSync(path.join(tmpdir(), "satelle-release-smoke-"));
    try {
      const expectedTarget = localTarget();
      const smokePackages = [
        ...(expectedTarget ? [matrix[expectedTarget].packageName] : []),
        ...topLevelPackages,
      ];
      const dependencies = {};
      for (const packageName of smokePackages) {
        const artifactName = npmArtifactName(packageName);
        copyFileSync(path.join(directory, artifactName), path.join(smokeRoot, artifactName));
        dependencies[packageName] = `file:./${artifactName}`;
      }
      writeFileSync(
        path.join(smokeRoot, "package.json"),
        `${JSON.stringify({ private: true, dependencies }, null, 2)}\n`,
      );
      runNpm(
        [
          "install",
          "--global=false",
          "--force",
          "--ignore-scripts",
          "--offline",
          "--no-audit",
          "--no-fund",
          "--package-lock=false",
          "--silent",
        ],
        smokeRoot,
      );

      const launcherPaths = topLevelPackages.map((packageName) => ({
        packageName,
        launcherPath: path.join(
          smokeRoot,
          "node_modules",
          ...packageName.split("/"),
          "bin",
          "satelle.cjs",
        ),
      }));
      for (const { packageName, launcherPath } of launcherPaths) {
        const child = spawnSync(process.execPath, [launcherPath, "--version"], {
          cwd: smokeRoot,
          encoding: "utf8",
          env: { ...process.env, npm_config_user_agent: "npm/release-validation" },
          killSignal: "SIGKILL",
          timeout: launcherSmokeTimeoutMilliseconds,
        });
        const validResult = expectedTarget
          ? child.status === 0 && child.stdout === `satelle ${version}\n` && child.stderr === ""
          : child.status === 1 &&
            child.stdout === "" &&
            child.stderr.startsWith("satelle: unsupported-local-platform:");
        if (!validResult) {
          fail(
            "release-executable-mismatch",
            `${packageName} packed executable does not preserve native launch behavior`,
          );
        }
      }

      // Removing native packages verifies the launchers' deterministic recovery boundary separately.
      for (const packageName of nativePackages) {
        rmSync(path.join(smokeRoot, "node_modules", ...packageName.split("/")), {
          recursive: true,
          force: true,
        });
      }
      for (const { packageName, launcherPath } of launcherPaths) {
        const child = spawnSync(process.execPath, [launcherPath], {
          cwd: smokeRoot,
          encoding: "utf8",
          env: { ...process.env, npm_config_user_agent: "npm/release-validation" },
          killSignal: "SIGKILL",
          timeout: launcherSmokeTimeoutMilliseconds,
        });
        const expectedError = expectedTarget
          ? "satelle: native-binary-package-missing:"
          : "satelle: unsupported-local-platform:";
        if (
          child.status !== 1 ||
          child.stdout !== "" ||
          !child.stderr.startsWith(expectedError)
        ) {
          fail(
            "release-executable-mismatch",
            `${packageName} packed executable does not preserve launcher behavior`,
          );
        }
      }
    } catch (error) {
      if (error instanceof ReleaseError) throw error;
      fail("release-executable-mismatch", `packed launcher smoke test failed: ${error.message}`);
    } finally {
      rmSync(smokeRoot, { recursive: true, force: true });
    }
  }

  function validateLaunchers(directory) {
    if (!directory) fail("release-destination-missing", "release destination is required");
    validatePackedLaunchers(directory, expectedVersion(process.env.RELEASE_TAG));
  }

  function validatePackedArtifact(packageName, artifactPath, version) {
    let members;
    let verboseMembers;
    let packed;
    let packedManifest;
    try {
      members = new Set(
        runTar(["-tzf", artifactPath], { encoding: "utf8" })
          .trim()
          .split(/\r?\n/),
      );
      verboseMembers = runTar(["-tvzf", artifactPath], { encoding: "utf8" })
        .trim()
        .split(/\r?\n/)
        .map((line) => {
          const normalized = line.trim();
          return {
            permissions: normalized.slice(0, 10),
            name: normalized.slice(normalized.lastIndexOf(" ") + 1),
          };
        });
      packedManifest = runTar([
        "-xOzf",
        artifactPath,
        "package/package.json",
      ]);
      packed = JSON.parse(packedManifest.toString("utf8"));
    } catch {
      fail("release-artifact-invalid", `${path.basename(artifactPath)} is not a valid npm archive`);
    }
    const sourceManifestPath = packageManifestPath(packageName);
    if (
      packed.name !== packageName ||
      packed.version !== version ||
      !packedManifest.equals(readFileSync(sourceManifestPath))
    ) {
      fail(
        "release-artifact-metadata-mismatch",
        `${path.basename(artifactPath)} does not contain ${packageName}@${version}`,
      );
    }
    const expectedMembers = new Set([
      "package/package.json",
      ...(packed.files ?? []).map((fileName) => `package/${fileName}`),
    ]);
    if (
      members.size !== expectedMembers.size ||
      verboseMembers.length !== expectedMembers.size ||
      [...members].some((member) => !expectedMembers.has(member)) ||
      verboseMembers.some(
        (entry) => !expectedMembers.has(entry.name) || entry.permissions[0] !== "-",
      )
    ) {
      fail(
        "release-artifact-invalid",
        `${path.basename(artifactPath)} contains unexpected package members`,
      );
    }
    const target = targets.find((candidate) => matrix[candidate].packageName === packageName);
    for (const fileName of packed.files ?? []) {
      const archiveName = `package/${fileName}`;
      const archiveEntries = verboseMembers.filter((entry) => entry.name === archiveName);
      if (
        !members.has(archiveName) ||
        archiveEntries.length !== 1 ||
        archiveEntries[0].permissions[0] !== "-"
      ) {
        fail(
          "release-artifact-invalid",
          `${path.basename(artifactPath)} is missing package file ${fileName}`,
        );
      }
      if (
        target &&
        matrix[target].os !== "win32" &&
        ![3, 6, 9].every((index) => archiveEntries[0].permissions[index] === "x")
      ) {
        fail(
          "release-artifact-permission-mismatch",
          `${path.basename(artifactPath)} native binary is not executable`,
        );
      }
      if (target) {
        let packedBinary;
        try {
          packedBinary = runTar(["-xOzf", artifactPath, archiveName], {
            maxBuffer: maximumNativeBinaryBytes,
          });
        } catch {
          fail(
            "release-artifact-invalid",
            `${path.basename(artifactPath)} native binary cannot be read within the size limit`,
          );
        }
        validateNativeBinary(
          target,
          packedBinary,
          `${path.basename(artifactPath)} member ${fileName}`,
        );
      }
      if (topLevelPackages.includes(packageName)) {
        const sourceFile = readFileSync(
          path.join(path.dirname(packageManifestPath(packageName)), fileName),
        );
        let packedFile;
        try {
          packedFile = runTar(["-xOzf", artifactPath, archiveName], {
            maxBuffer: sourceFile.length + 1,
          });
        } catch (error) {
          if (error.code === "ETIMEDOUT") {
            fail(
              "release-artifact-invalid",
              `${path.basename(artifactPath)} package file ${fileName} exceeded the archive deadline`,
            );
          }
          fail(
            "release-executable-mismatch",
            `${path.basename(artifactPath)} package file ${fileName} cannot be extracted`,
          );
        }
        if (!packedFile.equals(sourceFile)) {
          fail(
            "release-executable-mismatch",
            `${path.basename(artifactPath)} package file ${fileName} differs from its source`,
          );
        }
      }
    }
  }

  return {
    check,
    stageLaunchers,
    stageNative,
    validateLaunchers,
    validateNpmArtifacts,
  };
}

function runCli() {
  const release = createReleaseContext();
  const [command, ...argumentsList] = process.argv.slice(2);
  let output;
  switch (command) {
    case "check":
      output = release.check(process.env.RELEASE_TAG);
      break;
    case "stage-native":
      output = release.stageNative(argumentsList[0], argumentsList[1], argumentsList[2]);
      break;
    case "stage-launchers":
      output = release.stageLaunchers(argumentsList[0]);
      break;
    case "validate-npm-artifacts":
      output = release.validateNpmArtifacts(argumentsList[0], {
        writeManifest: argumentsList.includes("--write-manifest"),
      });
      break;
    default:
      fail("release-command-invalid", `unknown release command ${command ?? ""}`);
  }
  process.stdout.write(`${JSON.stringify(output)}\n`);
}

if (require.main === module) {
  try {
    runCli();
  } catch (error) {
    const code = error instanceof ReleaseError ? error.code : "release-command-failed";
    process.stderr.write(`${JSON.stringify({ code, message: error.message })}\n`);
    process.exitCode = 1;
  }
}

module.exports = {
  ReleaseError,
  createReleaseContext,
};
