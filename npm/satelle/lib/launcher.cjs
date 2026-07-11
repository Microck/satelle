"use strict";

const { spawnSync } = require("node:child_process");
const { existsSync } = require("node:fs");
const { createRequire } = require("node:module");
const path = require("node:path");

const platformMatrix = require("../platforms.json");

class LauncherError extends Error {
  constructor(code, message) {
    super(message);
    this.name = "LauncherError";
    this.code = code;
  }
}

function formatRuntime({ platform, arch, libc }) {
  return [platform, arch, platform === "linux" ? libc || "unknown-libc" : undefined]
    .filter(Boolean)
    .join("-");
}

function selectTarget(runtime) {
  const target = Object.values(platformMatrix).find(
    (candidate) =>
      candidate.os === runtime.platform &&
      candidate.cpu === runtime.arch &&
      (candidate.libc === undefined || candidate.libc === runtime.libc),
  );

  if (!target) {
    throw new LauncherError(
      "unsupported-local-platform",
      [
        `No Satelle native package is published for ${formatRuntime(runtime)}.`,
        "Use one of the supported platform packages or build the Rust CLI from source.",
      ].join(" "),
    );
  }

  return target;
}

function detectLinuxLibc(processObject = process) {
  try {
    const report = processObject.report?.getReport?.();
    if (report?.header?.glibcVersionRuntime) {
      return "glibc";
    }

    if (report?.sharedObjects?.some((sharedObject) => sharedObject.toLowerCase().includes("musl"))) {
      return "musl";
    }
  } catch {
    // A disabled runtime report means the libc cannot be identified safely.
  }

  return undefined;
}

function detectPackageManager({ userAgent, execPath, launcherPath } = {}) {
  const installationClues = [userAgent, execPath, launcherPath]
    .filter(Boolean)
    .join(" ")
    .toLowerCase();

  if (installationClues.includes("pnpm")) {
    return "pnpm";
  }
  if (installationClues.includes("bun")) {
    return "bun";
  }
  if (installationClues.includes("npm")) {
    return "npm";
  }
  return undefined;
}

function reinstallCommand(packageManager) {
  switch (packageManager) {
    case "pnpm":
      return "pnpm add @microck/satelle";
    case "bun":
      return "bun add @microck/satelle";
    case "npm":
    default:
      return "npm install @microck/satelle --include=optional";
  }
}

function missingPackageError(target, packageManager) {
  return new LauncherError(
    "native-binary-package-missing",
    [
      `The matching native package ${target.packageName} is missing`,
      `or does not contain ${target.binaryPath}.`,
      `Reinstall without omitting optional dependencies using \`${reinstallCommand(packageManager)}\`,`,
      "or use the direct native binary installation path.",
    ].join(" "),
  );
}

function resolveNativeBinary(target, searchFrom = path.resolve(__dirname, ".."), packageManager) {
  const resolver = createRequire(path.join(path.resolve(searchFrom), "satelle-resolver.cjs"));
  let packageManifestPath;

  try {
    packageManifestPath = resolver.resolve(`${target.packageName}/package.json`);
  } catch (error) {
    if (error?.code === "MODULE_NOT_FOUND") {
      throw missingPackageError(target, packageManager);
    }
    throw error;
  }

  const binaryPath = path.join(path.dirname(packageManifestPath), target.binaryPath);
  if (!existsSync(binaryPath)) {
    throw missingPackageError(target, packageManager);
  }
  return binaryPath;
}

function executeNativeBinary(binaryPath, argumentsToForward) {
  const child = spawnSync(binaryPath, argumentsToForward, { stdio: "inherit" });
  if (child.error) {
    throw new LauncherError(
      "native-binary-execution-failed",
      `Could not start ${binaryPath}: ${child.error.message}`,
    );
  }
  return child.status === null ? 1 : child.status;
}

function main() {
  try {
    const runtime = {
      platform: process.platform,
      arch: process.arch,
      libc: process.platform === "linux" ? detectLinuxLibc() : undefined,
    };
    const target = selectTarget(runtime);
    const packageManager = detectPackageManager({
      userAgent: process.env.npm_config_user_agent,
      execPath: process.env.npm_execpath,
      launcherPath: __filename,
    });
    const binaryPath = resolveNativeBinary(target, path.resolve(__dirname, ".."), packageManager);
    process.exitCode = executeNativeBinary(binaryPath, process.argv.slice(2));
  } catch (error) {
    if (!(error instanceof LauncherError)) {
      throw error;
    }
    console.error(`satelle: ${error.code}: ${error.message}`);
    process.exitCode = 1;
  }
}

module.exports = {
  LauncherError,
  detectLinuxLibc,
  detectPackageManager,
  executeNativeBinary,
  main,
  resolveNativeBinary,
  selectTarget,
};
