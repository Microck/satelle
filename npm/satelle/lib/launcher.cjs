"use strict";

const { spawnSync } = require("node:child_process");
const { existsSync, readFileSync } = require("node:fs");
const { createRequire } = require("node:module");
const path = require("node:path");

const launcherVersion = require("../package.json").version;
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
  const normalizedUserAgent = userAgent?.toLowerCase() || "";
  if (normalizedUserAgent.startsWith("pnpm/")) {
    return "pnpm";
  }
  if (normalizedUserAgent.startsWith("bun/")) {
    return "bun";
  }
  if (normalizedUserAgent.startsWith("npm/")) {
    return "npm";
  }

  const executableName = path.basename(execPath || "").toLowerCase();
  if (executableName.includes("pnpm")) {
    return "pnpm";
  }
  if (executableName === "bun" || executableName === "bun.exe") {
    return "bun";
  }
  if (
    executableName === "npm" ||
    executableName === "npm.cmd" ||
    executableName === "npm-cli.js"
  ) {
    return "npm";
  }

  const normalizedLauncherPath = launcherPath?.replaceAll("\\", "/").toLowerCase() || "";
  if (normalizedLauncherPath.includes("/.pnpm/") || normalizedLauncherPath.includes("/pnpm/")) {
    return "pnpm";
  }
  if (normalizedLauncherPath.includes("/.bun/") || normalizedLauncherPath.includes("/bun/")) {
    return "bun";
  }

  let installationRoot = launcherPath ? path.resolve(launcherPath) : undefined;
  while (installationRoot && path.basename(installationRoot) !== "node_modules") {
    const parent = path.dirname(installationRoot);
    if (parent === installationRoot) {
      installationRoot = undefined;
      break;
    }
    installationRoot = parent;
  }
  const projectRoot = installationRoot ? path.dirname(installationRoot) : undefined;
  if (projectRoot) {
    const lockfileManagers = [
      ["bun", ["bun.lock", "bun.lockb"]],
      ["pnpm", ["pnpm-lock.yaml"]],
      ["npm", ["package-lock.json", "npm-shrinkwrap.json"]],
    ];
    for (const [packageManager, lockfiles] of lockfileManagers) {
      if (lockfiles.some((lockfile) => existsSync(path.join(projectRoot, lockfile)))) {
        return packageManager;
      }
    }
  }
  return undefined;
}

function detectInstallationScope(launcherPath) {
  if (!launcherPath) {
    return undefined;
  }

  const normalizedPath = launcherPath.replaceAll("\\", "/").toLowerCase();
  const globalLayoutMarkers = [
    "/lib/node_modules/",
    "/appdata/roaming/npm/node_modules/",
    "/.bun/install/global/",
    "/pnpm/global/",
  ];
  if (globalLayoutMarkers.some((marker) => normalizedPath.includes(marker))) {
    return "global";
  }
  return normalizedPath.includes("/node_modules/") ? "local" : undefined;
}

function detectForwardingContext({ packageName, launcherPath }) {
  if (packageName !== "@microck/satelle") {
    return { packageName, launcherPath };
  }

  const canonicalRoot = path.dirname(path.dirname(launcherPath));
  if (
    path.basename(canonicalRoot) !== "satelle" ||
    path.basename(path.dirname(canonicalRoot)) !== "@microck"
  ) {
    return { packageName, launcherPath };
  }

  const nodeModulesRoot = path.dirname(path.dirname(canonicalRoot));
  const unscopedRoot = path.join(nodeModulesRoot, "satelle");
  const unscopedManifestPath = path.join(unscopedRoot, "package.json");
  const unscopedLauncherPath = path.join(unscopedRoot, "bin", "satelle.cjs");
  if (!existsSync(unscopedManifestPath) || !existsSync(unscopedLauncherPath)) {
    return { packageName, launcherPath };
  }

  try {
    const manifest = JSON.parse(readFileSync(unscopedManifestPath, "utf8"));
    if (manifest.name === "satelle" && manifest.dependencies?.["@microck/satelle"]) {
      return { packageName: "satelle", launcherPath: unscopedLauncherPath };
    }
  } catch {
    // Invalid package metadata must not change the canonical launch context.
  }

  return { packageName, launcherPath };
}

function reinstallCommand({ packageManager, packageName, installScope }) {
  const globalFlag = installScope === "global" ? " --global" : "";
  switch (packageManager) {
    case "pnpm":
      return `pnpm add${globalFlag} ${packageName}`;
    case "bun":
      return `bun add${globalFlag} ${packageName}`;
    case "npm":
    default:
      return `npm install${globalFlag} ${packageName} --include=optional`;
  }
}

function missingPackageError(target, recoveryContext = {}) {
  const context = {
    packageManager: recoveryContext.packageManager,
    packageName: recoveryContext.packageName || "@microck/satelle",
    installScope: recoveryContext.installScope,
  };
  const unknownScopeHint = context.installScope
    ? ""
    : " If Satelle was installed globally, add --global to that command.";
  return new LauncherError(
    "native-binary-package-missing",
    [
      `The matching native package ${target.packageName} is missing`,
      `or does not contain ${target.binaryPath}.`,
      `Reinstall without omitting optional dependencies using \`${reinstallCommand(context)}\`,`,
      `or use the direct native binary installation path.${unknownScopeHint}`,
    ].join(" "),
  );
}

function resolveNativeBinary(
  target,
  searchFrom = path.resolve(__dirname, ".."),
  recoveryContext,
  expectedVersion = launcherVersion,
) {
  const resolver = createRequire(path.join(path.resolve(searchFrom), "satelle-resolver.cjs"));
  let packageManifestPath;

  try {
    packageManifestPath = resolver.resolve(`${target.packageName}/package.json`);
  } catch (error) {
    if (error?.code === "MODULE_NOT_FOUND") {
      throw missingPackageError(target, recoveryContext);
    }
    throw error;
  }

  const nativeManifest = JSON.parse(readFileSync(packageManifestPath, "utf8"));
  if (nativeManifest.version !== expectedVersion) {
    throw missingPackageError(target, recoveryContext);
  }

  const binaryPath = path.join(path.dirname(packageManifestPath), target.binaryPath);
  if (!existsSync(binaryPath)) {
    throw missingPackageError(target, recoveryContext);
  }
  return binaryPath;
}

function executeNativeBinary(binaryPath, argumentsToForward) {
  const child = spawnSync(path.toNamespacedPath(binaryPath), argumentsToForward, {
    stdio: "inherit",
  });
  if (child.error) {
    throw new LauncherError(
      "native-binary-execution-failed",
      `Could not start ${binaryPath}: ${child.error.message}`,
    );
  }
  if (child.signal) {
    process.kill(process.pid, child.signal);
  }
  return child.status === null ? 1 : child.status;
}

function main({ packageName = "@microck/satelle", launcherPath = __filename } = {}) {
  try {
    const launchContext = detectForwardingContext({ packageName, launcherPath });
    const runtime = {
      platform: process.platform,
      arch: process.arch,
      libc: process.platform === "linux" ? detectLinuxLibc() : undefined,
    };
    const target = selectTarget(runtime);
    const packageManager = detectPackageManager({
      userAgent: process.env.npm_config_user_agent,
      execPath: process.env.npm_execpath,
      launcherPath: launchContext.launcherPath,
    });
    const recoveryContext = {
      packageManager,
      packageName: launchContext.packageName,
      installScope: detectInstallationScope(launchContext.launcherPath),
    };
    const binaryPath = resolveNativeBinary(
      target,
      path.resolve(__dirname, ".."),
      recoveryContext,
    );
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
  detectForwardingContext,
  detectInstallationScope,
  detectLinuxLibc,
  detectPackageManager,
  executeNativeBinary,
  main,
  resolveNativeBinary,
  selectTarget,
};
