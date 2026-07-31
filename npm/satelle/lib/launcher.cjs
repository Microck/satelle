"use strict";

const { spawnSync } = require("node:child_process");
const { existsSync, readFileSync, realpathSync } = require("node:fs");
const { createRequire } = require("node:module");
const path = require("node:path");

const launcherVersion = require("../package.json").version;
const platformMatrix = require("../platforms.json");
const packageInstallContextEnvironment = "SATELLE_PACKAGE_INSTALL_CONTEXT";

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

function pathContains(parentPath, childPath) {
  const relative = path.relative(parentPath, childPath);
  return relative === "" || (!relative.startsWith("..") && !path.isAbsolute(relative));
}

function packageRoot(globalRoot, packageName) {
  return path.join(globalRoot, ...packageName.split("/"));
}

function globalRootOwnsLauncher({ globalRoot, packageName, launcherPath }) {
  try {
    return pathContains(
      realpathSync(packageRoot(globalRoot, packageName)),
      realpathSync(launcherPath),
    );
  } catch {
    return false;
  }
}

function commandLine(command, argumentsToForward) {
  const result = spawnSync(command, argumentsToForward, {
    encoding: "utf8",
    timeout: 10_000,
    maxBuffer: 64 * 1024,
    windowsHide: true,
  });
  if (result.status !== 0 || result.error) {
    return undefined;
  }
  const lines = result.stdout
    .split(/\r?\n/)
    .map((line) => line.trim())
    .filter(Boolean);
  return lines.length === 1 ? lines[0] : undefined;
}

function packageManagerCommand(manager, platform) {
  if (platform !== "win32") {
    return manager;
  }
  return manager === "bun" ? "bun.exe" : `${manager}.cmd`;
}

function outerNodeModulesRoot(filePath) {
  let current = path.resolve(filePath);
  let selected;
  while (true) {
    if (path.basename(current).toLowerCase() === "node_modules") {
      selected = current;
    }
    const parent = path.dirname(current);
    if (parent === current) {
      return selected;
    }
    current = parent;
  }
}

function discoverGlobalOwnership({
  packageName,
  launcherPath,
  runCommand = commandLine,
  platform = process.platform,
}) {
  const owners = [];
  for (const [manager, command, argumentsToForward] of [
    ["npm", "npm", ["root", "--global"]],
    ["pnpm", "pnpm", ["root", "--global"]],
  ]) {
    const globalRoot = runCommand(
      packageManagerCommand(command, platform),
      argumentsToForward,
    );
    if (
      globalRoot &&
      globalRootOwnsLauncher({ globalRoot, packageName, launcherPath })
    ) {
      owners.push({ manager, installRoot: globalRoot });
    }
  }

  const bunBin = runCommand(
    packageManagerCommand("bun", platform),
    ["pm", "bin", "--global"],
  );
  if (bunBin) {
    const shimNames =
      platform === "win32"
        ? ["satelle.exe", "satelle.cmd", "satelle"]
        : ["satelle"];
    const bunOwnsLauncher = shimNames.some((shimName) => {
      try {
        return realpathSync(path.join(bunBin, shimName)) === realpathSync(launcherPath);
      } catch {
        return false;
      }
    });
    const installRoot = bunOwnsLauncher ? outerNodeModulesRoot(launcherPath) : undefined;
    if (
      installRoot &&
      globalRootOwnsLauncher({ globalRoot: installRoot, packageName, launcherPath })
    ) {
      owners.push({ manager: "bun", installRoot });
    }
  }
  return owners;
}

function declaredPackageManager(projectRoot, manifest) {
  const packageManager = manifest.packageManager?.split("@", 1)[0];
  const declaredManager = ["npm", "pnpm", "bun"].includes(packageManager)
    ? packageManager
    : undefined;
  const lockOwners = new Set();
  for (const [manager, lockfiles] of [
    ["npm", ["package-lock.json", "npm-shrinkwrap.json"]],
    ["pnpm", ["pnpm-lock.yaml"]],
    ["bun", ["bun.lock", "bun.lockb"]],
  ]) {
    if (lockfiles.some((lockfile) => existsSync(path.join(projectRoot, lockfile)))) {
      lockOwners.add(manager);
    }
  }
  if (declaredManager) {
    return [...lockOwners].every((manager) => manager === declaredManager)
      ? declaredManager
      : undefined;
  }
  return lockOwners.size === 1 ? [...lockOwners][0] : undefined;
}

function manifestDeclaresPackage(manifest, packageName) {
  return ["dependencies", "devDependencies", "optionalDependencies"].some(
    (field) => Object.hasOwn(manifest[field] || {}, packageName),
  );
}

function discoverLocalOwnership({ packageName, launcherPath }) {
  const contexts = [];
  let current = path.resolve(launcherPath);
  while (true) {
    if (path.basename(current).toLowerCase() === "node_modules") {
      const installRoot = path.dirname(current);
      try {
        const manifest = JSON.parse(readFileSync(path.join(installRoot, "package.json"), "utf8"));
        const manager = declaredPackageManager(installRoot, manifest);
        if (manager && manifestDeclaresPackage(manifest, packageName)) {
          contexts.push({ manager, installRoot });
        }
      } catch {
        // Missing or invalid project metadata cannot establish package ownership.
      }
    }
    const parent = path.dirname(current);
    if (parent === current) {
      break;
    }
    current = parent;
  }
  return contexts.length === 1 ? contexts[0] : undefined;
}

function packageInstallContext({
  packageName,
  launcherPath,
  globalOwners = discoverGlobalOwnership({ packageName, launcherPath }),
} = {}) {
  if (!packageName || !launcherPath) {
    return undefined;
  }
  const candidates = globalOwners.map((owner) => ({
    manager: owner.manager,
    scope: "global",
    package_name: packageName,
    install_root: path.resolve(owner.installRoot),
    launcher_path: realpathSync(launcherPath),
  }));
  const localOwner = discoverLocalOwnership({ packageName, launcherPath });
  if (localOwner) {
    candidates.push({
      manager: localOwner.manager,
      scope: "local",
      package_name: packageName,
      install_root: path.resolve(localOwner.installRoot),
      launcher_path: realpathSync(launcherPath),
    });
  }
  return candidates.length === 1 ? candidates[0] : undefined;
}

function isSelfUpdate(argumentsToForward) {
  const command = [];
  for (let index = 0; index < argumentsToForward.length; index += 1) {
    const argument = argumentsToForward[index];
    if (argument === "--no-color") {
      continue;
    }
    if (argument === "--profile" || argument === "--error-format") {
      index += 1;
      continue;
    }
    if (argument.startsWith("--profile=") || argument.startsWith("--error-format=")) {
      continue;
    }
    if (argument.startsWith("-")) {
      return false;
    }
    command.push(argument);
    if (command.length === 2) {
      return command[0] === "self" && command[1] === "update";
    }
  }
  return false;
}

function packageInstallContextForCommand(argumentsToForward, options) {
  return isSelfUpdate(argumentsToForward) ? packageInstallContext(options) : undefined;
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

  const candidates = [];
  let current = canonicalRoot;
  while (true) {
    if (path.basename(current).toLowerCase() === "node_modules") {
      const unscopedRoot = path.join(current, "satelle");
      const unscopedManifestPath = path.join(unscopedRoot, "package.json");
      const unscopedLauncherPath = path.join(unscopedRoot, "bin", "satelle.cjs");
      try {
        const manifest = JSON.parse(readFileSync(unscopedManifestPath, "utf8"));
        const dependency = manifest.dependencies?.["@microck/satelle"];
        let dependencyMatches = dependency === launcherVersion;
        if (!dependencyMatches && dependency) {
          const resolvedCanonicalLauncher = createRequire(unscopedManifestPath).resolve(
            "@microck/satelle/launcher",
          );
          const resolvedCanonicalRoot = path.dirname(path.dirname(resolvedCanonicalLauncher));
          const canonicalManifest = JSON.parse(
            readFileSync(path.join(resolvedCanonicalRoot, "package.json"), "utf8"),
          );
          dependencyMatches =
            canonicalManifest.version === launcherVersion &&
            realpathSync(resolvedCanonicalRoot) === realpathSync(canonicalRoot);
        }
        if (
          existsSync(unscopedLauncherPath) &&
          manifest.name === "satelle" &&
          manifest.version === launcherVersion &&
          dependencyMatches
        ) {
          candidates.push({
            packageName: "satelle",
            launcherPath: realpathSync(unscopedLauncherPath),
          });
        }
      } catch {
        // Invalid package metadata must not change the canonical launch context.
      }
    }
    const parent = path.dirname(current);
    if (parent === current) {
      break;
    }
    current = parent;
  }
  return candidates.length === 1 ? candidates[0] : { packageName, launcherPath };
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

function executeNativeBinary(binaryPath, argumentsToForward, installContext) {
  const environment = { ...process.env };
  delete environment[packageInstallContextEnvironment];
  if (installContext) {
    environment[packageInstallContextEnvironment] = JSON.stringify(installContext);
  }
  const child = spawnSync(path.toNamespacedPath(binaryPath), argumentsToForward, {
    env: environment,
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
    const argumentsToForward = process.argv.slice(2);
    const installContext = packageInstallContextForCommand(argumentsToForward, {
      packageName: launchContext.packageName,
      launcherPath: launchContext.launcherPath,
    });
    process.exitCode = executeNativeBinary(binaryPath, argumentsToForward, installContext);
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
  discoverGlobalOwnership,
  executeNativeBinary,
  isSelfUpdate,
  main,
  packageInstallContext,
  packageInstallContextForCommand,
  resolveNativeBinary,
  selectTarget,
};
