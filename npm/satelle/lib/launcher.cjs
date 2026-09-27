"use strict";

const { spawnSync } = require("node:child_process");
const { createHash } = require("node:crypto");
const { existsSync, lstatSync, readFileSync, realpathSync } = require("node:fs");
const { createRequire } = require("node:module");
const path = require("node:path");

const launcherVersion = require("../package.json").version;
const platformMatrix = require("../platforms.json");
const packageInstallContextEnvironment = "SATELLE_PACKAGE_INSTALL_CONTEXT";

class LauncherError extends Error {
  constructor(code, message, exitCode = 1) {
    super(message);
    this.name = "LauncherError";
    this.code = code;
    this.exitCode = exitCode;
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
    shell: path.extname(command).toLowerCase() === ".cmd",
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

function packageNodeModulesRoot(filePath, packageName) {
  let current = path.resolve(filePath);
  while (true) {
    if (
      path.basename(current).toLowerCase() === "node_modules" &&
      globalRootOwnsLauncher({ globalRoot: current, packageName, launcherPath: filePath })
    ) {
      return current;
    }
    const parent = path.dirname(current);
    if (parent === current) {
      return undefined;
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
    const installRoot = bunOwnsLauncher
      ? packageNodeModulesRoot(launcherPath, packageName)
      : undefined;
    if (installRoot) {
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
  let canonicalLauncherPath;
  try {
    canonicalLauncherPath = realpathSync(launcherPath);
  } catch {
    return undefined;
  }
  const candidates = globalOwners.map((owner) => ({
    manager: owner.manager,
    scope: "global",
    package_name: packageName,
    install_root: path.resolve(owner.installRoot),
    launcher_path: canonicalLauncherPath,
  }));
  const localOwner = discoverLocalOwnership({ packageName, launcherPath });
  if (localOwner) {
    candidates.push({
      manager: localOwner.manager,
      scope: "local",
      package_name: packageName,
      install_root: path.resolve(localOwner.installRoot),
      launcher_path: canonicalLauncherPath,
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
      `run \`satelle native repair\`, or use the direct native binary installation path.${unknownScopeHint}`,
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
  const environment = Object.fromEntries(
    Object.entries(process.env).filter(
      ([name]) => name.toUpperCase() !== packageInstallContextEnvironment,
    ),
  );
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

function nativeRepairOptions(argumentsToForward) {
  const arguments_ = argumentsToForward.filter((argument) => argument !== "--no-color");
  if (arguments_[0] !== "native") return undefined;
  if (arguments_.length === 2 && ["--help", "-h"].includes(arguments_[1])) {
    return { help: true, dryRun: false };
  }
  const options = arguments_.slice(2);
  if (
    arguments_[1] !== "repair" ||
    options.some((option) => !["--dry-run", "--help", "-h"].includes(option))
  ) {
    throw new LauncherError("invalid-usage", "Use satelle native repair [--dry-run].", 64);
  }
  return {
    help: options.includes("--help") || options.includes("-h"),
    dryRun: options.includes("--dry-run"),
  };
}

function nativeRepairPlan(target, installContext) {
  if (!installContext || !["npm", "pnpm", "bun"].includes(installContext.manager)) {
    throw new LauncherError(
      "native-repair-owner-unknown",
      "Cannot identify one package manager that owns this installation. Use the verified direct native binary installation path: https://github.com/Microck/satelle/releases/latest",
    );
  }
  const { manager, scope, install_root: installRoot } = installContext;
  const arguments_ = [manager === "npm" ? "install" : "add"];
  if (scope === "global") {
    arguments_.push("--global");
  } else {
    arguments_.push(
      manager === "bun" ? "--optional" : "--save-optional",
      manager === "bun" ? "--exact" : "--save-exact",
    );
    if (manager === "pnpm" && existsSync(path.join(installRoot, "pnpm-workspace.yaml"))) {
      arguments_.push("--workspace-root");
    }
  }
  // The package manager remains the sole writer of its installation graph.
  // Force rematerialization of missing files without running lifecycle scripts.
  arguments_.push("--force", "--ignore-scripts");
  if (manager === "npm") arguments_.push("--include=optional", "--no-audit", "--no-fund");
  arguments_.push(`${target.packageName}@${launcherVersion}`);
  return {
    manager,
    scope,
    cwd: scope === "global" ? path.dirname(installRoot) : installRoot,
    command: packageManagerCommand(manager, process.platform),
    arguments: arguments_,
  };
}

function verifyRepairedNativePackage(target, searchFrom = path.resolve(__dirname, "..")) {
  try {
    // Use the ordinary resolver, including its exact package-version check.
    const binaryPath = resolveNativeBinary(target, searchFrom);
    const nativeRoot = path.dirname(path.dirname(binaryPath));
    const manifest = JSON.parse(readFileSync(path.join(nativeRoot, "package.json"), "utf8"));
    const expectedLibc = target.libc ? [target.libc] : undefined;
    if (
      manifest.name !== target.packageName ||
      JSON.stringify(manifest.os) !== JSON.stringify([target.os]) ||
      JSON.stringify(manifest.cpu) !== JSON.stringify([target.cpu]) ||
      JSON.stringify(manifest.libc) !== JSON.stringify(expectedLibc)
    ) {
      throw new Error("package platform metadata does not match this runtime");
    }
    const binary = lstatSync(binaryPath);
    if (
      !binary.isFile() ||
      binary.size === 0 ||
      binary.size > 512 * 1024 * 1024 ||
      (target.os !== "win32" && (binary.mode & 0o111) === 0) ||
      realpathSync(binaryPath) !== path.join(realpathSync(nativeRoot), target.binaryPath)
    ) {
      throw new Error("package executable is not a regular executable inside its package");
    }
    const checksumsPath = path.join(nativeRoot, "SHA256SUMS");
    const checksums = lstatSync(checksumsPath);
    if (!checksums.isFile() || checksums.size > 1024) {
      throw new Error("package checksum metadata is not a bounded regular file");
    }
    const digest = createHash("sha256").update(readFileSync(binaryPath)).digest("hex");
    if (readFileSync(checksumsPath, "utf8") !== `${digest}  ${target.binaryPath}\n`) {
      throw new Error("package checksum metadata does not match its executable");
    }
    return binaryPath;
  } catch {
    throw new LauncherError(
      "native-repair-verification-failed",
      `${target.packageName}@${launcherVersion} did not pass version, platform, executable-path, and release-integrity verification. Use the verified direct native release if package-manager reinstallation cannot repair it.`,
    );
  }
}

function repairNativePackage(target, launchContext, { dryRun }) {
  const plan = nativeRepairPlan(target, packageInstallContext(launchContext));
  if (dryRun) {
    console.log(`Owner: ${plan.manager} (${plan.scope})`);
    console.log(`Directory: ${plan.cwd}`);
    console.log([plan.command, ...plan.arguments].join(" "));
    return 0;
  }
  const child = spawnSync(plan.command, plan.arguments, {
    cwd: plan.cwd,
    stdio: ["ignore", 2, 2],
    timeout: 300_000,
    windowsHide: true,
    shell: path.extname(plan.command).toLowerCase() === ".cmd",
  });
  if (child.status !== 0 || child.error) {
    throw new LauncherError(
      "native-repair-failed",
      `${plan.manager} did not complete native package repair. Check its diagnostic output, then retry or use the verified direct native release.`,
    );
  }
  const binaryPath = verifyRepairedNativePackage(target);
  console.log(`Repaired ${target.packageName}@${launcherVersion}\n${binaryPath}`);
  return 0;
}

function main({ packageName = "@microck/satelle", launcherPath = __filename } = {}) {
  try {
    const argumentsToForward = process.argv.slice(2);
    const repairOptions = nativeRepairOptions(argumentsToForward);
    if (repairOptions?.help) {
      console.log("Usage: satelle native repair [--dry-run]\n\nReinstall the exact native package through its package manager.\nLocal repair records an exact optional dependency in the owning project.\n\n  --dry-run   Show the owner and repair command without changing files\n  --no-color  Use plain output\n  -h, --help  Show this help");
      return;
    }
    const launchContext = detectForwardingContext({ packageName, launcherPath });
    const runtime = {
      platform: process.platform,
      arch: process.arch,
      libc: process.platform === "linux" ? detectLinuxLibc() : undefined,
    };
    const target = selectTarget(runtime);
    if (repairOptions) {
      process.exitCode = repairNativePackage(target, launchContext, repairOptions);
      return;
    }
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
    process.exitCode = error.exitCode;
  }
}

module.exports = {
  LauncherError,
  commandLine,
  detectForwardingContext,
  detectInstallationScope,
  detectLinuxLibc,
  detectPackageManager,
  discoverGlobalOwnership,
  executeNativeBinary,
  isSelfUpdate,
  main,
  nativeRepairOptions,
  nativeRepairPlan,
  packageInstallContext,
  packageInstallContextForCommand,
  resolveNativeBinary,
  selectTarget,
  verifyRepairedNativePackage,
};
