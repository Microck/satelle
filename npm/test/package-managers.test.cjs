"use strict";

const assert = require("node:assert/strict");
const { spawnSync } = require("node:child_process");
const {
  chmodSync,
  copyFileSync,
  cpSync,
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
const { pathToFileURL } = require("node:url");

const repositoryRoot = path.resolve(__dirname, "../..");
const sourceCanonicalRoot = path.join(repositoryRoot, "npm", "satelle");
const sourceUnscopedRoot = path.join(repositoryRoot, "npm", "satelle-unscoped");
const launcher = require(path.join(sourceCanonicalRoot, "lib", "launcher.cjs"));
const platformMatrix = require(path.join(sourceCanonicalRoot, "platforms.json"));

const packageManagers = [
  {
    name: "npm",
    executable: process.platform === "win32" ? "npm.cmd" : "npm",
    installArguments: ["install", "--ignore-scripts", "--no-audit", "--no-fund"],
  },
  {
    name: "pnpm",
    executable: process.platform === "win32" ? "pnpm.cmd" : "pnpm",
    installArguments: ["install", "--ignore-scripts", "--reporter=silent"],
  },
  {
    name: "bun",
    executable: process.platform === "win32" ? "bun.exe" : "bun",
    installArguments: ["install", "--ignore-scripts", "--no-progress", "--no-summary"],
  },
];

function spawnCommand(executable, arguments_, options = {}) {
  return spawnSync(
    executable,
    arguments_,
    process.platform === "win32" ? { ...options, shell: true } : options,
  );
}

function readJson(filePath) {
  return JSON.parse(readFileSync(filePath, "utf8"));
}

function writeJson(filePath, value) {
  writeFileSync(filePath, `${JSON.stringify(value, null, 2)}\n`);
}

function commandIsAvailable(packageManager) {
  const version = spawnCommand(packageManager.executable, ["--version"], { encoding: "utf8" });
  return version.status === 0;
}

function packFixturePackage(packageRoot, packDestination) {
  const npmExecutable = process.platform === "win32" ? "npm.cmd" : "npm";
  const packed = spawnCommand(
    npmExecutable,
    ["pack", "--json", "--silent", "--ignore-scripts", "--pack-destination", packDestination],
    { cwd: packageRoot, encoding: "utf8" },
  );
  assert.equal(packed.status, 0, `${packageRoot}\n${packed.stdout}\n${packed.stderr}`);
  const [{ filename }] = JSON.parse(packed.stdout);
  return path.join(packDestination, filename);
}

function currentTargetEntry() {
  const target = launcher.selectTarget({
    platform: process.platform,
    arch: process.arch,
    libc: process.platform === "linux" ? launcher.detectLinuxLibc() : undefined,
  });
  return Object.entries(platformMatrix).find(
    ([, candidate]) => candidate.packageName === target.packageName,
  );
}

function stagePackages(fixtureRoot) {
  const packagesRoot = path.join(fixtureRoot, "packages");
  const packsRoot = path.join(fixtureRoot, "packs");
  const canonicalRoot = path.join(packagesRoot, "satelle");
  const unscopedRoot = path.join(packagesRoot, "satelle-unscoped");
  mkdirSync(packsRoot);
  cpSync(sourceCanonicalRoot, canonicalRoot, { recursive: true });
  cpSync(sourceUnscopedRoot, unscopedRoot, { recursive: true });

  const [currentTargetId, currentTarget] = currentTargetEntry();
  for (const targetId of Object.keys(platformMatrix)) {
    const nativeRoot = path.join(packagesRoot, `satelle-${targetId}`);
    mkdirSync(nativeRoot, { recursive: true });
    const nativeManifest = readJson(
      path.join(repositoryRoot, "npm", `satelle-${targetId}`, "package.json"),
    );
    // Installation smoke tests do not run release-time prepack guards.
    delete nativeManifest.scripts;
    writeJson(path.join(nativeRoot, "package.json"), nativeManifest);
    if (targetId === currentTargetId) {
      const nativeBinaryPath = path.join(nativeRoot, currentTarget.binaryPath);
      mkdirSync(path.dirname(nativeBinaryPath), { recursive: true });
      copyFileSync(process.execPath, nativeBinaryPath);
      if (process.platform !== "win32") {
        chmodSync(nativeBinaryPath, 0o755);
      }
    }
  }

  const canonicalManifest = readJson(path.join(canonicalRoot, "package.json"));
  for (const [targetId, target] of Object.entries(platformMatrix)) {
    const nativeArtifact = packFixturePackage(
      path.join(packagesRoot, `satelle-${targetId}`),
      packsRoot,
    );
    canonicalManifest.optionalDependencies[target.packageName] = pathToFileURL(nativeArtifact).href;
  }
  writeJson(path.join(canonicalRoot, "package.json"), canonicalManifest);
  const canonicalArtifact = packFixturePackage(canonicalRoot, packsRoot);
  const unscopedManifest = readJson(path.join(unscopedRoot, "package.json"));
  unscopedManifest.dependencies["@microck/satelle"] = pathToFileURL(canonicalArtifact).href;
  writeJson(path.join(unscopedRoot, "package.json"), unscopedManifest);
  return packFixturePackage(unscopedRoot, packsRoot);
}

function installedBin(consumerRoot) {
  const binRoot = path.join(consumerRoot, "node_modules", ".bin");
  const names =
    process.platform === "win32" ? ["satelle.cmd", "satelle.exe", "satelle"] : ["satelle"];
  return names.map((name) => path.join(binRoot, name)).find(existsSync);
}

test("npm, pnpm, and Bun install and execute the unscoped forwarding package", (context) => {
  const fixtureRoot = mkdtempSync(path.join(tmpdir(), "satelle-package-managers-"));
  context.after(() => rmSync(fixtureRoot, { recursive: true, force: true }));
  const unscopedArtifact = stagePackages(fixtureRoot);
  const requiredManagers = new Set(
    (process.env.SATELLE_REQUIRED_PACKAGE_MANAGERS || "npm")
      .split(",")
      .map((name) => name.trim())
      .filter(Boolean),
  );

  for (const packageManager of packageManagers) {
    const available = commandIsAvailable(packageManager);
    if (!available) {
      assert.equal(
        requiredManagers.has(packageManager.name),
        false,
        `${packageManager.name} is required but is not installed`,
      );
      continue;
    }

    const consumerRoot = path.join(fixtureRoot, `consumer-${packageManager.name}`);
    mkdirSync(consumerRoot);
    writeJson(path.join(consumerRoot, "package.json"), {
      name: `satelle-${packageManager.name}-consumer`,
      version: "1.0.0",
      private: true,
      dependencies: {
        satelle: pathToFileURL(unscopedArtifact).href,
      },
    });

    const install = spawnCommand(packageManager.executable, packageManager.installArguments, {
      cwd: consumerRoot,
      encoding: "utf8",
      env: {
        ...process.env,
        BUN_CONFIG_REGISTRY: "http://127.0.0.1:9/",
        NO_COLOR: "1",
        npm_config_registry: "http://127.0.0.1:9/",
      },
    });
    assert.equal(
      install.status,
      0,
      `${packageManager.name} install failed\n${install.stdout}\n${install.stderr}`,
    );

    const probeScript = path.join(consumerRoot, "native-probe.cjs");
    writeFileSync(
      probeScript,
      'process.stdout.write(JSON.stringify(process.argv.slice(2))); process.exit(23);\n',
    );
    const executable = installedBin(consumerRoot);
    assert.ok(executable, `${packageManager.name} did not create the satelle executable`);
    const execution = spawnSync(executable, [probeScript, packageManager.name, "unscoped"], {
      cwd: consumerRoot,
      encoding: "utf8",
      shell: process.platform === "win32",
    });
    assert.equal(execution.status, 23, `${packageManager.name}: ${execution.stderr}`);
    assert.equal(execution.stdout, JSON.stringify([packageManager.name, "unscoped"]));
    assert.equal(execution.stderr, "");
  }
});
