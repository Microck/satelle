"use strict";

const assert = require("node:assert/strict");
const { spawnSync } = require("node:child_process");
const { createHash } = require("node:crypto");
const { once } = require("node:events");
const {
  chmodSync,
  copyFileSync,
  cpSync,
  existsSync,
  mkdtempSync,
  mkdirSync,
  readFileSync,
  realpathSync,
  rmSync,
  writeFileSync,
} = require("node:fs");
const { createRequire } = require("node:module");
const { tmpdir } = require("node:os");
const path = require("node:path");
const test = require("node:test");
const { Worker } = require("node:worker_threads");

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

const oneShotRunners = [
  {
    name: "npm exec",
    requiredManager: "npm",
    executable: process.platform === "win32" ? "npm.cmd" : "npm",
    arguments: (packageReference, commandArguments) => [
      "exec",
      `--package=${packageReference}`,
      "--",
      "satelle",
      ...commandArguments,
    ],
  },
  {
    name: "npx",
    requiredManager: "npm",
    executable: process.platform === "win32" ? "npx.cmd" : "npx",
    arguments: (packageReference, commandArguments) => [
      `--package=${packageReference}`,
      "--",
      "satelle",
      ...commandArguments,
    ],
  },
  {
    name: "pnpm dlx",
    requiredManager: "pnpm",
    executable: process.platform === "win32" ? "pnpm.cmd" : "pnpm",
    arguments: (packageReference, commandArguments) => [
      `--package=${packageReference}`,
      "dlx",
      "satelle",
      ...commandArguments,
    ],
  },
  {
    name: "bunx",
    requiredManager: "bun",
    executable: process.platform === "win32" ? "bunx.exe" : "bunx",
    requiredHelpOption: "--package",
    unsupportedMessage: "bunx one-shot execution requires Bun 1.3.14 or newer",
    arguments: (packageReference, commandArguments) => [
      "--silent",
      "--package",
      packageReference,
      "satelle",
      ...commandArguments,
    ],
  },
];

function spawnCommand(executable, arguments_, options = {}) {
  if (process.platform === "win32" && executable.toLowerCase().endsWith(".cmd")) {
    return spawnSync(
      process.env.ComSpec || "cmd.exe",
      ["/d", "/s", "/c", executable, ...arguments_],
      options,
    );
  }

  return spawnSync(executable, arguments_, options);
}

function readJson(filePath) {
  return JSON.parse(readFileSync(filePath, "utf8"));
}

function writeJson(filePath, value) {
  writeFileSync(filePath, `${JSON.stringify(value, null, 2)}\n`);
}

function localTarballReference(artifactPath) {
  return `file:${artifactPath.split(path.sep).join("/")}`;
}

function commandIsAvailable(packageManager) {
  const version = spawnCommand(packageManager.executable, ["--version"], { encoding: "utf8" });
  if (version.status !== 0 || !packageManager.requiredHelpOption) {
    return version.status === 0;
  }

  const help = spawnCommand(packageManager.executable, ["--help"], { encoding: "utf8" });
  return `${help.stdout}\n${help.stderr}`.includes(packageManager.requiredHelpOption);
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
      const digest = createHash("sha256").update(readFileSync(nativeBinaryPath)).digest("hex");
      writeFileSync(path.join(nativeRoot, "SHA256SUMS"), `${digest}  ${currentTarget.binaryPath}\n`);
    }
  }

  const canonicalManifest = readJson(path.join(canonicalRoot, "package.json"));
  for (const [targetId, target] of Object.entries(platformMatrix)) {
    const nativeArtifact = packFixturePackage(
      path.join(packagesRoot, `satelle-${targetId}`),
      packsRoot,
    );
    canonicalManifest.optionalDependencies[target.packageName] =
      localTarballReference(nativeArtifact);
  }
  writeJson(path.join(canonicalRoot, "package.json"), canonicalManifest);
  const canonicalArtifact = packFixturePackage(canonicalRoot, packsRoot);
  const unscopedManifest = readJson(path.join(unscopedRoot, "package.json"));
  unscopedManifest.dependencies["@microck/satelle"] = localTarballReference(canonicalArtifact);
  writeJson(path.join(unscopedRoot, "package.json"), unscopedManifest);
  const unscopedArtifact = packFixturePackage(unscopedRoot, packsRoot);
  const nativeArtifact = canonicalManifest.optionalDependencies[currentTarget.packageName].slice("file:".length);
  return { canonicalArtifact, unscopedArtifact, nativeArtifact };
}

function installedBin(consumerRoot) {
  const binRoot = path.join(consumerRoot, "node_modules", ".bin");
  const names =
    process.platform === "win32" ? ["satelle.cmd", "satelle.exe", "satelle"] : ["satelle"];
  return names.map((name) => path.join(binRoot, name)).find(existsSync);
}

test("npm, pnpm, and Bun install and execute the unscoped forwarding package", (context) => {
  const fixtureRoot = mkdtempSync(path.join(tmpdir(), "satelle-package-managers-"));
  context.after(() =>
    rmSync(fixtureRoot, { recursive: true, force: true, maxRetries: 20, retryDelay: 100 }),
  );
  const { unscopedArtifact } = stagePackages(fixtureRoot);
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
        satelle: `file:${path.relative(consumerRoot, unscopedArtifact).split(path.sep).join("/")}`,
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
    const execution = spawnCommand(executable, [probeScript, packageManager.name, "unscoped"], {
      cwd: consumerRoot,
      encoding: "utf8",
    });
    assert.equal(execution.status, 23, `${packageManager.name}: ${execution.stderr}`);
    assert.equal(execution.stdout, JSON.stringify([packageManager.name, "unscoped"]));
    assert.equal(execution.stderr, "");

    const canonicalLauncherPath = createRequire(
      realpathSync(path.join(consumerRoot, "node_modules", "satelle", "package.json")),
    ).resolve("@microck/satelle/launcher");
    const nativePackageManifest = createRequire(canonicalLauncherPath).resolve(
      `${currentTargetEntry()[1].packageName}/package.json`,
    );
    rmSync(path.dirname(nativePackageManifest), { recursive: true, force: true });
    const missingNativeExecution = spawnCommand(executable, [], {
      cwd: consumerRoot,
      encoding: "utf8",
      env: Object.fromEntries(
        Object.entries(process.env).filter(
          ([name]) => name !== "npm_config_user_agent" && name !== "npm_execpath",
        ),
      ),
    });
    assert.equal(missingNativeExecution.status, 1, packageManager.name);
    assert.match(
      missingNativeExecution.stderr,
      packageManager.name === "npm"
        ? /npm install satelle --include=optional/
        : new RegExp(`${packageManager.name} add satelle`),
      packageManager.name,
    );
  }
});

test("npm exec, npx, pnpm dlx, and bunx execute the canonical package", (context) => {
  const fixtureRoot = mkdtempSync(path.join(tmpdir(), "satelle-one-shot-"));
  context.after(() =>
    rmSync(fixtureRoot, { recursive: true, force: true, maxRetries: 20, retryDelay: 100 }),
  );
  const { canonicalArtifact } = stagePackages(fixtureRoot);
  const packageReference = localTarballReference(canonicalArtifact);
  const requiredManagers = new Set(
    (process.env.SATELLE_REQUIRED_PACKAGE_MANAGERS || "npm")
      .split(",")
      .map((name) => name.trim())
      .filter(Boolean),
  );
  const probeScript = path.join(fixtureRoot, "native-probe.cjs");
  const stderrSentinel = "satelle-native-stderr";
  writeFileSync(
    probeScript,
    `process.stderr.write(${JSON.stringify(stderrSentinel)}); process.stdout.write(JSON.stringify(process.argv.slice(2))); process.exit(23);\n`,
  );

  for (const runner of oneShotRunners) {
    const available = commandIsAvailable(runner);
    if (!available) {
      assert.equal(
        requiredManagers.has(runner.requiredManager),
        false,
        runner.unsupportedMessage || `${runner.name} is required but is not installed`,
      );
      continue;
    }

    const runnerRoot = path.join(fixtureRoot, runner.name.replaceAll(" ", "-"));
    const tempRoot = path.join(runnerRoot, "tmp");
    mkdirSync(tempRoot, { recursive: true });
    const expectedArguments = [runner.name, "value with spaces", "--looks-like-an-option"];
    const execution = spawnCommand(
      runner.executable,
      runner.arguments(packageReference, [probeScript, ...expectedArguments]),
      {
        cwd: runnerRoot,
        encoding: "utf8",
        env: {
          ...process.env,
          BUN_CONFIG_REGISTRY: "http://127.0.0.1:9/",
          BUN_INSTALL_CACHE_DIR: path.join(runnerRoot, "bun-cache"),
          NO_COLOR: "1",
          TEMP: tempRoot,
          TMP: tempRoot,
          TMPDIR: tempRoot,
          npm_config_cache: path.join(runnerRoot, "npm-cache"),
          npm_config_loglevel: "error",
          npm_config_registry: "http://127.0.0.1:9/",
          PNPM_CONFIG_REGISTRY: "http://127.0.0.1:9/",
          PNPM_CONFIG_REPORTER: "silent",
          pnpm_config_store_dir: path.join(runnerRoot, "pnpm-store"),
        },
      },
    );
    assert.equal(
      execution.status,
      23,
      `${runner.name} execution failed\n${execution.stdout}\n${execution.stderr}`,
    );
    assert.equal(execution.stdout, JSON.stringify(expectedArguments), runner.name);
    assert.equal(execution.stderr, stderrSentinel, runner.name);
  }
});


async function fixtureRegistry(context, nativeArtifact, manifest) {
  // Serve an actual npm pack through a local registry while synchronous package
  // managers run in the parent. The worker owns the HTTP server's event loop.
  const worker = new Worker(`
    const { createServer } = require("node:http");
    const { readFileSync } = require("node:fs");
    const { createHash } = require("node:crypto");
    const { parentPort, workerData } = require("node:worker_threads");
    const archive = readFileSync(workerData.nativeArtifact);
    const integrity = "sha512-" + createHash("sha512").update(archive).digest("base64");
    const manifest = workerData.manifest;
    const server = createServer((request, response) => {
      const pathname = decodeURIComponent(request.url.split("?", 1)[0]);
      if (pathname === "/native.tgz") {
        response.writeHead(200, { "Content-Type": "application/octet-stream", "Content-Length": archive.length });
        response.end(archive);
      } else if (pathname === "/" + manifest.name) {
        const version = { ...manifest, dist: { integrity, tarball: "http://127.0.0.1:" + server.address().port + "/native.tgz" } };
        response.writeHead(200, { "Content-Type": "application/json" });
        response.end(JSON.stringify({ name: manifest.name, "dist-tags": { latest: manifest.version }, versions: { [manifest.version]: version }, time: { [manifest.version]: "2020-01-01T00:00:00.000Z" } }));
      } else {
        response.writeHead(404); response.end("unknown fixture package");
      }
    });
    server.listen(0, "127.0.0.1", () => parentPort.postMessage(server.address().port));
  `, { eval: true, workerData: { nativeArtifact, manifest } });
  context.after(() => worker.terminate());
  const [port] = await once(worker, "message");
  return `http://127.0.0.1:${port}/`;
}

test("native repair uses real package managers to restore a missing native dependency", async (context) => {
  const fixtureRoot = mkdtempSync(path.join(tmpdir(), "satelle-native-repair-managers-"));
  context.after(() => rmSync(fixtureRoot, { recursive: true, force: true, maxRetries: 20, retryDelay: 100 }));
  const { unscopedArtifact, nativeArtifact } = stagePackages(fixtureRoot);
  const [targetId, target] = currentTargetEntry();
  const nativeManifest = readJson(path.join(fixtureRoot, "packages", `satelle-${targetId}`, "package.json"));
  const registry = await fixtureRegistry(context, nativeArtifact, nativeManifest);
  const requiredManagers = new Set((process.env.SATELLE_REQUIRED_PACKAGE_MANAGERS || "npm").split(","));
  for (const manager of packageManagers) {
    if (!commandIsAvailable(manager)) {
      assert.equal(requiredManagers.has(manager.name), false, `${manager.name} is required`);
      continue;
    }
    const consumerRoot = path.join(fixtureRoot, `consumer-${manager.name}`);
    mkdirSync(consumerRoot);
    const manifestPath = path.join(consumerRoot, "package.json");
    writeJson(manifestPath, {
      name: `satelle-native-repair-${manager.name}`,
      private: true,
      dependencies: { satelle: localTarballReference(unscopedArtifact) },
    });
    const environment = {
      ...process.env,
      npm_config_registry: registry,
      BUN_CONFIG_REGISTRY: registry,
      PNPM_CONFIG_REGISTRY: registry,
      npm_config_cache: path.join(consumerRoot, "npm-cache"),
      BUN_INSTALL_CACHE_DIR: path.join(consumerRoot, "bun-cache"),
      pnpm_config_store_dir: path.join(consumerRoot, "pnpm-store"),
      npm_config_user_agent: "OpenAI File Downloader, XaiImageApiFetch/1.0",
      NO_COLOR: "1",
    };
    const installed = spawnCommand(manager.executable, manager.installArguments, {
      cwd: consumerRoot, encoding: "utf8", env: environment,
    });
    assert.equal(installed.status, 0, `${manager.name}: ${installed.stdout}\n${installed.stderr}`);
    const executable = installedBin(consumerRoot);
    assert.ok(executable);
    const canonicalLauncher = createRequire(
      realpathSync(path.join(consumerRoot, "node_modules", "satelle", "package.json")),
    ).resolve("@microck/satelle/launcher");
    const nativeManifestPath = createRequire(canonicalLauncher).resolve(`${target.packageName}/package.json`);
    rmSync(path.dirname(nativeManifestPath), { recursive: true, force: true });
    const before = readFileSync(manifestPath);
    const preview = spawnCommand(executable, ["native", "repair", "--dry-run"], {
      cwd: consumerRoot, encoding: "utf8", env: environment,
    });
    assert.equal(preview.status, 0, `${manager.name}: ${preview.stderr}`);
    assert.ok(preview.stdout.includes(`Owner: ${manager.name} (local)`), preview.stdout);
    assert.ok(preview.stdout.includes(`${target.packageName}@${nativeManifest.version}`), preview.stdout);
    assert.ok(before.equals(readFileSync(manifestPath)), "dry-run preserves the owning manifest");
    assert.equal(existsSync(nativeManifestPath), false, "dry-run does not recreate native files");
    const repaired = spawnCommand(executable, ["native", "repair"], {
      cwd: consumerRoot, encoding: "utf8", env: environment, timeout: 120_000,
    });
    assert.equal(repaired.status, 0, `${manager.name}: ${repaired.stdout}\n${repaired.stderr}`);
    assert.match(repaired.stdout, /^Repaired @microck\/satelle-/);
    const installedManifest = readJson(manifestPath);
    assert.equal(installedManifest.optionalDependencies[target.packageName], nativeManifest.version);
    assert.equal(installedManifest.dependencies.satelle, localTarballReference(unscopedArtifact));
    assert.ok(launcher.verifyRepairedNativePackage(target, path.dirname(canonicalLauncher)));
    if (manager.name === "npm") {
      // A failed optional fetch may still make npm exit zero. Remove the npm
      // executable from PATH to exercise an actual package-manager launch failure.
      const emptyPath = path.join(consumerRoot, "empty-path");
      mkdirSync(emptyPath);
      const installedLauncher = path.join(consumerRoot, "node_modules", "satelle", "bin", "satelle.cjs");
      const failed = spawnSync(process.execPath, [installedLauncher, "native", "repair"], {
        cwd: consumerRoot, encoding: "utf8", timeout: 30_000,
        env: { ...environment, PATH: emptyPath },
      });
      assert.equal(failed.status, 1, failed.stderr);
      assert.equal(failed.stdout, "");
      assert.match(failed.stderr, /native-repair-failed/);
    }
  }
});
