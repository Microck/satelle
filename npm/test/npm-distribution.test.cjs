"use strict";

const assert = require("node:assert/strict");
const { execFileSync, spawnSync } = require("node:child_process");
const {
  copyFileSync,
  mkdtempSync,
  mkdirSync,
  readFileSync,
  realpathSync,
  rmSync,
  writeFileSync,
} = require("node:fs");
const { tmpdir } = require("node:os");
const path = require("node:path");
const test = require("node:test");

const repositoryRoot = path.resolve(__dirname, "../..");
const canonicalPackageRoot = path.join(repositoryRoot, "npm", "satelle");
const publicLauncher = require(path.join(canonicalPackageRoot, "bin", "satelle.cjs"));
const launcher = require(path.join(canonicalPackageRoot, "lib", "launcher.cjs"));
const platformMatrix = require(path.join(canonicalPackageRoot, "platforms.json"));

const expectedTargets = {
  "darwin-arm64": {
    os: "darwin",
    cpu: "arm64",
    rustTarget: "aarch64-apple-darwin",
  },
  "darwin-x64": {
    os: "darwin",
    cpu: "x64",
    rustTarget: "x86_64-apple-darwin",
  },
  "linux-arm64-gnu": {
    os: "linux",
    cpu: "arm64",
    libc: "glibc",
    rustTarget: "aarch64-unknown-linux-gnu",
  },
  "linux-x64-gnu": {
    os: "linux",
    cpu: "x64",
    libc: "glibc",
    rustTarget: "x86_64-unknown-linux-gnu",
  },
  "win32-arm64-msvc": {
    os: "win32",
    cpu: "arm64",
    rustTarget: "aarch64-pc-windows-msvc",
  },
  "win32-x64-msvc": {
    os: "win32",
    cpu: "x64",
    rustTarget: "x86_64-pc-windows-msvc",
  },
};

function readJson(filePath) {
  return JSON.parse(readFileSync(filePath, "utf8"));
}

function npmSpawnOptions(options = {}) {
  return process.platform === "win32" ? { ...options, shell: true } : options;
}

function packDryRun(packageRoot) {
  const npmExecutable = process.platform === "win32" ? "npm.cmd" : "npm";
  const output = execFileSync(
    npmExecutable,
    ["pack", "--dry-run", "--json", packageRoot],
    npmSpawnOptions({ cwd: repositoryRoot, encoding: "utf8" }),
  );
  return JSON.parse(output)[0];
}

function packPackage(packageRoot, packDestination) {
  const npmExecutable = process.platform === "win32" ? "npm.cmd" : "npm";
  const output = execFileSync(
    npmExecutable,
    ["pack", "--json", "--silent", "--pack-destination", packDestination, packageRoot],
    npmSpawnOptions({
      cwd: repositoryRoot,
      encoding: "utf8",
      env: { ...process.env, npm_config_ignore_scripts: "false" },
    }),
  );
  return JSON.parse(output)[0];
}

test("the platform matrix exactly covers the six MVP Rust targets", () => {
  assert.deepEqual(Object.keys(platformMatrix).sort(), Object.keys(expectedTargets).sort());

  for (const [targetId, expected] of Object.entries(expectedTargets)) {
    assert.deepEqual(
      {
        os: platformMatrix[targetId].os,
        cpu: platformMatrix[targetId].cpu,
        ...(platformMatrix[targetId].libc ? { libc: platformMatrix[targetId].libc } : {}),
        rustTarget: platformMatrix[targetId].rustTarget,
      },
      expected,
    );
    assert.equal(platformMatrix[targetId].packageName, `@microck/satelle-${targetId}`);
    assert.equal(
      platformMatrix[targetId].binaryPath,
      targetId.startsWith("win32-") ? "bin/satelle.exe" : "bin/satelle",
    );
  }
});

test("runtime selection returns the exact matching package", () => {
  for (const [targetId, target] of Object.entries(platformMatrix)) {
    assert.equal(
      launcher.selectTarget({ platform: target.os, arch: target.cpu, libc: target.libc }),
      target,
      targetId,
    );
  }
});

test("unsupported runtimes fail with a typed error and never select a download fallback", () => {
  for (const runtime of [
    { platform: "linux", arch: "x64", libc: "musl" },
    { platform: "linux", arch: "arm", libc: "glibc" },
    { platform: "freebsd", arch: "x64" },
    { platform: "win32", arch: "ia32" },
  ]) {
    assert.throws(
      () => launcher.selectTarget(runtime),
      (error) => {
        assert.equal(error.code, "unsupported-local-platform");
        assert.match(error.message, /No Satelle native package is published/);
        assert.doesNotMatch(error.message, /download/i);
        return true;
      },
    );
  }
});

test("native package resolution returns the installed binary", (context) => {
  const fixtureRoot = mkdtempSync(path.join(tmpdir(), "satelle-native-package-"));
  context.after(() => rmSync(fixtureRoot, { recursive: true, force: true }));
  const target = platformMatrix["linux-x64-gnu"];
  const packageRoot = path.join(fixtureRoot, "node_modules", "@microck", "satelle-linux-x64-gnu");
  const binaryPath = path.join(packageRoot, "bin", "satelle");
  mkdirSync(path.dirname(binaryPath), { recursive: true });
  writeFileSync(
    path.join(packageRoot, "package.json"),
    JSON.stringify({ name: target.packageName, version: "0.1.0" }),
  );
  writeFileSync(binaryPath, "fixture");

  assert.equal(
    realpathSync(launcher.resolveNativeBinary(target, fixtureRoot, undefined, "0.1.0")),
    realpathSync(binaryPath),
  );
});

test("native package resolution rejects an ancestor package from another version", (context) => {
  const fixtureRoot = mkdtempSync(path.join(tmpdir(), "satelle-native-version-"));
  context.after(() => rmSync(fixtureRoot, { recursive: true, force: true }));
  const target = platformMatrix["linux-x64-gnu"];
  const packageRoot = path.join(fixtureRoot, "node_modules", "@microck", "satelle-linux-x64-gnu");
  const nestedLauncherRoot = path.join(
    fixtureRoot,
    "node_modules",
    "consumer",
    "node_modules",
    "@microck",
    "satelle",
  );
  mkdirSync(path.join(packageRoot, "bin"), { recursive: true });
  mkdirSync(nestedLauncherRoot, { recursive: true });
  writeFileSync(
    path.join(packageRoot, "package.json"),
    JSON.stringify({ name: target.packageName, version: "0.1.0" }),
  );
  writeFileSync(path.join(packageRoot, "bin", "satelle"), "stale fixture");

  assert.throws(
    () => launcher.resolveNativeBinary(target, nestedLauncherRoot, undefined, "0.2.0"),
    (error) => error.code === "native-binary-package-missing",
  );
});

test("a missing native package produces typed package-manager-specific recovery guidance", (context) => {
  const target = platformMatrix["linux-x64-gnu"];
  const fixtureRoot = mkdtempSync(path.join(tmpdir(), "satelle-missing-package-"));
  context.after(() => rmSync(fixtureRoot, { recursive: true, force: true }));

  for (const [recoveryContext, expectedCommand] of [
    [
      { packageManager: "npm", packageName: "@microck/satelle", installScope: "local" },
      "npm install @microck/satelle --include=optional",
    ],
    [
      { packageManager: "pnpm", packageName: "@microck/satelle", installScope: "local" },
      "pnpm add @microck/satelle",
    ],
    [
      { packageManager: "bun", packageName: "@microck/satelle", installScope: "local" },
      "bun add @microck/satelle",
    ],
    [
      { packageManager: "npm", packageName: "satelle", installScope: "global" },
      "npm install --global satelle --include=optional",
    ],
    [
      { packageManager: "pnpm", packageName: "satelle", installScope: "global" },
      "pnpm add --global satelle",
    ],
    [
      { packageManager: "bun", packageName: "satelle", installScope: "global" },
      "bun add --global satelle",
    ],
  ]) {
    assert.throws(
      () => launcher.resolveNativeBinary(target, fixtureRoot, recoveryContext),
      (error) => {
        assert.equal(error.code, "native-binary-package-missing");
        assert.match(error.message, new RegExp(target.packageName.replace("/", "\\/")));
        assert.match(error.message, new RegExp(expectedCommand.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")));
        assert.match(error.message, /without omitting optional dependencies/);
        assert.match(error.message, /direct native binary/);
        return true;
      },
    );
  }
});

test("package-manager detection recognizes npm, pnpm, and Bun owners", (context) => {
  assert.equal(launcher.detectPackageManager({ userAgent: "npm/11.6.2 node/v24" }), "npm");
  assert.equal(launcher.detectPackageManager({ execPath: "/usr/local/bin/pnpm.cjs" }), "pnpm");
  assert.equal(
    launcher.detectPackageManager({
      launcherPath: "/home/me/.bun/install/global/node_modules/satelle/bin/satelle.cjs",
    }),
    "bun",
  );
  assert.equal(launcher.detectPackageManager({ launcherPath: "/tmp/custom/satelle.cjs" }), undefined);
  assert.equal(
    launcher.detectPackageManager({
      launcherPath: "/home/ubuntu/project/node_modules/satelle/bin/satelle.cjs",
    }),
    undefined,
  );

  const fixtureRoot = mkdtempSync(path.join(tmpdir(), "satelle-manager-lockfiles-"));
  context.after(() => rmSync(fixtureRoot, { recursive: true, force: true }));
  const launcherPath = path.join(fixtureRoot, "node_modules", "satelle", "bin", "satelle.cjs");
  mkdirSync(path.dirname(launcherPath), { recursive: true });
  for (const [lockfile, expectedManager] of [
    ["bun.lock", "bun"],
    ["pnpm-lock.yaml", "pnpm"],
    ["package-lock.json", "npm"],
  ]) {
    writeFileSync(path.join(fixtureRoot, lockfile), "fixture");
    assert.equal(launcher.detectPackageManager({ launcherPath }), expectedManager, lockfile);
    rmSync(path.join(fixtureRoot, lockfile));
  }
});

test("installation scope detection recognizes global and local package layouts", () => {
  for (const launcherPath of [
    "/usr/local/lib/node_modules/@microck/satelle/bin/satelle.cjs",
    "/home/me/.bun/install/global/node_modules/satelle/bin/satelle.cjs",
    "/home/me/.local/share/pnpm/global/5/node_modules/satelle/bin/satelle.cjs",
    "C:\\Users\\me\\AppData\\Roaming\\npm\\node_modules\\satelle\\bin\\satelle.cjs",
  ]) {
    assert.equal(launcher.detectInstallationScope(launcherPath), "global", launcherPath);
  }
  assert.equal(
    launcher.detectInstallationScope("/home/me/project/node_modules/satelle/bin/satelle.cjs"),
    "local",
  );
  assert.equal(launcher.detectInstallationScope("/opt/satelle/bin/satelle.cjs"), undefined);
});

test("canonical launches detect an installed unscoped forwarding package", (context) => {
  const fixtureRoot = mkdtempSync(path.join(tmpdir(), "satelle-forwarding-context-"));
  context.after(() => rmSync(fixtureRoot, { recursive: true, force: true }));
  const canonicalLauncher = path.join(
    fixtureRoot,
    "node_modules",
    "@microck",
    "satelle",
    "bin",
    "satelle.cjs",
  );
  const unscopedRoot = path.join(fixtureRoot, "node_modules", "satelle");
  const unscopedLauncher = path.join(unscopedRoot, "bin", "satelle.cjs");
  mkdirSync(path.dirname(canonicalLauncher), { recursive: true });
  mkdirSync(path.dirname(unscopedLauncher), { recursive: true });
  writeFileSync(unscopedLauncher, "fixture");
  writeFileSync(
    path.join(unscopedRoot, "package.json"),
    JSON.stringify({
      name: "satelle",
      dependencies: { "@microck/satelle": "0.1.0" },
    }),
  );

  assert.deepEqual(
    launcher.detectForwardingContext({
      packageName: "@microck/satelle",
      launcherPath: canonicalLauncher,
    }),
    { packageName: "satelle", launcherPath: unscopedLauncher },
  );
});

test("Linux libc detection distinguishes glibc, musl, and unknown runtimes", () => {
  assert.equal(
    launcher.detectLinuxLibc({
      report: { getReport: () => ({ header: { glibcVersionRuntime: "2.35" } }) },
    }),
    "glibc",
  );
  assert.equal(
    launcher.detectLinuxLibc({
      report: {
        getReport: () => ({
          header: {},
          sharedObjects: ["/lib/ld-musl-aarch64.so.1"],
        }),
      },
    }),
    "musl",
  );
  assert.equal(launcher.detectLinuxLibc({}), undefined);
});

test("native execution forwards arguments and returns the child exit status", (context) => {
  const fixtureRoot = mkdtempSync(path.join(tmpdir(), "satelle-exec-"));
  context.after(() => rmSync(fixtureRoot, { recursive: true, force: true }));
  const fixtureScript = path.join(fixtureRoot, "native-fixture.cjs");
  const outputPath = path.join(fixtureRoot, "arguments.json");
  writeFileSync(
    fixtureScript,
    [
      'const { writeFileSync } = require("node:fs");',
      "const [outputPath, ...forwardedArguments] = process.argv.slice(2);",
      "writeFileSync(outputPath, JSON.stringify(forwardedArguments));",
      "process.exit(23);",
      "",
    ].join("\n"),
  );

  const status = launcher.executeNativeBinary(process.execPath, [
    fixtureScript,
    outputPath,
    "run",
    "--command",
    "two words",
  ]);

  assert.equal(status, 23);
  assert.deepEqual(readJson(outputPath), ["run", "--command", "two words"]);
});

test(
  "native execution preserves signal termination",
  { skip: process.platform === "win32" },
  (context) => {
    const fixtureRoot = mkdtempSync(path.join(tmpdir(), "satelle-signal-"));
    context.after(() => rmSync(fixtureRoot, { recursive: true, force: true }));
    const wrapperScript = path.join(fixtureRoot, "signal-wrapper.cjs");
    writeFileSync(
      wrapperScript,
      [
        `const { executeNativeBinary } = require(${JSON.stringify(
          path.join(canonicalPackageRoot, "lib", "launcher.cjs"),
        )});`,
        'executeNativeBinary(process.execPath, ["-e", "process.kill(process.pid, \'SIGTERM\')"]);',
        "",
      ].join("\n"),
    );

    const child = spawnSync(process.execPath, [wrapperScript]);
    assert.equal(child.status, null);
    assert.equal(child.signal, "SIGTERM");
  },
);

test("package manifests align versions, constraints, dependencies, and executable ownership", () => {
  const rootManifest = readJson(path.join(repositoryRoot, "package.json"));
  const canonicalManifest = readJson(path.join(canonicalPackageRoot, "package.json"));
  const unscopedManifest = readJson(path.join(repositoryRoot, "npm", "satelle-unscoped", "package.json"));

  assert.equal(rootManifest.private, true);
  // Native packages have mutually exclusive os/cpu constraints. Treating them as npm
  // workspaces makes installation fail on every platform except their own.
  assert.equal(rootManifest.workspaces, undefined);
  assert.equal(canonicalManifest.name, "@microck/satelle");
  assert.equal(canonicalManifest.bin.satelle, "bin/satelle.cjs");
  assert.deepEqual(canonicalManifest.exports, { "./launcher": "./bin/satelle.cjs" });
  assert.deepEqual(Object.keys(publicLauncher), ["main"]);
  assert.equal(canonicalManifest.scripts?.postinstall, undefined);
  assert.equal(unscopedManifest.name, "satelle");
  assert.deepEqual(unscopedManifest.dependencies, {
    "@microck/satelle": canonicalManifest.version,
  });
  assert.equal(unscopedManifest.optionalDependencies, undefined);
  assert.equal(unscopedManifest.bin.satelle, "bin/satelle.cjs");

  const expectedOptionalDependencies = {};
  for (const [targetId, target] of Object.entries(platformMatrix)) {
    expectedOptionalDependencies[target.packageName] = canonicalManifest.version;
    const nativeManifest = readJson(
      path.join(repositoryRoot, "npm", `satelle-${targetId}`, "package.json"),
    );
    assert.equal(nativeManifest.name, target.packageName);
    assert.equal(nativeManifest.version, canonicalManifest.version);
    assert.deepEqual(nativeManifest.os, [target.os]);
    assert.deepEqual(nativeManifest.cpu, [target.cpu]);
    assert.deepEqual(nativeManifest.libc, target.libc ? [target.libc] : undefined);
    assert.equal(nativeManifest.bin, undefined);
    assert.deepEqual(nativeManifest.files, [target.binaryPath]);
    assert.equal(nativeManifest.scripts.prepack, "node ../scripts/verify-native-package.cjs");
  }

  assert.deepEqual(canonicalManifest.optionalDependencies, expectedOptionalDependencies);
  assert.equal(unscopedManifest.version, canonicalManifest.version);
});

test("the unscoped executable preserves its forwarding context", (context) => {
  const fixtureRoot = mkdtempSync(path.join(tmpdir(), "satelle-unscoped-forwarder-"));
  context.after(() => rmSync(fixtureRoot, { recursive: true, force: true }));
  const unscopedBin = path.join(fixtureRoot, "node_modules", "satelle", "bin", "satelle.cjs");
  const canonicalRoot = path.join(fixtureRoot, "node_modules", "@microck", "satelle");
  mkdirSync(path.dirname(unscopedBin), { recursive: true });
  mkdirSync(canonicalRoot, { recursive: true });
  copyFileSync(
    path.join(repositoryRoot, "npm", "satelle-unscoped", "bin", "satelle.cjs"),
    unscopedBin,
  );
  writeFileSync(
    path.join(canonicalRoot, "package.json"),
    JSON.stringify({
      name: "@microck/satelle",
      exports: { "./launcher": "./launcher.cjs" },
    }),
  );
  writeFileSync(
    path.join(canonicalRoot, "launcher.cjs"),
    "module.exports = { main(options) { process.stdout.write(JSON.stringify(options)); } };\n",
  );

  const child = spawnSync(process.execPath, [unscopedBin], { encoding: "utf8" });
  assert.equal(child.status, 0);
  assert.deepEqual(JSON.parse(child.stdout), {
    packageName: "satelle",
    launcherPath: realpathSync(unscopedBin),
  });
  assert.equal(child.stderr, "");
});

test("npm pack includes only the intended launcher package files", () => {
  const canonicalPack = packDryRun(canonicalPackageRoot);
  const unscopedPack = packDryRun(path.join(repositoryRoot, "npm", "satelle-unscoped"));

  assert.deepEqual(
    canonicalPack.files.map(({ path: filePath }) => filePath).sort(),
    ["bin/satelle.cjs", "lib/launcher.cjs", "package.json", "platforms.json"],
  );
  assert.deepEqual(
    unscopedPack.files.map(({ path: filePath }) => filePath).sort(),
    ["bin/satelle.cjs", "package.json"],
  );
  if (process.platform !== "win32") {
    assert.equal(
      canonicalPack.files.find(({ path: filePath }) => filePath === "bin/satelle.cjs").mode,
      0o755,
    );
    assert.equal(
      unscopedPack.files.find(({ path: filePath }) => filePath === "bin/satelle.cjs").mode,
      0o755,
    );
  }
});

test("native packages fail closed when release assembly has not injected a binary", (context) => {
  const npmExecutable = process.platform === "win32" ? "npm.cmd" : "npm";
  const packDestination = mkdtempSync(path.join(tmpdir(), "satelle-broken-native-packs-"));
  context.after(() => rmSync(packDestination, { recursive: true, force: true }));

  for (const targetId of Object.keys(platformMatrix)) {
    const child = spawnSync(
      npmExecutable,
      [
        "pack",
        "--json",
        "--pack-destination",
        packDestination,
        path.join(repositoryRoot, "npm", `satelle-${targetId}`),
      ],
      npmSpawnOptions({
        cwd: repositoryRoot,
        encoding: "utf8",
        env: { ...process.env, npm_config_ignore_scripts: "false" },
      }),
    );
    assert.notEqual(child.status, 0, targetId);
    assert.match(`${child.stdout}\n${child.stderr}`, /native-package-invalid/, targetId);
  }
});

test("native package prepack accepts an assembled binary and includes it", (context) => {
  const fixtureRoot = mkdtempSync(path.join(tmpdir(), "satelle-native-pack-"));
  context.after(() => rmSync(fixtureRoot, { recursive: true, force: true }));
  const stagedNpmRoot = path.join(fixtureRoot, "npm");
  const stagedPackageRoot = path.join(stagedNpmRoot, "satelle-win32-x64-msvc");
  const stagedScriptsRoot = path.join(stagedNpmRoot, "scripts");
  const binaryPath = path.join(stagedPackageRoot, "bin", "satelle.exe");
  mkdirSync(path.dirname(binaryPath), { recursive: true });
  mkdirSync(stagedScriptsRoot, { recursive: true });
  copyFileSync(
    path.join(repositoryRoot, "npm", "satelle-win32-x64-msvc", "package.json"),
    path.join(stagedPackageRoot, "package.json"),
  );
  copyFileSync(
    path.join(repositoryRoot, "npm", "scripts", "verify-native-package.cjs"),
    path.join(stagedScriptsRoot, "verify-native-package.cjs"),
  );
  writeFileSync(binaryPath, "assembled-native-binary");

  const packDestination = path.join(fixtureRoot, "packs");
  mkdirSync(packDestination);
  const nativePack = packPackage(stagedPackageRoot, packDestination);
  assert.deepEqual(
    nativePack.files.map(({ path: filePath }) => filePath).sort(),
    ["bin/satelle.exe", "package.json"],
  );
});

test("the executable boundary prints typed errors without a stack trace", () => {
  const child = spawnSync(process.execPath, [path.join(canonicalPackageRoot, "bin", "satelle.cjs")], {
    encoding: "utf8",
  });

  assert.equal(child.status, 1);
  assert.match(child.stderr, /^satelle: native-binary-package-missing:/);
  assert.doesNotMatch(child.stderr, /LauncherError|\n\s+at /);
});
