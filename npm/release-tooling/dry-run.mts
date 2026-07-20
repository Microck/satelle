import {
  mkdtempSync,
  mkdirSync,
  readFileSync,
  readdirSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { tegami } from "tegami";
import { cargo } from "tegami/plugins/cargo";
import tegamiPackage from "tegami/package.json" with { type: "json" };
import type { TegamiPlugin } from "tegami";

const toolRoot = path.dirname(fileURLToPath(import.meta.url));
const repositoryRoot = path.resolve(toolRoot, "../..");

function cargoInventory(capture: string[]): TegamiPlugin {
  return {
    name: "satelle-cargo-inventory",
    enforce: "post",
    initDraft() {
      capture.push(
        ...this.graph
          .getPackages()
          .filter((pkg) => pkg.manager === "cargo")
          .map((pkg) => `${pkg.id}@${pkg.version}`)
          .sort(),
      );
    },
    willPublish({ pkg }) {
      if (pkg.manager === "cargo") return false;
    },
  };
}

function listFiles(root: string, relative = ""): string[] {
  return readdirSync(path.join(root, relative), { withFileTypes: true }).flatMap((entry) => {
    const child = path.join(relative, entry.name);
    return entry.isDirectory() ? listFiles(root, child) : [child.split(path.sep).join("/")];
  });
}

if (Number.parseInt(process.versions.node.split(".")[0], 10) < 24) {
  throw new Error(`Tegami validation requires Node.js 24; found ${process.version}`);
}
if (tegamiPackage.version !== "1.2.5") {
  throw new Error(`expected Tegami 1.2.5; found ${tegamiPackage.version}`);
}

const discoveredCargoPackages: string[] = [];
const repositoryPaper = tegami({
  cwd: repositoryRoot,
  changelogDir: path.join(repositoryRoot, "npm/release-tooling/changelogs"),
  lockPath: path.join(repositoryRoot, "npm/release-tooling/publish-lock.yaml"),
  plugins: [cargo({ bumpDep: () => false }), cargoInventory(discoveredCargoPackages)],
});
await repositoryPaper.draft();
if (discoveredCargoPackages.length === 0) {
  throw new Error("Tegami Cargo plugin did not discover the Satelle workspace packages");
}

const fixtureRoot = mkdtempSync(path.join(tmpdir(), "satelle-tegami-dry-run-"));
try {
  mkdirSync(path.join(fixtureRoot, "crates/core"), { recursive: true });
  mkdirSync(path.join(fixtureRoot, "crates/cli"), { recursive: true });
  mkdirSync(path.join(fixtureRoot, ".tegami"));
  writeFileSync(
    path.join(fixtureRoot, "Cargo.toml"),
    `[workspace]
members = ["crates/*"]
resolver = "2"

[workspace.package]
version = "1.0.0"
publish = false
`,
  );
  writeFileSync(
    path.join(fixtureRoot, "crates/core/Cargo.toml"),
    `[package]
name = "satelle-core-fixture"
version.workspace = true
publish.workspace = true
`,
  );
  writeFileSync(
    path.join(fixtureRoot, "crates/cli/Cargo.toml"),
    `[package]
name = "satelle-cli-fixture"
version.workspace = true
publish.workspace = true

[dependencies]
satelle-core-fixture = { path = "../core", version = "1.0.0" }
`,
  );
  writeFileSync(
    path.join(fixtureRoot, ".tegami/release.md"),
    `---
packages:
  "cargo:satelle-core-fixture": patch
---

## Exercise Cargo release behavior

Validate package discovery, versioning, and dependency updates.
`,
  );

  const fixturePackages: string[] = [];
  const fixturePaper = tegami({
    cwd: fixtureRoot,
    plugins: [
      cargo({ updateLockFile: false, bumpDep: () => false }),
      cargoInventory(fixturePackages),
    ],
  });
  const draft = await fixturePaper.draft();
  const draftedPackages = [...draft.getPackageDrafts()].map(([id, value]) => [id, value.type]);
  await draft.apply();

  const rootManifest = readFileSync(path.join(fixtureRoot, "Cargo.toml"), "utf8");
  const cliManifest = readFileSync(path.join(fixtureRoot, "crates/cli/Cargo.toml"), "utf8");
  if (!rootManifest.includes('version = "1.0.1"')) {
    throw new Error(`Tegami Cargo dry run did not bump the workspace version (${JSON.stringify(draftedPackages)}):\n${rootManifest}`);
  }
  if (!cliManifest.includes('version = "1.0.1"')) {
    throw new Error("Tegami Cargo dry run did not update the dependency range");
  }

  const report = {
    schemaVersion: "satelle.tegami-validation.v1",
    nodeVersion: process.version,
    tegamiVersion: tegamiPackage.version,
    cargoPlugin: {
      discoveredWorkspacePackages: discoveredCargoPackages,
      fixturePackages,
      versionBump: "1.0.0 -> 1.0.1",
      dependencyRange: "1.0.0 -> 1.0.1",
      configuredUpdateLockFile: true,
      fixtureUpdateLockFile: false,
    },
    generatedFiles: listFiles(fixtureRoot).sort(),
    skippedPublishTargets: ["crates.io", "npm registry", "GitHub release"],
  };
  process.stdout.write(`${JSON.stringify(report, null, 2)}\n`);
} finally {
  rmSync(fixtureRoot, { recursive: true, force: true });
}
