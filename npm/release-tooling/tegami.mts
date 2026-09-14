import path from "node:path";
import { fileURLToPath } from "node:url";
import { tegami } from "tegami";
import { runCli } from "tegami/cli";
import { cargo } from "tegami/plugins/cargo";
import type { TegamiPlugin } from "tegami";

const repositoryRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../..");

// Cargo participates in discovery and versioning. The signed-tag workflow owns
// the crates.io write so it can bind the package to the same reviewed artifacts.
const preventCargoPublication: TegamiPlugin = {
  name: "satelle-prevent-cargo-publication",
  publishPreflight({ pkg }) {
    if (pkg.manager === "cargo") return { shouldPublish: false };
  },
  willPublish({ pkg }) {
    if (pkg.manager === "cargo") return false;
  },
};

const paper = tegami({
  cwd: repositoryRoot,
  changelogDir: path.join(repositoryRoot, "npm/release-tooling/changelogs"),
  lockPath: path.join(repositoryRoot, "npm/release-tooling/publish-lock.yaml"),
  // The preflight guard must run before the Cargo plugin, which otherwise checks crates.io.
  plugins: [preventCargoPublication, cargo({ bumpDep: () => false })],
});

await runCli(paper, {
  // Tegami validates the plan. release.yml performs the guarded registry writes.
  publish() {
    if (!process.env.SATELLE_TEGAMI_RELEASE_VERSION) {
      throw new Error(
        "Tegami release orchestration requires SATELLE_TEGAMI_RELEASE_VERSION from release.yml",
      );
    }
    return paper.publish({ dryRun: true });
  },
});
