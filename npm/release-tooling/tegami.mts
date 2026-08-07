import path from "node:path";
import { fileURLToPath } from "node:url";
import { tegami } from "tegami";
import { runCli } from "tegami/cli";
import { cargo } from "tegami/plugins/cargo";
import type { TegamiPlugin } from "tegami";

const repositoryRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../..");

// Cargo participates in workspace discovery, versioning, and dependency-range updates,
// but the MVP release deliberately has no crates.io publication target.
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
  // Every Satelle crate inherits one workspace version. Avoid applying one dependency
  // bump per dependent crate while still letting Cargo update dependency ranges.
  // The preflight guard must run before the Cargo plugin, which otherwise checks crates.io.
  plugins: [preventCargoPublication, cargo({ bumpDep: () => false })],
});

await runCli(paper, {
  // Tegami validates the committed release plan, then release.yml acts as its explicit
  // hook for signed binaries and the recoverable npm candidate/promotion transaction.
  // Tegami must never publish the private Cargo workspace to crates.io.
  publish() {
    if (!process.env.SATELLE_TEGAMI_RELEASE_VERSION) {
      throw new Error(
        "Tegami release orchestration requires SATELLE_TEGAMI_RELEASE_VERSION from release.yml",
      );
    }
    return paper.publish({ dryRun: true });
  },
});
