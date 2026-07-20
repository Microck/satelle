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
  plugins: [cargo({ bumpDep: () => false }), preventCargoPublication],
});

await runCli(paper, {
  // Public npm and GitHub publication stays in release.yml until the recorded dry-run
  // gate has passed and Tegami can preserve Satelle's candidate/promotion transaction.
  publish() {
    if (process.env.SATELLE_TEGAMI_DRY_RUN !== "1") {
      throw new Error(
        "Tegami publication is gated; run npm run dry-run in npm/release-tooling and use the manual release workflow",
      );
    }
    return paper.publish({ dryRun: true });
  },
});
