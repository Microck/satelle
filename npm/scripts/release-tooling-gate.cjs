#!/usr/bin/env node
"use strict";

const {
  existsSync,
  readFileSync,
  readdirSync,
  statSync,
  writeFileSync,
} = require("node:fs");
const path = require("node:path");

const versionPattern = /^(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)$/;
const repositoryRoot = path.resolve(__dirname, "../..");

function fail(message) {
  throw new Error(message);
}

function readJson(filePath) {
  return JSON.parse(readFileSync(filePath, "utf8"));
}

function writeJson(filePath, value) {
  writeFileSync(filePath, `${JSON.stringify(value, null, 2)}\n`);
}

function changelogFiles(root = path.join(repositoryRoot, "crates")) {
  return readdirSync(root).flatMap((entry) => {
    const packageRoot = path.join(root, entry);
    if (!statSync(packageRoot).isDirectory()) return [];
    const changelog = path.join(packageRoot, "CHANGELOG.md");
    return existsSync(changelog) ? [changelog] : [];
  });
}

function verifyChangelogs(version, expectedFiles = changelogFiles()) {
  if (!versionPattern.test(version ?? "")) fail(`invalid release version ${version ?? ""}`);
  const matching = expectedFiles.filter((filePath) => {
    if (!existsSync(filePath)) return false;
    const contents = readFileSync(filePath, "utf8");
    const escapedVersion = version.replaceAll(".", "\\.");
    return new RegExp(
      `^##? (?:\\[v?${escapedVersion}\\]|v?${escapedVersion})(?![0-9A-Za-z.+-])`,
      "m",
    ).test(contents);
  });
  if (matching.length === 0) {
    fail(`no committed Tegami changelog output describes release ${version}`);
  }
  return matching.map((filePath) => path.relative(repositoryRoot, filePath).split(path.sep).join("/"));
}

function selectOrchestration(version, tegamiOutcome, validationPath, fallbackPath) {
  if (!versionPattern.test(version ?? "")) fail(`invalid release version ${version ?? ""}`);
  if (tegamiOutcome === "success") {
    const validation = readJson(validationPath);
    if (
      validation.schemaVersion !== "satelle.tegami-validation.v1" ||
      validation.cargoPlugin?.changelogGeneration !== "1.0.0 -> 1.0.1"
    ) {
      fail("Tegami validation did not prove changelog generation");
    }
    return {
      schemaVersion: "satelle.release-orchestration.v1",
      version,
      mode: "tegami",
      tegamiVersion: validation.tegamiVersion,
    };
  }
  if (tegamiOutcome !== "failure") fail(`invalid Tegami outcome ${tegamiOutcome ?? ""}`);
  if (!existsSync(fallbackPath)) {
    fail("Tegami failed and the merged release pull request has no manual fallback record");
  }
  const fallback = readJson(fallbackPath);
  if (
    fallback.schemaVersion !== "satelle.manual-release-fallback.v1" ||
    fallback.version !== version ||
    fallback.generatedChangesReviewed !== true ||
    typeof fallback.reason !== "string" ||
    fallback.reason.trim() === "" ||
    !Array.isArray(fallback.changelogFiles) ||
    fallback.changelogFiles.length === 0
  ) {
    fail("manual release fallback record is incomplete or version-mismatched");
  }
  const files = fallback.changelogFiles.map((fileName) => {
    if (typeof fileName !== "string" || path.isAbsolute(fileName)) {
      fail("manual release fallback changelog paths must be repository-relative files");
    }
    const filePath = path.resolve(repositoryRoot, fileName);
    if (path.relative(repositoryRoot, filePath).startsWith("..")) {
      fail("manual release fallback changelog paths must stay inside the repository");
    }
    return filePath;
  });
  const verifiedChangelogs = verifyChangelogs(version, files);
  return {
    schemaVersion: "satelle.release-orchestration.v1",
    version,
    mode: "manual",
    reason: fallback.reason,
    verifiedChangelogs,
  };
}

function recordFailure(outputPath) {
  // This record becomes a public release asset. Keep subprocess output only in the
  // private workflow capture because npm tooling can echo registry credentials.
  writeJson(outputPath, {
    schemaVersion: "satelle.tegami-validation.v1",
    status: "failed",
    reason: "tegami-validation-command-failed",
    message: "Tegami validation failed; rerun it in a trusted environment",
  });
}

function runCli() {
  const [command, ...args] = process.argv.slice(2);
  if (command === "select") {
    const record = selectOrchestration(args[0], args[1], args[2], args[3]);
    writeJson(args[4], record);
  } else if (command === "verify-changelogs") {
    const files = verifyChangelogs(args[0]);
    writeJson(args[1], {
      schemaVersion: "satelle.tegami-changelog-validation.v1",
      version: args[0],
      files,
    });
  } else if (command === "record-failure") {
    recordFailure(args[0]);
  } else {
    fail(`unknown release tooling gate command ${command ?? ""}`);
  }
}

if (require.main === module) {
  try {
    runCli();
  } catch (error) {
    process.stderr.write(`${JSON.stringify({
      code: "release-tooling-gate-failed",
      message: error.message,
    })}\n`);
    process.exitCode = 1;
  }
}

module.exports = { recordFailure, selectOrchestration, verifyChangelogs };
