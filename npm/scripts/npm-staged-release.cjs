#!/usr/bin/env node
"use strict";

const { execFileSync, spawnSync } = require("node:child_process");
const {
  mkdtempSync,
  readFileSync,
  readdirSync,
  renameSync,
  rmSync,
  writeFileSync,
} = require("node:fs");
const { tmpdir } = require("node:os");
const path = require("node:path");
const { createReleaseContext, sha512Integrity } = require("./release.cjs");

const repositoryRoot = path.resolve(__dirname, "../..");
const versionPattern = /^(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)$/;
const uuidPattern = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const sha1Pattern = /^[0-9a-f]{40}$/;

class StagedReleaseError extends Error {
  constructor(code, message) {
    super(message);
    this.code = code;
  }
}

function fail(code, message) {
  throw new StagedReleaseError(code, message);
}

function createStageRecord(version, manifest, now) {
  if (
    !versionPattern.test(version ?? "") ||
    manifest?.schemaVersion !== "satelle.npm-artifacts.v1" ||
    manifest.version !== version
  ) {
    fail("npm-stage-record-invalid", "release version and npm artifact manifest must match");
  }
  const order = createReleaseContext(repositoryRoot).check(`v${version}`).publicationOrder;
  const artifacts = new Map((manifest.packages ?? []).map((entry) => [entry.package, entry]));
  if (artifacts.size !== manifest.packages?.length) {
    fail("npm-stage-record-invalid", "npm artifact manifest contains a duplicate package");
  }
  const packages = order.map((name) => {
    const artifact = artifacts.get(name);
    if (
      artifact?.version !== version ||
      typeof artifact.file !== "string" ||
      typeof artifact.integrity !== "string" ||
      !artifact.integrity.startsWith("sha512-")
    ) {
      fail("npm-stage-record-invalid", `${name} is missing validated artifact metadata`);
    }
    return {
      name,
      file: artifact.file,
      integrity: artifact.integrity,
      ...(artifact.target ? { target: artifact.target } : {}),
      status: "pending",
      stageId: null,
      shasum: null,
    };
  });
  if (artifacts.size !== packages.length) {
    fail("npm-stage-record-invalid", "npm artifact manifest contains an unexpected package");
  }
  const timestamp = new Date(now ?? Date.now()).toISOString();
  return {
    schemaVersion: "satelle.npm-staged-release.v1",
    version,
    tag: "latest",
    status: "staging",
    provenance: "github-actions-oidc",
    createdAt: timestamp,
    updatedAt: timestamp,
    packages,
  };
}

function validateStageRecord(record) {
  if (
    record?.schemaVersion !== "satelle.npm-staged-release.v1" ||
    !versionPattern.test(record.version ?? "") ||
    record.tag !== "latest" ||
    !["staging", "awaiting_approval"].includes(record.status) ||
    record.provenance !== "github-actions-oidc" ||
    !Array.isArray(record.packages) ||
    record.packages.length !== 8
  ) {
    fail("npm-stage-record-invalid", "npm staged release record has an invalid envelope");
  }
  const names = new Set();
  for (const entry of record.packages) {
    if (
      typeof entry.name !== "string" ||
      names.has(entry.name) ||
      typeof entry.file !== "string" ||
      typeof entry.integrity !== "string" ||
      !entry.integrity.startsWith("sha512-") ||
      (entry.target !== undefined && typeof entry.target !== "string") ||
      !["pending", "staged"].includes(entry.status) ||
      (entry.status === "pending" && (entry.stageId !== null || entry.shasum !== null)) ||
      (entry.status === "staged" &&
        (!uuidPattern.test(entry.stageId ?? "") || !sha1Pattern.test(entry.shasum ?? "")))
    ) {
      fail("npm-stage-record-invalid", `npm stage record has an invalid ${entry.name ?? "package"} entry`);
    }
    names.add(entry.name);
  }
  const staged = record.packages.every((entry) => entry.status === "staged");
  if ((record.status === "awaiting_approval") !== staged) {
    fail("npm-stage-record-invalid", "npm stage record status does not match its packages");
  }
  return record;
}

function findPublishResult(value) {
  if (!value || typeof value !== "object") return null;
  if (typeof value.stageId === "string") return value;
  for (const child of Object.values(value)) {
    const result = findPublishResult(child);
    if (result) return result;
  }
  return null;
}

function recordStagedPackage(record, packageName, publishOutput, now) {
  validateStageRecord(record);
  const pending = record.packages.find((entry) => entry.status === "pending");
  if (!pending || pending.name !== packageName) {
    fail("npm-stage-order-invalid", `${packageName} is not the next package`);
  }
  const published = findPublishResult(publishOutput);
  const publishedName = published?.name ?? published?.id?.split("@").slice(0, -1).join("@");
  if (
    !published ||
    publishedName !== pending.name ||
    published.version !== record.version ||
    published.integrity !== pending.integrity ||
    !uuidPattern.test(published.stageId ?? "") ||
    !sha1Pattern.test(published.shasum ?? "")
  ) {
    fail("npm-stage-output-invalid", `${packageName} stage output does not match its artifact`);
  }
  const next = structuredClone(record);
  const entry = next.packages.find(({ name }) => name === packageName);
  entry.status = "staged";
  entry.stageId = published.stageId;
  entry.shasum = published.shasum;
  next.updatedAt = new Date(now ?? Date.now()).toISOString();
  if (next.packages.every((candidate) => candidate.status === "staged")) {
    next.status = "awaiting_approval";
  }
  return validateStageRecord(next);
}

function writeRecord(filePath, record) {
  validateStageRecord(record);
  const destination = path.resolve(filePath);
  const temporary = `${destination}.tmp`;
  writeFileSync(temporary, `${JSON.stringify(record, null, 2)}\n`, { mode: 0o600 });
  renameSync(temporary, destination);
}

function readRecord(filePath) {
  return validateStageRecord(JSON.parse(readFileSync(filePath, "utf8")));
}

function nextPendingPackage(record) {
  validateStageRecord(record);
  return record.packages.find((entry) => entry.status === "pending") ?? null;
}

function assertRecordMatchesManifest(record, manifest) {
  validateStageRecord(record);
  const expected = createStageRecord(record.version, manifest, record.createdAt);
  for (const [index, entry] of record.packages.entries()) {
    const expectedEntry = expected.packages[index];
    if (
      entry.name !== expectedEntry.name ||
      entry.file !== expectedEntry.file ||
      entry.integrity !== expectedEntry.integrity ||
      entry.target !== expectedEntry.target
    ) {
      fail("npm-stage-record-invalid", "npm stage record differs from validated release artifacts");
    }
  }
  return record;
}

function assertStageView(entry, record, view) {
  if (
    view?.id !== entry.stageId ||
    view.packageName !== entry.name ||
    view.version !== record.version ||
    view.tag !== record.tag ||
    view.shasum !== entry.shasum ||
    view.actorType !== "trusted automation" ||
    !["awaiting_approval", "staged"].includes(view.status)
  ) {
    fail("npm-stage-review-invalid", `${entry.name} staged metadata is not ready for approval`);
  }
}

function npmJson(argumentsList, options = {}) {
  const child = spawnSync("npm", argumentsList, {
    cwd: options.cwd,
    encoding: "utf8",
    stdio: ["inherit", "pipe", "inherit"],
    timeout: 120_000,
  });
  if (child.error || child.signal || child.status !== 0) {
    fail("npm-stage-command-failed", `npm ${argumentsList.join(" ")} failed`);
  }
  try {
    return JSON.parse(child.stdout);
  } catch {
    fail("npm-stage-command-failed", `npm ${argumentsList.join(" ")} returned invalid JSON`);
  }
}

function assertInteractiveReviewEnvironment() {
  if (process.env.CI === "true" || process.env.GITHUB_ACTIONS === "true" || !process.stdin.isTTY) {
    fail("npm-stage-interactive-required", "staged npm approval requires an interactive maintainer terminal");
  }
  const node = process.versions.node.split(".").map(Number);
  if (node[0] < 22 || (node[0] === 22 && node[1] < 14)) {
    fail("npm-stage-cli-too-old", "staged npm approval requires Node.js 22.14.0 or newer");
  }
  const npmVersion = execFileSync("npm", ["--version"], { encoding: "utf8", timeout: 120_000 }).trim();
  const npm = npmVersion.split(".").map(Number);
  if (npm[0] < 11 || (npm[0] === 11 && npm[1] < 15)) {
    fail("npm-stage-cli-too-old", "staged npm approval requires npm 11.15.0 or newer");
  }
}

function reviewAndApprove(recordPath) {
  assertInteractiveReviewEnvironment();
  const record = readRecord(recordPath);
  if (record.status !== "awaiting_approval") {
    fail("npm-stage-review-invalid", "all eight npm packages must be staged before review");
  }
  const reviewRoot = mkdtempSync(path.join(tmpdir(), `satelle-npm-stage-${record.version}-`));
  try {
    for (const entry of record.packages) {
      const view = npmJson(["stage", "view", entry.stageId, "--json"]);
      assertStageView(entry, record, view);
      const before = new Set(readdirSync(reviewRoot));
      npmJson(["stage", "download", entry.stageId, "--json"], { cwd: reviewRoot });
      const downloaded = readdirSync(reviewRoot).filter((name) => !before.has(name));
      if (downloaded.length !== 1 || !downloaded[0].endsWith(".tgz")) {
        fail("npm-stage-review-invalid", `${entry.name} did not download one staged tarball`);
      }
      const downloadedPath = path.join(reviewRoot, downloaded[0]);
      if (sha512Integrity(downloadedPath) !== entry.integrity) {
        fail("npm-stage-review-invalid", `${entry.name} staged tarball digest does not match`);
      }
      renameSync(downloadedPath, path.join(reviewRoot, entry.file));
    }

    const manifest = {
      schemaVersion: "satelle.npm-artifacts.v1",
      version: record.version,
      packages: record.packages.map(({ name, file, integrity, target }) => ({
        package: name,
        version: record.version,
        ...(target ? { target } : {}),
        file,
        integrity,
      })),
    };
    writeFileSync(path.join(reviewRoot, "npm-artifacts.json"), `${JSON.stringify(manifest, null, 2)}\n`);
    createReleaseContext(repositoryRoot).validateNpmArtifacts(reviewRoot, {
      releaseTag: `v${record.version}`,
    });

    // No 2FA prompt can occur until every package's metadata, OIDC provenance,
    // release version, archive contents, and exact digest have passed above.
    for (const entry of record.packages) {
      execFileSync("npm", ["stage", "approve", entry.stageId], { stdio: "inherit" });
    }
  } finally {
    rmSync(reviewRoot, { recursive: true, force: true });
  }
}

function runCli() {
  const [command, ...argumentsList] = process.argv.slice(2);
  if (command === "create") {
    const [version, manifestPath, recordPath] = argumentsList;
    writeRecord(recordPath, createStageRecord(version, JSON.parse(readFileSync(manifestPath, "utf8"))));
    return;
  }
  if (command === "next") {
    process.stdout.write(`${JSON.stringify(nextPendingPackage(readRecord(argumentsList[0])))}\n`);
    return;
  }
  if (command === "record") {
    const [recordPath, packageName, outputPath] = argumentsList;
    writeRecord(
      recordPath,
      recordStagedPackage(readRecord(recordPath), packageName, JSON.parse(readFileSync(outputPath, "utf8"))),
    );
    return;
  }
  if (command === "verify") {
    const [recordPath, manifestPath] = argumentsList;
    assertRecordMatchesManifest(
      readRecord(recordPath),
      JSON.parse(readFileSync(manifestPath, "utf8")),
    );
    return;
  }
  if (command === "approve") {
    reviewAndApprove(argumentsList[0]);
    return;
  }
  fail("npm-stage-command-invalid", `unknown staged release command ${command ?? ""}`);
}

if (require.main === module) {
  try {
    runCli();
  } catch (error) {
    const code = error instanceof StagedReleaseError ? error.code : "npm-stage-command-failed";
    process.stderr.write(`${JSON.stringify({ code, message: error.message })}\n`);
    process.exitCode = 1;
  }
}

module.exports = {
  StagedReleaseError,
  assertRecordMatchesManifest,
  assertStageView,
  createStageRecord,
  nextPendingPackage,
  recordStagedPackage,
  validateStageRecord,
};
