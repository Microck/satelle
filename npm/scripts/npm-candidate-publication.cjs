#!/usr/bin/env node
"use strict";

const { execFileSync, spawnSync } = require("node:child_process");
const {
  mkdtempSync,
  readFileSync,
  renameSync,
  rmSync,
  writeFileSync,
} = require("node:fs");
const path = require("node:path");
const { createReleaseContext } = require("./release.cjs");

const versionPattern = /^(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)$/;

class CandidatePublicationError extends Error {
  constructor(code, message) {
    super(message);
    this.code = code;
  }
}

function fail(code, message) {
  throw new CandidatePublicationError(code, message);
}

function requireReleaseAutomation(version) {
  if (
    process.env.GITHUB_ACTIONS !== "true" ||
    process.env.GITHUB_REPOSITORY !== "Microck/satelle" ||
    process.env.GITHUB_REF !== `refs/tags/v${version}`
  ) {
    fail(
      "release-automation-required",
      "npm candidate publication is limited to the Microck/satelle tag release workflow",
    );
  }
}

function createPublicationRecord(version, manifest, now) {
  if (!versionPattern.test(version ?? "") || manifest?.version !== version) {
    fail("candidate-record-invalid", "candidate version and npm artifact manifest must match");
  }
  const releasePlan = createReleaseContext(path.resolve(__dirname, "../..")).check(`v${version}`);
  const artifacts = new Map((manifest.packages ?? []).map((entry) => [entry.package, entry]));
  const packages = releasePlan.publicationOrder.map((packageName) => {
    const artifact = artifacts.get(packageName);
    if (
      artifact?.version !== version ||
      typeof artifact.file !== "string" ||
      typeof artifact.integrity !== "string"
    ) {
      fail("candidate-record-invalid", `${packageName} is missing validated artifact metadata`);
    }
    return {
      name: packageName,
      file: artifact.file,
      integrity: artifact.integrity,
      status: "pending",
    };
  });
  if (artifacts.size !== packages.length) {
    fail("candidate-record-invalid", "npm artifact manifest contains an unexpected package");
  }
  const timestamp = new Date(now ?? Date.now()).toISOString();
  return {
    schemaVersion: "satelle.npm-candidate-publication.v1",
    version,
    candidateTag: `rc-v${version}`,
    status: "publishing",
    sequence: 0,
    createdAt: timestamp,
    updatedAt: timestamp,
    recovery: `rerun the v${version} release workflow without moving the signed tag or changing package bytes`,
    error: null,
    packages,
  };
}

function validatePublicationRecord(record) {
  if (
    record?.schemaVersion !== "satelle.npm-candidate-publication.v1" ||
    !versionPattern.test(record.version ?? "") ||
    record.candidateTag !== `rc-v${record.version}` ||
    !["publishing", "complete", "failed"].includes(record.status) ||
    !Number.isSafeInteger(record.sequence) ||
    !Array.isArray(record.packages) ||
    record.packages.length === 0 ||
    record.packages.some(
      (entry) =>
        typeof entry.name !== "string" ||
        typeof entry.file !== "string" ||
        typeof entry.integrity !== "string" ||
        !["pending", "published"].includes(entry.status),
    )
  ) {
    fail("candidate-record-invalid", "npm candidate publication record is invalid");
  }
  return record;
}

function checkpointPublished(record, packageName, now) {
  validatePublicationRecord(record);
  const pending = record.packages.find((entry) => entry.status === "pending");
  if (!pending || pending.name !== packageName) {
    fail("candidate-publication-order-invalid", `${packageName} is not the next package`);
  }
  const next = structuredClone(record);
  next.packages.find((entry) => entry.name === packageName).status = "published";
  next.sequence += 1;
  next.updatedAt = new Date(now ?? Date.now()).toISOString();
  next.error = null;
  if (next.packages.every((entry) => entry.status === "published")) {
    next.status = "complete";
  }
  return next;
}

function writeRecord(filePath, record) {
  validatePublicationRecord(record);
  const destination = path.resolve(filePath);
  const temporaryRoot = mkdtempSync(path.join(path.dirname(destination), ".candidate-"));
  const temporaryPath = path.join(temporaryRoot, path.basename(destination));
  try {
    writeFileSync(temporaryPath, `${JSON.stringify(record, null, 2)}\n`, {
      flag: "wx",
      mode: 0o600,
    });
    renameSync(temporaryPath, destination);
  } finally {
    rmSync(temporaryRoot, { recursive: true, force: true });
  }
}

function readRecord(filePath) {
  return validatePublicationRecord(JSON.parse(readFileSync(filePath, "utf8")));
}

function npmView(packageSpec, field) {
  const child = spawnSync("npm", ["view", packageSpec, field, "--json"], {
    encoding: "utf8",
    env: process.env,
    timeout: 120_000,
  });
  if (child.status !== 0) {
    if (/E404|not found/i.test(child.stderr)) return null;
    fail("candidate-registry-read-failed", child.stderr.trim() || `npm view ${packageSpec} failed`);
  }
  const output = child.stdout.trim();
  return output === "" ? null : JSON.parse(output);
}

function verifyPublishedCandidate(entry, record) {
  const packageSpec = `${entry.name}@${record.version}`;
  const version = npmView(packageSpec, "version");
  const integrity = npmView(packageSpec, "dist.integrity");
  const taggedVersion = npmView(entry.name, `dist-tags.${record.candidateTag}`);
  if (version !== record.version || integrity !== entry.integrity) {
    fail(
      "candidate-registry-integrity-mismatch",
      `${packageSpec} does not match the validated immutable artifact`,
    );
  }
  if (taggedVersion !== record.version) {
    execFileSync(
      "npm",
      ["dist-tag", "add", packageSpec, record.candidateTag],
      { stdio: "inherit", timeout: 120_000 },
    );
    if (npmView(entry.name, `dist-tags.${record.candidateTag}`) !== record.version) {
      fail("candidate-registry-tag-mismatch", `${packageSpec} is not visible under ${record.candidateTag}`);
    }
  }
}

function advancePublication(recordPath, artifactDirectory) {
  let record = readRecord(recordPath);
  requireReleaseAutomation(record.version);
  const entry = record.packages.find((candidate) => candidate.status === "pending");
  if (!entry) return record;
  try {
    const packageSpec = `${entry.name}@${record.version}`;
    const publishedVersion = npmView(packageSpec, "version");
    if (publishedVersion === null) {
      execFileSync(
        "npm",
        [
          "publish",
          path.join(artifactDirectory, entry.file),
          "--tag",
          record.candidateTag,
          "--provenance",
          "--access",
          "public",
          "--ignore-scripts",
        ],
        { stdio: "inherit", timeout: 300_000 },
      );
    }
    verifyPublishedCandidate(entry, record);
    record = checkpointPublished(record, entry.name);
    writeRecord(recordPath, record);
    return record;
  } catch (error) {
    const publicationError = error instanceof CandidatePublicationError
      ? error
      : new CandidatePublicationError("candidate-publication-failed", error.message);
    record.status = "failed";
    record.sequence += 1;
    record.updatedAt = new Date().toISOString();
    record.error = { code: publicationError.code, message: publicationError.message };
    writeRecord(recordPath, record);
    throw publicationError;
  }
}

function runCli() {
  const [command, ...argumentsList] = process.argv.slice(2);
  let output;
  if (command === "create") {
    const [version, manifestPath, recordPath] = argumentsList;
    requireReleaseAutomation(version);
    output = createPublicationRecord(version, JSON.parse(readFileSync(manifestPath, "utf8")));
    writeRecord(recordPath, output);
  } else if (command === "advance") {
    output = advancePublication(argumentsList[0], argumentsList[1]);
  } else if (command === "status") {
    output = readRecord(argumentsList[0]);
  } else {
    fail("candidate-command-invalid", `unknown npm candidate command ${command ?? ""}`);
  }
  process.stdout.write(`${JSON.stringify(output)}\n`);
}

if (require.main === module) {
  try {
    runCli();
  } catch (error) {
    const code = error instanceof CandidatePublicationError
      ? error.code
      : "candidate-command-failed";
    process.stderr.write(`${JSON.stringify({ code, message: error.message })}\n`);
    process.exitCode = 1;
  }
}

module.exports = {
  CandidatePublicationError,
  checkpointPublished,
  createPublicationRecord,
};
