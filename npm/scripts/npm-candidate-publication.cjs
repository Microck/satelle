#!/usr/bin/env node
"use strict";

const { execFileSync, spawnSync } = require("node:child_process");
const {
  mkdtempSync,
  readFileSync,
  realpathSync,
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

function requireCandidateTagRecovery(version) {
  if (
    process.env.GITHUB_ACTIONS !== "true" ||
    process.env.GITHUB_EVENT_NAME !== "workflow_dispatch" ||
    process.env.GITHUB_REPOSITORY !== "Microck/satelle" ||
    process.env.SATELLE_RELEASE_RECOVERY !== "1" ||
    process.env.SATELLE_RELEASE_RECOVERY_TAG !== `v${version}`
  ) {
    fail(
      "release-automation-required",
      "npm candidate tag repair is limited to the matching Satelle release recovery workflow",
    );
  }
}

function assertCandidateRecoveryAuthorization({
  currentTagDigest,
  currentSourceDigest,
  isDraft,
  verifiedTagDigest,
  verifiedSourceDigest,
}) {
  if (
    currentTagDigest !== verifiedTagDigest ||
    currentSourceDigest !== verifiedSourceDigest ||
    isDraft !== true
  ) {
    fail(
      "release-recovery-not-authorized",
      "candidate tag recovery requires the verified signed tag and a draft GitHub release",
    );
  }
}

function recheckCandidateRecoveryAuthorization(version) {
  requireCandidateTagRecovery(version);
  const repository = process.env.GITHUB_REPOSITORY;
  const verifiedTagDigest = process.env.VERIFIED_TAG_DIGEST;
  const verifiedSourceDigest = process.env.VERIFIED_SOURCE_DIGEST;
  try {
    const currentTagDigest = execFileSync(
      "gh",
      ["api", `repos/${repository}/git/ref/tags/v${version}`, "--jq", ".object.sha"],
      { encoding: "utf8", timeout: 120_000 },
    ).trim();
    const currentSourceDigest = execFileSync(
      "gh",
      [
        "api",
        `repos/${repository}/git/tags/${currentTagDigest}`,
        "--jq",
        "select(.verification.verified == true and .object.type == \"commit\") | .object.sha",
      ],
      { encoding: "utf8", timeout: 120_000 },
    ).trim();
    const isDraft = execFileSync(
      "gh",
      [
        "release",
        "view",
        `v${version}`,
        "--repo",
        repository,
        "--json",
        "isDraft",
        "--jq",
        ".isDraft",
      ],
      { encoding: "utf8", timeout: 120_000 },
    ).trim() === "true";
    assertCandidateRecoveryAuthorization({
      currentTagDigest,
      currentSourceDigest,
      isDraft,
      verifiedTagDigest,
      verifiedSourceDigest,
    });
  } catch (error) {
    if (error instanceof CandidatePublicationError) throw error;
    fail(
      "release-recovery-not-authorized",
      `candidate tag recovery authorization could not be revalidated: ${error.message}`,
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
    recovery: publicationRecoveryInstruction(version),
    error: null,
    packages,
  };
}

function publicationRecoveryInstruction(version, errorCode) {
  if (errorCode === "candidate-registry-tag-mismatch") {
    return `dispatch candidate-tag-repair for v${version}, then rerun the signed-tag workflow without moving the tag or changing package bytes`;
  }
  return `rerun the v${version} release workflow without moving the signed tag or changing package bytes`;
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
  } else {
    next.status = "publishing";
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
  if (child.error || child.signal) {
    const reason = child.error?.code === "ETIMEDOUT"
      ? "timed out"
      : child.signal
        ? `was terminated by ${child.signal}`
        : "could not start";
    fail("candidate-registry-read-failed", `npm view ${packageSpec} ${reason}`);
  }
  if (child.status !== 0) {
    const stderr = child.stderr ?? "";
    if (/E404|not found/i.test(stderr)) return null;
    fail("candidate-registry-read-failed", `npm view ${packageSpec} failed`);
  }
  const output = (child.stdout ?? "").trim();
  return output === "" ? null : JSON.parse(output);
}

function candidateTagValue(distTags, candidateTag) {
  if (distTags === null) return null;
  if (typeof distTags !== "object" || Array.isArray(distTags)) {
    fail("candidate-registry-read-failed", "npm returned invalid dist-tags");
  }
  return distTags[candidateTag] ?? null;
}

function candidateTagRepairAction(taggedVersion, candidateVersion) {
  if (taggedVersion === null) return "repair";
  if (taggedVersion === candidateVersion) return "already_tagged";
  fail(
    "candidate-registry-tag-conflict",
    `candidate tag points to ${taggedVersion} instead of ${candidateVersion}`,
  );
}

function readCandidateTag(packageName, candidateTag) {
  return candidateTagValue(npmView(packageName, "dist-tags"), candidateTag);
}

function resolveArtifactPath(artifactDirectory, fileName) {
  if (path.isAbsolute(fileName)) {
    fail("candidate-record-invalid", "candidate artifact paths must be relative");
  }
  const artifactRoot = realpathSync(artifactDirectory);
  const artifactPath = path.resolve(artifactRoot, fileName);
  const relativePath = path.relative(artifactRoot, artifactPath);
  if (
    relativePath === "" ||
    relativePath === ".." ||
    relativePath.startsWith(`..${path.sep}`) ||
    path.isAbsolute(relativePath)
  ) {
    fail("candidate-record-invalid", "candidate artifact path must stay inside its artifact directory");
  }
  const resolvedArtifactPath = realpathSync(artifactPath);
  const resolvedRelativePath = path.relative(artifactRoot, resolvedArtifactPath);
  if (
    resolvedRelativePath === ".." ||
    resolvedRelativePath.startsWith(`..${path.sep}`) ||
    path.isAbsolute(resolvedRelativePath)
  ) {
    fail("candidate-record-invalid", "candidate artifact path must stay inside its artifact directory");
  }
  return resolvedArtifactPath;
}

function verifyPublishedCandidate(entry, record) {
  const packageSpec = `${entry.name}@${record.version}`;
  const version = npmView(packageSpec, "version");
  const integrity = npmView(packageSpec, "dist.integrity");
  const taggedVersion = readCandidateTag(entry.name, record.candidateTag);
  if (version !== record.version || integrity !== entry.integrity) {
    fail(
      "candidate-registry-integrity-mismatch",
      `${packageSpec} does not match the validated immutable artifact`,
    );
  }
  if (taggedVersion !== record.version) {
    fail(
      "candidate-registry-tag-mismatch",
      `${packageSpec} is not visible under ${record.candidateTag}; dispatch candidate-tag-repair for v${record.version}, then rerun the signed-tag workflow`,
    );
  }
}

function repairCandidateTags(version, manifest) {
  requireCandidateTagRecovery(version);
  const record = createPublicationRecord(version, manifest);
  const repaired = [];
  const alreadyTagged = [];
  const unpublished = [];

  for (const entry of record.packages) {
    const packageSpec = `${entry.name}@${version}`;
    const publishedVersion = npmView(packageSpec, "version");
    if (publishedVersion === null) {
      unpublished.push(entry.name);
      continue;
    }
    const integrity = npmView(packageSpec, "dist.integrity");
    if (publishedVersion !== version || integrity !== entry.integrity) {
      fail(
        "candidate-registry-integrity-mismatch",
        `${packageSpec} does not match the validated immutable artifact`,
      );
    }
    const repairAction = candidateTagRepairAction(
      readCandidateTag(entry.name, record.candidateTag),
      version,
    );
    if (repairAction === "already_tagged") {
      alreadyTagged.push(entry.name);
      continue;
    }
    recheckCandidateRecoveryAuthorization(version);
    try {
      execFileSync(
        "npm",
        ["dist-tag", "add", packageSpec, record.candidateTag],
        { stdio: "inherit", timeout: 120_000 },
      );
    } catch {
      fail(
        "candidate-registry-tag-repair-failed",
        `${packageSpec} could not be assigned ${record.candidateTag}`,
      );
    }
    if (readCandidateTag(entry.name, record.candidateTag) !== version) {
      fail(
        "candidate-registry-tag-repair-failed",
        `${packageSpec} is still not visible under ${record.candidateTag}`,
      );
    }
    repaired.push(entry.name);
  }

  return { version, candidateTag: record.candidateTag, repaired, alreadyTagged, unpublished };
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
      const artifactPath = resolveArtifactPath(artifactDirectory, entry.file);
      execFileSync(
        "npm",
        [
          "publish",
          artifactPath,
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
    record.recovery = publicationRecoveryInstruction(record.version, publicationError.code);
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
  } else if (command === "repair-tags") {
    const [version, manifestPath] = argumentsList;
    output = repairCandidateTags(version, JSON.parse(readFileSync(manifestPath, "utf8")));
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
  assertCandidateRecoveryAuthorization,
  CandidatePublicationError,
  candidateTagRepairAction,
  candidateTagValue,
  checkpointPublished,
  createPublicationRecord,
  npmView,
  publicationRecoveryInstruction,
  readCandidateTag,
  repairCandidateTags,
  resolveArtifactPath,
};
