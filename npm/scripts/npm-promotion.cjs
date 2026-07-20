#!/usr/bin/env node
"use strict";

const { execFileSync } = require("node:child_process");
const {
  existsSync,
  mkdtempSync,
  readFileSync,
  renameSync,
  rmSync,
  writeFileSync,
} = require("node:fs");
const { tmpdir } = require("node:os");
const path = require("node:path");

const versionPattern = /^(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)$/;
const terminalStatuses = new Set(["complete", "rolled_back"]);
const promotionStatuses = new Set([
  "in_progress",
  "complete",
  "rolling_back",
  "rolled_back",
  "conflicted",
]);

class PromotionError extends Error {
  constructor(code, message) {
    super(message);
    this.code = code;
  }
}

function fail(code, message) {
  throw new PromotionError(code, message);
}

function validLatest(value) {
  return value === null || (typeof value === "string" && versionPattern.test(value));
}

function createPromotionRecord({ version, packageNames, previousLatest, now }) {
  if (!versionPattern.test(version ?? "")) {
    fail("promotion-record-invalid", `invalid candidate version ${version ?? ""}`);
  }
  if (
    !Array.isArray(packageNames) ||
    packageNames.length === 0 ||
    new Set(packageNames).size !== packageNames.length ||
    packageNames.some((name) => typeof name !== "string" || name.length === 0)
  ) {
    fail("promotion-record-invalid", "promotion packages must be a nonempty unique order");
  }
  const previousKeys = Object.keys(previousLatest ?? {});
  if (
    previousKeys.length !== packageNames.length ||
    packageNames.some(
      (name) => !Object.hasOwn(previousLatest, name) || !validLatest(previousLatest[name]),
    )
  ) {
    fail("promotion-record-invalid", "every promotion package needs its prior latest value");
  }
  const timestamp = new Date(now ?? Date.now()).toISOString();
  return {
    schemaVersion: "satelle.npm-promotion.v1",
    version,
    candidateTag: `rc-v${version}`,
    mode: "promotion",
    status: "in_progress",
    sequence: 0,
    createdAt: timestamp,
    updatedAt: timestamp,
    conflict: null,
    packages: packageNames.map((name) => ({
      name,
      previousLatest: previousLatest[name],
      promotionStatus: "pending",
      restorationStatus: "pending",
    })),
  };
}

function validatePromotionRecord(record) {
  if (
    record?.schemaVersion !== "satelle.npm-promotion.v1" ||
    !versionPattern.test(record.version ?? "") ||
    record.candidateTag !== `rc-v${record.version}` ||
    !["promotion", "rollback"].includes(record.mode) ||
    !promotionStatuses.has(record.status) ||
    !Number.isSafeInteger(record.sequence) ||
    record.sequence < 0 ||
    !Array.isArray(record.packages) ||
    record.packages.length === 0 ||
    new Set(record.packages.map(({ name }) => name)).size !== record.packages.length
  ) {
    fail("promotion-record-invalid", "npm promotion record has an invalid envelope");
  }
  for (const entry of record.packages) {
    if (
      typeof entry.name !== "string" ||
      !validLatest(entry.previousLatest) ||
      !["pending", "promoted"].includes(entry.promotionStatus) ||
      !["pending", "restored"].includes(entry.restorationStatus)
    ) {
      fail("promotion-record-invalid", `npm promotion record has an invalid ${entry.name ?? "package"} entry`);
    }
  }
  if (
    (record.mode === "promotion" && ["rolling_back", "rolled_back"].includes(record.status)) ||
    (record.mode === "rollback" && ["in_progress", "complete"].includes(record.status))
  ) {
    fail("promotion-record-invalid", "npm promotion record mode and status disagree");
  }
  return record;
}

function pendingEntry(record) {
  validatePromotionRecord(record);
  if (record.mode === "promotion") {
    return record.packages.find((entry) => entry.promotionStatus === "pending");
  }
  return [...record.packages]
    .reverse()
    .find((entry) => entry.restorationStatus === "pending");
}

function planRegistryOperation(record, observedLatest) {
  if (!validLatest(observedLatest)) {
    fail("promotion-state-conflict", "npm returned a non-version latest value");
  }
  const entry = pendingEntry(record);
  if (!entry) return { type: "finished" };

  if (record.mode === "promotion") {
    if (observedLatest === record.version) {
      return { type: "checkpoint", packageName: entry.name };
    }
    if (observedLatest === entry.previousLatest) {
      return { type: "set_latest", packageName: entry.name, version: record.version };
    }
  } else {
    if (observedLatest === entry.previousLatest) {
      return { type: "checkpoint", packageName: entry.name };
    }
    if (observedLatest === record.version) {
      return entry.previousLatest === null
        ? { type: "remove_latest", packageName: entry.name }
        : { type: "set_latest", packageName: entry.name, version: entry.previousLatest };
    }
  }

  fail(
    "promotion-state-conflict",
    `${entry.name} latest is ${observedLatest ?? "absent"}; expected ${entry.previousLatest ?? "absent"} or ${record.version}`,
  );
}

function checkpointOperation(record, observedLatest, options = {}) {
  const entry = pendingEntry(record);
  if (!entry) return structuredClone(record);
  const expected = record.mode === "promotion" ? record.version : entry.previousLatest;
  if (observedLatest !== expected) {
    fail(
      "promotion-state-conflict",
      `${entry.name} latest is ${observedLatest ?? "absent"}; expected ${expected ?? "absent"} after mutation`,
    );
  }

  const next = structuredClone(record);
  const nextEntry = next.packages.find(({ name }) => name === entry.name);
  if (next.mode === "promotion") nextEntry.promotionStatus = "promoted";
  else nextEntry.restorationStatus = "restored";
  next.sequence += 1;
  next.updatedAt = new Date(options.now ?? Date.now()).toISOString();

  if (!pendingEntry(next)) {
    if (next.mode === "promotion") {
      const allLatest = options.allLatest;
      if (
        !allLatest ||
        next.packages.some(
          ({ name }) => !Object.hasOwn(allLatest, name) || allLatest[name] !== next.version,
        )
      ) {
        fail(
          "promotion-state-conflict",
          "every required package must resolve latest to the candidate before promotion completes",
        );
      }
      next.status = "complete";
    } else {
      next.status = "rolled_back";
    }
  }
  next.conflict = null;
  return next;
}

function beginRollback(record, now) {
  validatePromotionRecord(record);
  if (record.status === "rolled_back") return structuredClone(record);
  const next = structuredClone(record);
  next.mode = "rollback";
  next.status = "rolling_back";
  next.conflict = null;
  next.sequence += 1;
  next.updatedAt = new Date(now ?? Date.now()).toISOString();
  for (const entry of next.packages) entry.restorationStatus = "pending";
  return next;
}

function conflictedRecord(record, error) {
  const next = structuredClone(record);
  next.status = "conflicted";
  next.sequence += 1;
  next.updatedAt = new Date().toISOString();
  next.conflict = { code: error.code, message: error.message };
  return next;
}

function readRecord(filePath) {
  return validatePromotionRecord(JSON.parse(readFileSync(filePath, "utf8")));
}

function writeRecord(filePath, record) {
  validatePromotionRecord(record);
  const destination = path.resolve(filePath);
  const temporaryRoot = mkdtempSync(path.join(path.dirname(destination), ".promotion-"));
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

function npmJson(argumentsList) {
  const output = execFileSync("npm", [...argumentsList, "--json"], {
    encoding: "utf8",
    env: process.env,
    timeout: 120_000,
  }).trim();
  return output === "" ? null : JSON.parse(output);
}

function readLatest(packageName) {
  const value = npmJson(["view", packageName, "dist-tags.latest"]);
  return value === undefined ? null : value;
}

function readCandidate(packageName, candidateTag) {
  return npmJson(["view", packageName, `dist-tags.${candidateTag}`]);
}

function readAllLatest(record) {
  return Object.fromEntries(record.packages.map(({ name }) => [name, readLatest(name)]));
}

function requireReleaseAutomation(version, { recovery = false } = {}) {
  const expectedRef = `refs/tags/v${version}`;
  const tagRun = process.env.GITHUB_REF === expectedRef;
  const recoveryRun =
    recovery &&
    process.env.GITHUB_EVENT_NAME === "workflow_dispatch" &&
    process.env.SATELLE_RELEASE_RECOVERY === "1";
  if (
    process.env.GITHUB_ACTIONS !== "true" ||
    process.env.GITHUB_REPOSITORY !== "Microck/satelle" ||
    (!tagRun && !recoveryRun)
  ) {
    fail(
      "release-automation-required",
      "npm dist-tag mutation is limited to the Microck/satelle GitHub Actions release workflow",
    );
  }
}

function verifyCandidate(packageName, version, candidateTag, expectedIntegrity) {
  if (readCandidate(packageName, candidateTag) !== version) {
    fail(
      "release-candidate-missing",
      `${packageName}@${version} is not visible under ${candidateTag}`,
    );
  }
  const integrity = npmJson(["view", `${packageName}@${version}`, "dist.integrity"]);
  if (integrity !== expectedIntegrity) {
    fail(
      "release-candidate-integrity-mismatch",
      `${packageName}@${version} registry integrity differs from the validated artifact`,
    );
  }
}

function createRecordFromRegistry(version, recordPath, manifestPath) {
  requireReleaseAutomation(version);
  if (existsSync(recordPath)) {
    fail("promotion-record-exists", `promotion record already exists at ${recordPath}`);
  }
  const { createReleaseContext } = require("./release.cjs");
  const plan = createReleaseContext(path.resolve(__dirname, "../..")).check(`v${version}`);
  const manifest = JSON.parse(readFileSync(manifestPath, "utf8"));
  const manifestPackages = new Map(manifest.packages.map((entry) => [entry.package, entry]));
  const previousLatest = {};
  for (const packageName of plan.publicationOrder) {
    const artifact = manifestPackages.get(packageName);
    if (!artifact || artifact.version !== version || typeof artifact.integrity !== "string") {
      fail("promotion-record-invalid", `${packageName} is missing from npm-artifacts.json`);
    }
    verifyCandidate(packageName, version, `rc-v${version}`, artifact.integrity);
    previousLatest[packageName] = readLatest(packageName);
    if (previousLatest[packageName] === version) {
      fail(
        "promotion-state-conflict",
        `${packageName} already resolves latest to ${version} without a durable promotion record`,
      );
    }
  }
  const record = createPromotionRecord({
    version,
    packageNames: plan.publicationOrder,
    previousLatest,
  });
  writeRecord(recordPath, record);
  return record;
}

function advanceRecord(recordPath) {
  let record = readRecord(recordPath);
  requireReleaseAutomation(record.version, { recovery: record.mode === "rollback" });
  const entry = pendingEntry(record);
  if (!entry) return record;
  try {
    const operation = planRegistryOperation(record, readLatest(entry.name));
    if (operation.type === "set_latest") {
      execFileSync("npm", ["dist-tag", "add", `${entry.name}@${operation.version}`, "latest"], {
        stdio: "inherit",
        timeout: 120_000,
      });
    } else if (operation.type === "remove_latest") {
      execFileSync("npm", ["dist-tag", "rm", entry.name, "latest"], {
        stdio: "inherit",
        timeout: 120_000,
      });
    }
    const observedLatest = readLatest(entry.name);
    const isFinal = record.mode === "promotion" && record.packages.every(
      (candidate) => candidate.name === entry.name || candidate.promotionStatus === "promoted",
    );
    record = checkpointOperation(record, observedLatest, {
      allLatest: isFinal ? readAllLatest(record) : undefined,
    });
    writeRecord(recordPath, record);
    return record;
  } catch (error) {
    const promotionError = error instanceof PromotionError
      ? error
      : new PromotionError("promotion-command-failed", error.message);
    record = conflictedRecord(record, promotionError);
    writeRecord(recordPath, record);
    throw promotionError;
  }
}

function auditRecords(directory, currentVersion) {
  const latestByVersion = new Map();
  for (const fileName of require("node:fs").readdirSync(directory)) {
    if (!fileName.endsWith(".json")) continue;
    let record;
    try {
      record = readRecord(path.join(directory, fileName));
    } catch (error) {
      fail(
        "promotion-record-invalid",
        `${fileName} is not a valid npm promotion checkpoint: ${error.message}`,
      );
    }
    const previous = latestByVersion.get(record.version);
    if (!previous || record.sequence > previous.record.sequence) {
      latestByVersion.set(record.version, { fileName, record });
    } else if (
      record.sequence === previous.record.sequence &&
      JSON.stringify(record) !== JSON.stringify(previous.record)
    ) {
      fail(
        "promotion-record-conflict",
        `npm promotion ${record.version} has divergent checkpoints at sequence ${record.sequence}`,
      );
    }
  }
  for (const [version, { record }] of latestByVersion) {
    if (version !== currentVersion && !terminalStatuses.has(record.status)) {
      fail(
        "promotion-record-nonterminal",
        `npm promotion ${version} is ${record.status}; recover it before ${currentVersion}`,
      );
    }
  }
  return latestByVersion.get(currentVersion) ?? null;
}

function runCli() {
  const [command, ...argumentsList] = process.argv.slice(2);
  let output;
  if (command === "create") {
    output = createRecordFromRegistry(
      argumentsList[0],
      argumentsList[1],
      argumentsList[2],
    );
  } else if (command === "advance") {
    output = advanceRecord(argumentsList[0]);
  } else if (command === "abort") {
    let record = readRecord(argumentsList[0]);
    requireReleaseAutomation(record.version, { recovery: true });
    record = beginRollback(record);
    writeRecord(argumentsList[0], record);
    output = record;
  } else if (command === "audit-records") {
    output = auditRecords(argumentsList[0], argumentsList[1]);
  } else if (command === "status") {
    output = readRecord(argumentsList[0]);
  } else {
    fail("promotion-command-invalid", `unknown npm promotion command ${command ?? ""}`);
  }
  process.stdout.write(`${JSON.stringify(output)}\n`);
}

if (require.main === module) {
  try {
    runCli();
  } catch (error) {
    const code = error instanceof PromotionError ? error.code : "promotion-command-failed";
    process.stderr.write(`${JSON.stringify({ code, message: error.message })}\n`);
    process.exitCode = 1;
  }
}

module.exports = {
  PromotionError,
  auditRecords,
  beginRollback,
  checkpointOperation,
  createPromotionRecord,
  planRegistryOperation,
};
