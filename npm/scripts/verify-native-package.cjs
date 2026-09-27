"use strict";

const { accessSync, constants, readFileSync, statSync } = require("node:fs");
const { createHash } = require("node:crypto");
const path = require("node:path");

function fail(message) {
  console.error(`satelle: native-package-invalid: ${message}`);
  process.exit(1);
}

const packageRoot = process.cwd();
const manifest = JSON.parse(readFileSync(path.join(packageRoot, "package.json"), "utf8"));
const packagedFiles = manifest.files;

if (!Array.isArray(packagedFiles) || packagedFiles.length !== 2 || packagedFiles[1] !== "SHA256SUMS") {
  fail(`${manifest.name} must package one native binary and SHA256SUMS.`);
}

const binaryRelativePath = packagedFiles[0];
const expectedBinaryPath = manifest.os?.includes("win32") ? "bin/satelle.exe" : "bin/satelle";
if (binaryRelativePath !== expectedBinaryPath) {
  fail(`${manifest.name} must package ${expectedBinaryPath}, not ${binaryRelativePath}.`);
}

const binaryPath = path.join(packageRoot, binaryRelativePath);
try {
  accessSync(binaryPath, constants.R_OK);
  const binary = statSync(binaryPath);
  if (!binary.isFile()) {
    fail(`${binaryRelativePath} is not a regular file.`);
  }
  if (expectedBinaryPath !== "bin/satelle.exe" && (binary.mode & 0o111) === 0) {
    fail(`${binaryRelativePath} is not executable.`);
  }
  const digest = createHash("sha256").update(readFileSync(binaryPath)).digest("hex");
  if (readFileSync(path.join(packageRoot, "SHA256SUMS"), "utf8") !== `${digest}  ${binaryRelativePath}\n`) {
    fail("SHA256SUMS does not match the packaged executable.");
  }
} catch (error) {
  if (error?.code === "ENOENT") {
    fail(`${manifest.name} is missing its executable or SHA256SUMS; assemble the native artifact before packing.`);
  }
  throw error;
}
