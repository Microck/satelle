#!/usr/bin/env node
"use strict";

const { createHash } = require("node:crypto");
const { execFileSync, spawnSync } = require("node:child_process");
const {
  chmodSync,
  closeSync,
  constants: fsConstants,
  copyFileSync,
  existsSync,
  fstatSync,
  lstatSync,
  mkdirSync,
  mkdtempSync,
  openSync,
  readdirSync,
  readFileSync,
  readSync,
  renameSync,
  rmSync,
  statSync,
  writeSync,
  writeFileSync,
} = require("node:fs");
const { tmpdir } = require("node:os");
const path = require("node:path");
const { performance } = require("node:perf_hooks");
const { gunzipSync, inflateRawSync } = require("node:zlib");

const defaultRepositoryRoot = path.resolve(__dirname, "../..");
const maximumNativeBinaryBytes = 512 * 1024 * 1024;
const maximumNpmArtifactBytes = 512 * 1024 * 1024;
const maximumNativeReleaseArchiveBytes = maximumNpmArtifactBytes;
const launcherSmokeTimeoutMilliseconds = 9_000;
const defaultNpmCommandTimeoutMilliseconds = 300_000;
const defaultTarCommandTimeoutMilliseconds = 60_000;
const defaultNativeArchiveValidationTimeoutMilliseconds = 60_000;
const defaultNativeArchiveLimits = Object.freeze({
  maximumMembers: 256,
  maximumMemberBytes: maximumNativeBinaryBytes,
  maximumExpandedBytes: maximumNativeBinaryBytes,
});
const archiveWorkerCommand = "__inspect-native-release-archives";

function zipInflateMaximumOutputLength(declaredSize, limits) {
  return Math.min(
    declaredSize,
    limits.maximumMemberBytes,
    limits.maximumExpandedBytes,
  ) + 1;
}

class ReleaseError extends Error {
  constructor(code, message) {
    super(message);
    this.code = code;
  }
}

function fail(code, message) {
  throw new ReleaseError(code, message);
}

function readJson(filePath) {
  return JSON.parse(readFileSync(filePath, "utf8"));
}

function sameJson(left, right) {
  return JSON.stringify(left) === JSON.stringify(right);
}

function sortedObject(entries) {
  return Object.fromEntries(
    [...entries].sort(([left], [right]) => left.localeCompare(right)),
  );
}

function sha512Integrity(filePath) {
  const digest = createHash("sha512");
  const file = openSync(filePath, "r");
  const chunk = Buffer.allocUnsafe(1024 * 1024);
  try {
    let bytesRead;
    while ((bytesRead = readSync(file, chunk, 0, chunk.length, null)) !== 0) {
      digest.update(chunk.subarray(0, bytesRead));
    }
  } finally {
    closeSync(file);
  }
  return `sha512-${digest.digest("base64")}`;
}

function sha256Bytes(bytes) {
  return createHash("sha256").update(bytes).digest("hex");
}

function decodeArchiveName(bytes, label) {
  const name = bytes.toString("utf8");
  if (name.includes("\ufffd")) {
    fail("release-archive-invalid", `${label} contains a non-UTF-8 member name`);
  }
  return name;
}

function normalizeArchiveMember(member, label, type) {
  if (member.includes("\\") || (type === "file" && member.endsWith("/"))) {
    fail("release-archive-invalid", `${label} contains noncanonical member ${member}`);
  }
  let portable = member;
  if (
    portable.includes("\0") ||
    portable.startsWith("/") ||
    /^[A-Za-z]:\//.test(portable)
  ) {
    fail("release-archive-invalid", `${label} contains unsafe member ${member}`);
  }
  portable = portable.replace(/^(?:\.\/)+/, "").replace(/\/+$/, "");
  const components = portable.split("/");
  const normalizedComponents = components.filter((component) => component !== ".");
  if (
    !portable ||
    components.includes("") ||
    components.includes("..") ||
    normalizedComponents.some((component) => /[. ]$/.test(component)) ||
    normalizedComponents.length === 0 ||
    normalizedComponents[0].startsWith("-")
  ) {
    fail("release-archive-invalid", `${label} contains unsafe member ${member}`);
  }
  return normalizedComponents.join("/");
}

function readCheckedUInt64LE(buffer, offset, label) {
  if (offset < 0 || offset + 8 > buffer.length) {
    fail("release-binary-target-mismatch", `${label} contains an out-of-bounds integer`);
  }
  const value = buffer.readBigUInt64LE(offset);
  if (value > BigInt(Number.MAX_SAFE_INTEGER)) {
    fail("release-binary-target-mismatch", `${label} contains an unsupported large offset`);
  }
  return Number(value);
}

function checkedRange(offset, length, total, label, code = "release-archive-invalid") {
  if (
    !Number.isSafeInteger(offset) ||
    !Number.isSafeInteger(length) ||
    offset < 0 ||
    length < 0 ||
    offset > total ||
    length > total - offset
  ) {
    fail(code, `${label} contains an out-of-bounds range`);
  }
}

function parseTarNumber(field, label) {
  if ((field[0] & 0x80) !== 0) {
    fail("release-archive-invalid", `${label} uses an unsupported base-256 tar number`);
  }
  const value = field.toString("ascii").replace(/\0.*$/, "").trim();
  if (!/^[0-7]+$/.test(value)) {
    fail("release-archive-invalid", `${label} contains an invalid tar number`);
  }
  const parsed = Number.parseInt(value, 8);
  if (!Number.isSafeInteger(parsed)) {
    fail("release-archive-invalid", `${label} contains an oversized tar number`);
  }
  return parsed;
}

function accountArchiveMember(state, member, limits, label) {
  state.memberCount += 1;
  if (state.memberCount > limits.maximumMembers) {
    fail(
      "release-archive-limit-exceeded",
      `${label} contains more than ${limits.maximumMembers} members`,
    );
  }
  if (member.size > limits.maximumMemberBytes) {
    fail(
      "release-archive-limit-exceeded",
      `${label} member ${member.name} exceeds ${limits.maximumMemberBytes} expanded bytes`,
    );
  }
  if (member.size > limits.maximumExpandedBytes - state.expandedBytes) {
    fail(
      "release-archive-limit-exceeded",
      `${label} exceeds ${limits.maximumExpandedBytes} total expanded bytes`,
    );
  }
  state.expandedBytes += member.size;
  if (state.names.has(member.name)) {
    fail("release-archive-invalid", `${label} contains duplicate member ${member.name}`);
  }
  state.names.add(member.name);
  state.members.push(member);
}

function readArchiveBytes(source, label) {
  if (typeof source !== "number") return readFileSync(source);
  const metadata = fstatSync(source, { bigint: true });
  if (!metadata.isFile() || metadata.size > BigInt(Number.MAX_SAFE_INTEGER)) {
    fail("release-archive-invalid", `${label} is not a readable regular archive`);
  }
  const bytes = Buffer.allocUnsafe(Number(metadata.size));
  let offset = 0;
  while (offset < bytes.length) {
    const bytesRead = readSync(source, bytes, offset, bytes.length - offset, offset);
    if (bytesRead === 0) {
      fail("release-archive-invalid", `${label} ended before its pinned size`);
    }
    offset += bytesRead;
  }
  return bytes;
}

function parseTarArchive(archiveSource, label, limits, selectedNames) {
  const compressed = readArchiveBytes(archiveSource, label);
  const maximumContainerBytes =
    limits.maximumExpandedBytes + ((limits.maximumMembers + 2) * 512);
  let tar;
  try {
    tar = gunzipSync(compressed, { maxOutputLength: maximumContainerBytes });
  } catch {
    fail("release-archive-invalid", `${label} is not a bounded gzip tar archive`);
  }

  const state = { memberCount: 0, expandedBytes: 0, names: new Set(), members: [] };
  const selected = new Map();
  let offset = 0;
  let zeroBlocks = 0;
  while (offset + 512 <= tar.length) {
    const header = tar.subarray(offset, offset + 512);
    offset += 512;
    if (header.every((byte) => byte === 0)) {
      zeroBlocks += 1;
      if (zeroBlocks === 2) break;
      continue;
    }
    if (zeroBlocks !== 0) {
      fail("release-archive-invalid", `${label} contains data after a tar end marker`);
    }

    const expectedChecksum = parseTarNumber(header.subarray(148, 156), label);
    let actualChecksum = 0;
    for (let index = 0; index < header.length; index += 1) {
      actualChecksum += index >= 148 && index < 156 ? 0x20 : header[index];
    }
    if (expectedChecksum !== actualChecksum) {
      fail("release-archive-invalid", `${label} contains an invalid tar header checksum`);
    }

    const typeFlag = header[156];
    const type = typeFlag === 0 || typeFlag === 0x30
      ? "file"
      : typeFlag === 0x35
        ? "directory"
        : "special";
    const rawName = decodeArchiveName(header.subarray(0, 100), label).replace(/\0.*$/, "");
    const prefix = decodeArchiveName(header.subarray(345, 500), label).replace(/\0.*$/, "");
    const combinedName = prefix ? `${prefix}/${rawName}` : rawName;
    const name = normalizeArchiveMember(combinedName, label, type);
    const size = parseTarNumber(header.subarray(124, 136), `${label} member ${name}`);
    const mode = parseTarNumber(header.subarray(100, 108), `${label} member ${name}`);
    if (type === "special") {
      fail(
        "release-archive-invalid",
        `${label} member ${name} is a link, device, FIFO, or special entry`,
      );
    }
    if (type === "directory" && size !== 0) {
      fail("release-archive-invalid", `${label} directory ${name} has file contents`);
    }

    const member = { name, type, size, mode };
    accountArchiveMember(state, member, limits, label);
    checkedRange(offset, size, tar.length, `${label} member ${name}`);
    if (type === "file" && selectedNames.has(name)) {
      if (combinedName !== name) {
        fail("release-archive-invalid", `${label} contains noncanonical selected member ${combinedName}`);
      }
      selected.set(name, Buffer.from(tar.subarray(offset, offset + size)));
    }
    const paddedSize = Math.ceil(size / 512) * 512;
    checkedRange(offset, paddedSize, tar.length, `${label} member ${name}`);
    offset += paddedSize;
  }
  if (zeroBlocks !== 2 || tar.subarray(offset).some((byte) => byte !== 0)) {
    fail("release-archive-invalid", `${label} has a malformed tar end marker`);
  }
  return { members: state.members, expandedBytes: state.expandedBytes, selected };
}

let crc32Table;
function crc32(bytes) {
  if (!crc32Table) {
    crc32Table = Array.from({ length: 256 }, (_, value) => {
      let entry = value;
      for (let bit = 0; bit < 8; bit += 1) {
        entry = (entry & 1) !== 0 ? (entry >>> 1) ^ 0xedb88320 : entry >>> 1;
      }
      return entry >>> 0;
    });
  }
  let digest = 0xffffffff;
  for (const byte of bytes) digest = (digest >>> 8) ^ crc32Table[(digest ^ byte) & 0xff];
  return (digest ^ 0xffffffff) >>> 0;
}

function findZipEndOfCentralDirectory(zip, label) {
  if (zip.length < 22) {
    fail("release-archive-invalid", `${label} is too short to be a ZIP archive`);
  }
  const minimumOffset = Math.max(0, zip.length - 65_557);
  for (let offset = zip.length - 22; offset >= minimumOffset; offset -= 1) {
    if (zip.readUInt32LE(offset) !== 0x06054b50) continue;
    const commentLength = zip.readUInt16LE(offset + 20);
    if (offset + 22 + commentLength === zip.length) return offset;
  }
  fail("release-archive-invalid", `${label} has no valid ZIP end record`);
}

function zipMemberType(name, versionMadeBy, externalAttributes) {
  const creator = versionMadeBy >>> 8;
  const unixType = creator === 3 ? (externalAttributes >>> 16) & 0xf000 : 0;
  const dosAttributes = externalAttributes & 0xffff;
  if ((dosAttributes & (0x0040 | 0x0400)) !== 0) return "special";
  if (unixType === 0x8000) return "file";
  if (unixType === 0x4000) return "directory";
  if (unixType !== 0) return "special";
  return name.endsWith("/") || (externalAttributes & 0x10) !== 0
    ? "directory"
    : "file";
}

function parseZipExtraFields(bytes, label, location) {
  const fields = [];
  const identifiers = new Set();
  let cursor = 0;
  while (cursor < bytes.length) {
    checkedRange(cursor, 4, bytes.length, `${label} ZIP extra field`);
    const identifier = bytes.readUInt16LE(cursor);
    const size = bytes.readUInt16LE(cursor + 2);
    checkedRange(cursor + 4, size, bytes.length, `${label} ZIP extra field`);
    if (identifiers.has(identifier)) {
      fail(
        "release-archive-invalid",
        `${label} repeats ZIP extra field 0x${identifier.toString(16).padStart(4, "0")}`,
      );
    }
    identifiers.add(identifier);
    const contents = bytes.subarray(cursor + 4, cursor + 4 + size);

    // Only the Extended Timestamp field is extraction-inert for this release
    // contract. An allowlist prevents path or type aliases such as Unicode Path
    // (0x7075) and ASi Unix (0x756e), including future fields unknown here.
    if (identifier !== 0x5455) {
      fail(
        "release-archive-invalid",
        `${label} uses unsupported ZIP extra field 0x${identifier.toString(16).padStart(4, "0")}`,
      );
    }
    if (contents.length < 1) {
      fail("release-archive-invalid", `${label} has a malformed ZIP timestamp field`);
    }
    const flags = contents[0];
    const timestampCount = Number(Boolean(flags & 1)) +
      Number(Boolean(flags & 2)) + Number(Boolean(flags & 4));
    // The central form can represent only modification time. Normalize both
    // forms to that shared semantic value before comparing the inventories.
    const timestampBytes = location === "central"
      ? Number(Boolean(flags & 1)) * 4
      : timestampCount * 4;
    if (
      flags === 0 ||
      (flags & ~7) !== 0 ||
      (location === "central" && flags !== 1) ||
      contents.length !== 1 + timestampBytes
    ) {
      fail("release-archive-invalid", `${label} has a malformed ZIP timestamp field`);
    }
    fields.push({
      identifier,
      modifiedTime: (flags & 1) !== 0 ? contents.readUInt32LE(1) : undefined,
    });
    cursor += 4 + size;
  }
  return fields.sort((left, right) => left.identifier - right.identifier);
}

function parseZipArchive(archiveSource, label, limits, selectedNames) {
  const zip = readArchiveBytes(archiveSource, label);
  const endOffset = findZipEndOfCentralDirectory(zip, label);
  const disk = zip.readUInt16LE(endOffset + 4);
  const centralDisk = zip.readUInt16LE(endOffset + 6);
  const entriesOnDisk = zip.readUInt16LE(endOffset + 8);
  const entryCount = zip.readUInt16LE(endOffset + 10);
  const centralSize = zip.readUInt32LE(endOffset + 12);
  const centralOffset = zip.readUInt32LE(endOffset + 16);
  if (
    disk !== 0 ||
    centralDisk !== 0 ||
    entriesOnDisk !== entryCount ||
    entryCount === 0xffff ||
    centralSize === 0xffffffff ||
    centralOffset === 0xffffffff
  ) {
    fail("release-archive-invalid", `${label} uses unsupported multi-disk or ZIP64 metadata`);
  }
  checkedRange(centralOffset, centralSize, zip.length, `${label} central directory`);
  if (centralOffset + centralSize !== endOffset) {
    fail("release-archive-invalid", `${label} has data outside its ZIP inventory`);
  }

  const state = { memberCount: 0, expandedBytes: 0, names: new Set(), members: [] };
  const centralEntries = [];
  let cursor = centralOffset;
  for (let index = 0; index < entryCount; index += 1) {
    checkedRange(cursor, 46, endOffset, `${label} central entry`);
    if (zip.readUInt32LE(cursor) !== 0x02014b50) {
      fail("release-archive-invalid", `${label} has a malformed ZIP central entry`);
    }
    const versionMadeBy = zip.readUInt16LE(cursor + 4);
    const flags = zip.readUInt16LE(cursor + 8);
    const method = zip.readUInt16LE(cursor + 10);
    const expectedCrc32 = zip.readUInt32LE(cursor + 16);
    const compressedSize = zip.readUInt32LE(cursor + 20);
    const size = zip.readUInt32LE(cursor + 24);
    const nameLength = zip.readUInt16LE(cursor + 28);
    const extraLength = zip.readUInt16LE(cursor + 30);
    const commentLength = zip.readUInt16LE(cursor + 32);
    const externalAttributes = zip.readUInt32LE(cursor + 38);
    const localOffset = zip.readUInt32LE(cursor + 42);
    const entryLength = 46 + nameLength + extraLength + commentLength;
    checkedRange(cursor, entryLength, endOffset, `${label} central entry`);
    if (
      compressedSize === 0xffffffff ||
      size === 0xffffffff ||
      localOffset === 0xffffffff
    ) {
      fail("release-archive-invalid", `${label} uses unsupported ZIP64 member metadata`);
    }
    const rawName = decodeArchiveName(zip.subarray(cursor + 46, cursor + 46 + nameLength), label);
    const extraOffset = cursor + 46 + nameLength;
    const extraFields = parseZipExtraFields(
      zip.subarray(extraOffset, extraOffset + extraLength),
      `${label} central entry ${rawName}`,
      "central",
    );
    const type = zipMemberType(rawName, versionMadeBy, externalAttributes);
    const name = normalizeArchiveMember(rawName, label, type);
    if (type === "special") {
      fail(
        "release-archive-invalid",
        `${label} member ${name} is a link, device, FIFO, or special entry`,
      );
    }
    if ((flags & ~0x0808) !== 0 || (type === "file" && method !== 0 && method !== 8)) {
      fail("release-archive-invalid", `${label} member ${name} uses unsupported ZIP encoding`);
    }
    if (type === "directory" && (size !== 0 || compressedSize !== 0)) {
      fail("release-archive-invalid", `${label} directory ${name} has file contents`);
    }
    const mode = (externalAttributes >>> 16) & 0o7777;
    accountArchiveMember(state, { name, type, size, mode }, limits, label);
    centralEntries.push({
      name,
      rawName,
      type,
      size,
      mode,
      flags,
      method,
      expectedCrc32,
      compressedSize,
      localOffset,
      extraFields,
    });
    cursor += entryLength;
  }
  if (cursor !== endOffset || state.memberCount !== entryCount) {
    fail("release-archive-invalid", `${label} has an incomplete ZIP inventory`);
  }

  const selected = new Map();
  cursor = 0;
  for (const entry of [...centralEntries].sort((left, right) => left.localOffset - right.localOffset)) {
    if (entry.localOffset !== cursor) {
      fail("release-archive-invalid", `${label} has unaccounted ZIP local data`);
    }
    checkedRange(cursor, 30, centralOffset, `${label} local entry`);
    if (zip.readUInt32LE(cursor) !== 0x04034b50) {
      fail("release-archive-invalid", `${label} has a malformed ZIP local entry`);
    }
    const flags = zip.readUInt16LE(cursor + 6);
    const method = zip.readUInt16LE(cursor + 8);
    const localCrc32 = zip.readUInt32LE(cursor + 14);
    const localCompressedSize = zip.readUInt32LE(cursor + 18);
    const localSize = zip.readUInt32LE(cursor + 22);
    const nameLength = zip.readUInt16LE(cursor + 26);
    const extraLength = zip.readUInt16LE(cursor + 28);
    const dataOffset = cursor + 30 + nameLength + extraLength;
    checkedRange(cursor, 30 + nameLength + extraLength, centralOffset, `${label} local entry`);
    const localName = decodeArchiveName(zip.subarray(cursor + 30, cursor + 30 + nameLength), label);
    const localExtraOffset = cursor + 30 + nameLength;
    const localExtraFields = parseZipExtraFields(
      zip.subarray(localExtraOffset, localExtraOffset + extraLength),
      `${label} local entry ${localName}`,
      "local",
    );
    if (
      localName !== entry.rawName ||
      flags !== entry.flags ||
      method !== entry.method ||
      !sameJson(localExtraFields, entry.extraFields)
    ) {
      fail("release-archive-invalid", `${label} local and central ZIP metadata differ`);
    }
    if (
      (entry.flags & 0x08) === 0 &&
      (localCrc32 !== entry.expectedCrc32 ||
        localCompressedSize !== entry.compressedSize ||
        localSize !== entry.size)
    ) {
      fail("release-archive-invalid", `${label} local and central ZIP sizes differ`);
    }
    checkedRange(dataOffset, entry.compressedSize, centralOffset, `${label} member ${entry.name}`);
    const compressed = zip.subarray(dataOffset, dataOffset + entry.compressedSize);
    let contents;
    try {
      contents = entry.type === "directory"
        ? Buffer.alloc(0)
        : entry.method === 0
          ? Buffer.from(compressed)
            : inflateRawSync(compressed, {
              maxOutputLength: zipInflateMaximumOutputLength(entry.size, limits),
            });
    } catch {
      fail("release-archive-invalid", `${label} member ${entry.name} cannot be decompressed`);
    }
    if (contents.length !== entry.size || crc32(contents) !== entry.expectedCrc32) {
      fail("release-archive-invalid", `${label} member ${entry.name} has corrupt ZIP contents`);
    }
    if (entry.type === "file" && selectedNames.has(entry.name)) {
      if (entry.rawName !== entry.name) {
        fail(
          "release-archive-invalid",
          `${label} contains noncanonical selected member ${entry.rawName}`,
        );
      }
      selected.set(entry.name, contents);
    }
    cursor = dataOffset + entry.compressedSize;
    if ((entry.flags & 0x08) !== 0) {
      checkedRange(cursor, 4, centralOffset, `${label} ZIP data descriptor`);
      const descriptorOffset = zip.readUInt32LE(cursor) === 0x08074b50 ? cursor + 4 : cursor;
      checkedRange(descriptorOffset, 12, centralOffset, `${label} ZIP data descriptor`);
      if (
        zip.readUInt32LE(descriptorOffset) !== entry.expectedCrc32 ||
        zip.readUInt32LE(descriptorOffset + 4) !== entry.compressedSize ||
        zip.readUInt32LE(descriptorOffset + 8) !== entry.size
      ) {
        fail("release-archive-invalid", `${label} has a corrupt ZIP data descriptor`);
      }
      cursor = descriptorOffset + 12;
    }
  }
  if (cursor !== centralOffset) {
    fail("release-archive-invalid", `${label} has unaccounted ZIP local data`);
  }
  return { members: state.members, expandedBytes: state.expandedBytes, selected };
}

function inspectNativeReleaseArchive(request, release) {
  const selectedNames = new Set(request.selections.map(({ member }) => member));
  const parsed = request.format === "zip"
    ? parseZipArchive(request.archiveDescriptor, request.label, request.limits, selectedNames)
    : parseTarArchive(request.archiveDescriptor, request.label, request.limits, selectedNames);
  if (request.postInventoryDelayMilliseconds > 0) {
    Atomics.wait(
      new Int32Array(new SharedArrayBuffer(4)),
      0,
      0,
      request.postInventoryDelayMilliseconds,
    );
  }
  const selections = [];
  for (const selection of request.selections) {
    const contents = parsed.selected.get(selection.member);
    if (!contents) {
      fail(
        "release-archive-invalid",
        `${request.label} does not contain selected member ${selection.member}`,
      );
    }
    const digest = sha256Bytes(contents);
    if (selection.kind === "native") {
      release.validateNativeBinary(
        selection.target,
        contents,
        `${request.label} member ${selection.member}`,
      );
    } else if (selection.kind === "manifest") {
      let manifest;
      try {
        manifest = JSON.parse(contents);
      } catch {
        fail("release-artifact-invalid", `${request.label} has invalid package metadata`);
      }
      if (
        manifest.name !== selection.expectedName ||
        manifest.version !== selection.expectedVersion ||
        digest !== selection.expectedSha256
      ) {
        fail(
          "release-artifact-metadata-mismatch",
          `${request.label} does not contain ${selection.expectedName}@${selection.expectedVersion}`,
        );
      }
    } else {
      fail("release-archive-invalid", `${request.label} has an unknown selected member check`);
    }
    selections.push({ member: selection.member, sha256: digest });
  }
  return { members: parsed.members, expandedBytes: parsed.expandedBytes, selections };
}

function runArchiveWorker() {
  const requests = JSON.parse(process.argv[3]);
  const releases = new Map();
  const inventories = requests.map((request) => {
    let release = releases.get(request.repositoryRoot);
    if (!release) {
      release = createReleaseContext(request.repositoryRoot, {
        matrixSnapshot: request.matrixSnapshot,
      });
      releases.set(request.repositoryRoot, release);
    }
    return inspectNativeReleaseArchive(request, release);
  });
  process.stdout.write(JSON.stringify(inventories));
}

function createReleaseContext(repositoryRoot = defaultRepositoryRoot, options = {}) {
  const npmRoot = path.join(repositoryRoot, "npm");
  const npmCommandTimeoutMilliseconds =
    options.npmCommandTimeoutMilliseconds ?? defaultNpmCommandTimeoutMilliseconds;
  const tarCommandTimeoutMilliseconds =
    options.tarCommandTimeoutMilliseconds ?? defaultTarCommandTimeoutMilliseconds;
  const nativeArchiveValidationTimeoutMilliseconds =
    options.nativeArchiveValidationTimeoutMilliseconds ??
    defaultNativeArchiveValidationTimeoutMilliseconds;
  const nativeArchivePostInventoryDelayMilliseconds =
    options.nativeArchivePostInventoryDelayMilliseconds ?? 0;
  const afterNativeArchiveSnapshots = options.afterNativeArchiveSnapshots;
  const afterNativeArchiveSourceChunk = options.afterNativeArchiveSourceChunk;
  const observeNativeArchiveSourceRead = options.observeNativeArchiveSourceRead;
  const beforeNativeArchiveFinalSourceValidation =
    options.beforeNativeArchiveFinalSourceValidation;
  const afterLauncherInstall = options.afterLauncherInstall;
  const nativeArchiveLimits = Object.freeze({
    ...defaultNativeArchiveLimits,
    ...(options.nativeArchiveLimits ?? {}),
  });
  for (const [name, value] of Object.entries(nativeArchiveLimits)) {
    if (
      !Object.hasOwn(defaultNativeArchiveLimits, name) ||
      !Number.isSafeInteger(value) ||
      value <= 0 ||
      value > defaultNativeArchiveLimits[name]
    ) {
      fail(
        "release-archive-limit-invalid",
        `${name} must be positive and no greater than its production cap`,
      );
    }
  }
  if (
    !Number.isSafeInteger(nativeArchiveValidationTimeoutMilliseconds) ||
    nativeArchiveValidationTimeoutMilliseconds <= 0 ||
    nativeArchiveValidationTimeoutMilliseconds > defaultNativeArchiveValidationTimeoutMilliseconds
  ) {
    fail(
      "release-archive-limit-invalid",
      "the native archive deadline must be positive and no greater than its production cap",
    );
  }
  for (const [name, observer] of Object.entries({
    afterNativeArchiveSnapshots,
    afterNativeArchiveSourceChunk,
    observeNativeArchiveSourceRead,
    beforeNativeArchiveFinalSourceValidation,
    afterLauncherInstall,
  })) {
    if (observer !== undefined && typeof observer !== "function") {
      fail("release-archive-limit-invalid", `${name} must be a function`);
    }
  }
  if (
    !Number.isSafeInteger(nativeArchivePostInventoryDelayMilliseconds) ||
    nativeArchivePostInventoryDelayMilliseconds < 0 ||
    nativeArchivePostInventoryDelayMilliseconds > defaultNativeArchiveValidationTimeoutMilliseconds
  ) {
    fail(
      "release-archive-limit-invalid",
      "the post-inventory validation delay must be nonnegative and bounded by the production deadline",
    );
  }
  const matrix = options.matrixSnapshot ?? readJson(path.join(npmRoot, "satelle", "platforms.json"));
  const targets = Object.keys(matrix).sort();
  const nativePackages = targets.map((target) => matrix[target].packageName);
  const topLevelPackages = ["@microck/satelle", "satelle"];
  const publicationOrder = [...nativePackages, ...topLevelPackages];

  function packageDirectory(packageName) {
    if (packageName === "@microck/satelle") return "satelle";
    if (packageName === "satelle") return "satelle-unscoped";
    const target = targets.find((candidate) => matrix[candidate].packageName === packageName);
    if (!target) fail("release-package-unknown", `unknown release package ${packageName}`);
    return `satelle-${target}`;
  }

  function packageManifestPath(packageName) {
    return path.join(npmRoot, packageDirectory(packageName), "package.json");
  }

  function readWorkspaceVersion() {
    const cargo = readFileSync(path.join(repositoryRoot, "Cargo.toml"), "utf8");
    const workspacePackage = cargo.match(/\[workspace\.package\]([\s\S]*?)(?:\n\[|$)/);
    const version = workspacePackage?.[1].match(/^version\s*=\s*"([^"]+)"/m)?.[1];
    if (!version) fail("release-version-missing", "Cargo workspace version is missing");
    return version;
  }

  function validatePublishMetadata(packageName, manifest) {
    if (
      manifest.private === true ||
      manifest.publishConfig?.access !== "public" ||
      manifest.publishConfig?.provenance !== true
    ) {
      fail(
        "release-package-metadata-mismatch",
        `${packageName} must enable public npm provenance`,
      );
    }
    for (const lifecycle of ["preinstall", "install", "postinstall", "prepare"]) {
      if (manifest.scripts?.[lifecycle] !== undefined) {
        fail(
          "release-package-metadata-mismatch",
          `${packageName} defines forbidden consumer lifecycle script ${lifecycle}`,
        );
      }
    }
  }

  function validatePackageGraph(version) {
    const manifests = new Map();
    const manifestBytes = new Map();
    for (const packageName of publicationOrder) {
      const bytes = readFileSync(packageManifestPath(packageName));
      const manifest = JSON.parse(bytes);
      manifests.set(packageName, manifest);
      manifestBytes.set(packageName, bytes);
      if (manifest.name !== packageName) {
        fail(
          "release-package-metadata-mismatch",
          `${packageName} manifest declares ${manifest.name ?? "no package name"}`,
        );
      }
      if (manifest.version !== version) {
        fail(
          "release-version-mismatch",
          `${packageName} has version ${manifest.version}; expected ${version}`,
        );
      }
      validatePublishMetadata(packageName, manifest);
    }

    const scoped = manifests.get("@microck/satelle");
    const expectedOptionalDependencies = sortedObject(
      nativePackages.map((packageName) => [packageName, version]),
    );
    const actualOptionalDependencies = sortedObject(
      Object.entries(scoped.optionalDependencies ?? {}),
    );
    if (!sameJson(actualOptionalDependencies, expectedOptionalDependencies)) {
      fail(
        "release-package-graph-mismatch",
        "the scoped package optionalDependencies do not exactly match the native target matrix",
      );
    }
    if (scoped.dependencies !== undefined || scoped.peerDependencies !== undefined) {
      fail(
        "release-package-graph-mismatch",
        "@microck/satelle defines unexpected install-time dependency edges",
      );
    }
    if (
      scoped.bin?.satelle !== "bin/satelle.cjs" ||
      !sameJson(scoped.exports, { "./launcher": "./bin/satelle.cjs" }) ||
      !sameJson(scoped.files, ["bin/satelle.cjs", "lib/launcher.cjs", "platforms.json"])
    ) {
      fail(
        "release-package-metadata-mismatch",
        "@microck/satelle executable ownership does not match the canonical launcher",
      );
    }

    const unscoped = manifests.get("satelle");
    if (
      !sameJson(unscoped.dependencies, { "@microck/satelle": version }) ||
      unscoped.optionalDependencies !== undefined ||
      unscoped.peerDependencies !== undefined ||
      unscoped.bin?.satelle !== "bin/satelle.cjs" ||
      !sameJson(unscoped.files, ["bin/satelle.cjs"])
    ) {
      fail(
        "release-package-metadata-mismatch",
        "satelle must forward its executable to the exact canonical package version",
      );
    }

    for (const target of targets) {
      const targetMetadata = matrix[target];
      const manifest = manifests.get(targetMetadata.packageName);
      const expectedLibc = targetMetadata.libc ? [targetMetadata.libc] : undefined;
      if (
        manifest.dependencies !== undefined ||
        manifest.optionalDependencies !== undefined ||
        manifest.peerDependencies !== undefined
      ) {
        fail(
          "release-package-graph-mismatch",
          `${targetMetadata.packageName} defines unexpected install-time dependency edges`,
        );
      }
      if (
        !sameJson(manifest.os, [targetMetadata.os]) ||
        !sameJson(manifest.cpu, [targetMetadata.cpu]) ||
        !sameJson(manifest.libc, expectedLibc) ||
        !sameJson(manifest.files, [targetMetadata.binaryPath]) ||
        manifest.bin !== undefined ||
        manifest.scripts?.prepack !== "node ../scripts/verify-native-package.cjs"
      ) {
        fail(
          "release-package-metadata-mismatch",
          `${targetMetadata.packageName} does not match target ${target}`,
        );
      }
    }
    return manifestBytes;
  }

  function validateReadme() {
    const readmeSource = readFileSync(path.join(repositoryRoot, "README.md"), "utf8");
    const guidanceSource = readmeSource.replace(/\\\r?\n\s*/g, " ");
    const readme = readmeSource.replace(/^> ?/gm, "").replace(/\s+/g, " ");
    const requiredGuidance = [
      "Satelle is pre-release software. Build it from source.",
      "reserved by this repository are not published installation paths yet.",
      "Source builds are the only documented installation path until release publication is complete.",
    ];
    const publicNpmGuidance = [
      /\bnpm\s+(?:install|i|exec)\b[^\n`]*\b(?:@microck\/satelle|satelle)\b/i,
      /\bpnpm\s+(?:add|dlx)\b[^\n`]*\b(?:@microck\/satelle|satelle)\b/i,
      /\bpnpm\s+--package(?:=|\s+)(?:@microck\/satelle|satelle)\s+dlx\b/i,
      /\b(?:npx|bunx)\b[^\n`]*\b(?:@microck\/satelle|satelle)\b/i,
      /\bbun\s+add\b[^\n`]*\b(?:@microck\/satelle|satelle)\b/i,
    ];
    if (
      requiredGuidance.some((text) => !readme.includes(text)) ||
      publicNpmGuidance.some((pattern) => pattern.test(guidanceSource))
    ) {
      fail(
        "release-readme-mismatch",
        "README installation guidance must keep npm packages unavailable before publication",
      );
    }
  }

  function validateReleaseState(tag) {
    const version = readWorkspaceVersion();
    if (tag !== undefined && tag !== `v${version}`) {
      fail(
        "release-version-mismatch",
        `release tag ${tag} does not match workspace version v${version}`,
      );
    }
    const manifestBytes = validatePackageGraph(version);
    validateReadme();
    return { version, manifestBytes };
  }

  function expectedVersion(tag) {
    return validateReleaseState(tag).version;
  }

  function expectedArchiveName(version, target) {
    const extension = target.startsWith("win32-") ? "zip" : "tar.gz";
    return `satelle-v${version}-${target}.${extension}`;
  }

  function npmArtifactName(packageName) {
    if (packageName === "@microck/satelle") return "npm-satelle-scoped.tgz";
    if (packageName === "satelle") return "npm-satelle-unscoped.tgz";
    const target = targets.find((candidate) => matrix[candidate].packageName === packageName);
    return `npm-${target}.tgz`;
  }

  function check(tag) {
    const version = expectedVersion(tag);
    return {
      schemaVersion: "satelle.release-plan.v1",
      version,
      targets: [...targets],
      publicationOrder: [...publicationOrder],
      artifacts: targets.map((target) => ({
        target,
        package: matrix[target].packageName,
        archive: expectedArchiveName(version, target),
        npmArtifact: npmArtifactName(matrix[target].packageName),
      })),
    };
  }

  function resolveNpmCli() {
    const npmCli = [
      process.env.npm_execpath,
      path.join(path.dirname(process.execPath), "node_modules", "npm", "bin", "npm-cli.js"),
      path.resolve(
        path.dirname(process.execPath),
        "../lib/node_modules/npm/bin/npm-cli.js",
      ),
    ].find((candidate) => candidate && existsSync(candidate));
    if (!npmCli) {
      fail("release-npm-missing", "the npm CLI could not be resolved from the Node.js installation");
    }
    return npmCli;
  }

  function runNpm(
    argumentsList,
    cwd = repositoryRoot,
    timeoutMilliseconds = npmCommandTimeoutMilliseconds,
  ) {
    try {
      return execFileSync(
        process.execPath,
        [resolveNpmCli(), ...argumentsList],
        {
          cwd,
          encoding: "utf8",
          env: { ...process.env, npm_config_ignore_scripts: "false" },
          killSignal: "SIGKILL",
          shell: false,
          timeout: timeoutMilliseconds,
        },
      );
    } catch (error) {
      if (error.code === "ETIMEDOUT") {
        fail(
          "release-command-timeout",
          `npm ${argumentsList[0] ?? "command"} exceeded ${timeoutMilliseconds}ms`,
        );
      }
      throw error;
    }
  }

  function npmPack(packageRoot, destination, options = {}) {
    const packDestination = path.resolve(destination);
    mkdirSync(packDestination, { recursive: true });
    const output = runNpm([
      "pack",
      ...(options.ignoreScripts ? ["--ignore-scripts"] : []),
      "--json",
      "--silent",
      "--pack-destination",
      packDestination,
      packageRoot,
    ]);
    const [metadata] = JSON.parse(output);
    return { metadata, archivePath: path.join(packDestination, metadata.filename) };
  }

  function runTar(argumentsList, options = {}) {
    return execFileSync("tar", argumentsList, {
      ...options,
      killSignal: "SIGKILL",
      timeout: tarCommandTimeoutMilliseconds,
    });
  }

  function requireFile(filePath, code, message) {
    if (!filePath || !existsSync(filePath) || !statSync(filePath).isFile()) {
      fail(code, message);
    }
  }

  function remainingDeadline(deadline, label) {
    const remaining = deadline - performance.now();
    if (remaining <= 0) {
      fail(
        "release-archive-timeout",
        `${label} exceeded the ${nativeArchiveValidationTimeoutMilliseconds}ms total deadline`,
      );
    }
    return Math.ceil(remaining);
  }

  function sameFileIdentity(left, right) {
    return left.dev === right.dev && left.ino === right.ino;
  }

  function sameOpenFileState(left, right) {
    return (
      sameFileIdentity(left, right) &&
      left.size === right.size &&
      left.mtimeNs === right.mtimeNs &&
      left.ctimeNs === right.ctimeNs
    );
  }

  function snapshotArtifact(sourcePath, snapshotPath, label, maximumBytes, deadline) {
    let pathState;
    try {
      pathState = lstatSync(sourcePath, { bigint: true });
    } catch {
      fail("release-archive-set-incomplete", `missing release artifact ${label}`);
    }
    if (!pathState.isFile() || pathState.isSymbolicLink()) {
      fail("release-archive-invalid", `${label} must be a regular non-link file`);
    }

    let source;
    let destination;
    let keepDestinationOpen = false;
    const noFollow = fsConstants.O_NOFOLLOW ?? 0;
    try {
      source = openSync(sourcePath, fsConstants.O_RDONLY | noFollow);
    } catch {
      fail("release-archive-invalid", `${label} cannot be opened without following links`);
    }
    try {
      const openedState = fstatSync(source, { bigint: true });
      if (
        !openedState.isFile() ||
        !sameFileIdentity(pathState, openedState) ||
        openedState.size <= 0n ||
        openedState.size >= BigInt(maximumBytes)
      ) {
        fail(
          "release-archive-invalid",
          `${label} must be a stable regular file smaller than ${maximumBytes} bytes`,
        );
      }
      destination = openSync(
        snapshotPath,
        fsConstants.O_RDWR | fsConstants.O_CREAT | fsConstants.O_EXCL,
        0o600,
      );
      const digest = createHash("sha256");
      const chunk = Buffer.allocUnsafe(1024 * 1024);
      const expectedBytes = Number(openedState.size);
      let position = 0;
      let observedSourceChunk = false;
      while (position < expectedBytes) {
        remainingDeadline(deadline, label);
        const requested = Math.min(chunk.length, expectedBytes - position);
        const bytesRead = readSync(source, chunk, 0, requested, position);
        observeNativeArchiveSourceRead?.({
          label,
          sourcePath,
          bytesRead,
          position: position + bytesRead,
          expectedBytes,
        });
        if (bytesRead === 0) {
          fail("release-integrity-mismatch", `${label} was truncated while snapshotted`);
        }
        digest.update(chunk.subarray(0, bytesRead));
        let written = 0;
        while (written < bytesRead) {
          written += writeSync(
            destination,
            chunk,
            written,
            bytesRead - written,
            position + written,
          );
        }
        position += bytesRead;
        if (!observedSourceChunk) {
          observedSourceChunk = true;
          afterNativeArchiveSourceChunk?.({ label, sourcePath });
        }
      }
      const finalOpenState = fstatSync(source, { bigint: true });
      let finalPathState;
      try {
        finalPathState = lstatSync(sourcePath, { bigint: true });
      } catch {
        fail("release-integrity-mismatch", `${label} was replaced while it was snapshotted`);
      }
      if (
        BigInt(position) !== openedState.size ||
        !sameOpenFileState(openedState, finalOpenState) ||
        !finalPathState.isFile() ||
        finalPathState.isSymbolicLink() ||
        !sameFileIdentity(finalOpenState, finalPathState)
      ) {
        fail("release-integrity-mismatch", `${label} changed while it was snapshotted`);
      }
      const snapshotState = fstatSync(destination, { bigint: true });
      if (snapshotState.size !== openedState.size) {
        fail("release-integrity-mismatch", `${label} snapshot has an incomplete size`);
      }
      keepDestinationOpen = true;
      return {
        handle: destination,
        initialState: snapshotState,
        sourcePath,
        sourceState: finalOpenState,
        snapshotPath,
        digest: digest.digest("hex"),
        label,
      };
    } finally {
      if (destination !== undefined && !keepDestinationOpen) closeSync(destination);
      closeSync(source);
    }
  }

  function validateSnapshotSource(snapshot) {
    let sourcePathState;
    try {
      sourcePathState = lstatSync(snapshot.sourcePath, { bigint: true });
    } catch {
      fail("release-integrity-mismatch", `${snapshot.label} source path was replaced`);
    }
    if (
      !sourcePathState.isFile() ||
      sourcePathState.isSymbolicLink() ||
      !sameOpenFileState(snapshot.sourceState, sourcePathState)
    ) {
      fail("release-integrity-mismatch", `${snapshot.label} source changed during validation`);
    }
  }

  function inspectArchiveSnapshots(requests, deadline) {
    const workerRequests = requests.map(({ archiveHandle, ...request }, index) => ({
      ...request,
      archiveDescriptor: index + 3,
    }));
    const child = spawnSync(
      process.execPath,
      [__filename, archiveWorkerCommand, JSON.stringify(workerRequests)],
      {
        encoding: "utf8",
        killSignal: "SIGKILL",
        maxBuffer: 2 * 1024 * 1024,
        stdio: ["ignore", "pipe", "pipe", ...requests.map(({ archiveHandle }) => archiveHandle)],
        timeout: remainingDeadline(deadline, "native release archive validation"),
      },
    );
    if (child.error?.code === "ETIMEDOUT" || child.signal === "SIGKILL") {
      fail(
        "release-archive-timeout",
        `native release archive validation exceeded the ${nativeArchiveValidationTimeoutMilliseconds}ms total deadline`,
      );
    }
    if (child.status !== 0) {
      let reported;
      try {
        reported = JSON.parse(child.stderr);
      } catch {
        reported = undefined;
      }
      fail(
        reported?.code ?? "release-archive-invalid",
        reported?.message ?? "native release archive inspection failed",
      );
    }
    try {
      return JSON.parse(child.stdout);
    } catch {
      fail("release-archive-invalid", "native release archive inspection returned invalid data");
    }
  }

  function validateArchiveInventory(target, archiveName, inventory) {
    const metadata = matrix[target];
    const executableName = metadata.os === "win32" ? "satelle.exe" : "satelle";
    const rootFiles = inventory.members.filter(
      ({ name, type }) => type === "file" && !name.includes("/"),
    );
    const executable = rootFiles.filter(({ name }) => name === executableName);
    if (executable.length !== 1) {
      fail(
        "release-archive-invalid",
        `${archiveName} must contain exactly one root ${executableName} executable`,
      );
    }
    if (metadata.os === "win32") {
      const rootExecutables = rootFiles.filter(({ name }) => /\.(?:exe|com|bat|cmd)$/i.test(name));
      if (rootExecutables.length !== 1 || rootExecutables[0].name !== executableName) {
        fail(
          "release-archive-invalid",
          `${archiveName} must contain exactly one root ${executableName} executable`,
        );
      }
    } else {
      const rootExecutables = rootFiles.filter(({ mode }) => (mode & 0o111) !== 0);
      if (
        rootExecutables.length !== 1 ||
        rootExecutables[0].name !== executableName ||
        (executable[0].mode & 0o7777) !== 0o755
      ) {
        fail(
          "release-archive-invalid",
          `${archiveName} root ${executableName} is not the sole regular root executable`,
        );
      }
    }
  }

  function validateNativeBinary(target, binary, label) {
    const metadata = matrix[target];
    try {
      if (metadata.os === "linux") {
        const expectedMachine = metadata.cpu === "arm64" ? 183 : 62;
        const expectedInterpreter = metadata.cpu === "arm64"
          ? "/lib/ld-linux-aarch64.so.1"
          : "/lib64/ld-linux-x86-64.so.2";
        if (
          binary.length < 64 ||
          !binary.subarray(0, 4).equals(Buffer.from([0x7f, 0x45, 0x4c, 0x46])) ||
          binary[4] !== 2 ||
          binary[5] !== 1 ||
          binary[6] !== 1 ||
          ![2, 3].includes(binary.readUInt16LE(16)) ||
          binary.readUInt16LE(18) !== expectedMachine ||
          binary.readUInt32LE(20) !== 1 ||
          binary.readUInt16LE(52) !== 64
        ) {
          throw new Error("invalid ELF header");
        }
        const programOffset = readCheckedUInt64LE(binary, 32, label);
        const entryPoint = readCheckedUInt64LE(binary, 24, label);
        const programEntrySize = binary.readUInt16LE(54);
        const programCount = binary.readUInt16LE(56);
        if (programOffset < 64 || programEntrySize !== 56 || programCount === 0) {
          throw new Error("invalid ELF table");
        }
        checkedRange(
          programOffset,
          programEntrySize * programCount,
          binary.length,
          label,
          "release-binary-target-mismatch",
        );
        let hasLoadSegment = false;
        let hasExecutableEntryPoint = false;
        let interpreter;
        let interpreterRange;
        const loadFileRanges = [];
        for (let index = 0; index < programCount; index += 1) {
          const entry = programOffset + (index * programEntrySize);
          const type = binary.readUInt32LE(entry);
          const flags = binary.readUInt32LE(entry + 4);
          const fileOffset = readCheckedUInt64LE(binary, entry + 8, label);
          const virtualAddress = readCheckedUInt64LE(binary, entry + 16, label);
          const fileSize = readCheckedUInt64LE(binary, entry + 32, label);
          const memorySize = readCheckedUInt64LE(binary, entry + 40, label);
          checkedRange(
            fileOffset,
            fileSize,
            binary.length,
            label,
            "release-binary-target-mismatch",
          );
          if (type === 1 && fileSize > 0) {
            if (fileSize > memorySize) throw new Error("ELF load size exceeds memory size");
            hasLoadSegment = true;
            loadFileRanges.push({ offset: fileOffset, size: fileSize });
            if (
              entryPoint !== 0 &&
              (flags & 1) !== 0 &&
              fileSize > 0 &&
              entryPoint >= virtualAddress &&
              entryPoint - virtualAddress < fileSize
            ) {
              hasExecutableEntryPoint = true;
            }
          }
          if (type === 3) {
            if (interpreter !== undefined || fileSize < 2) throw new Error("invalid ELF interpreter");
            const bytes = binary.subarray(fileOffset, fileOffset + fileSize);
            if (bytes.at(-1) !== 0 || bytes.subarray(0, -1).includes(0)) {
              throw new Error("invalid ELF interpreter");
            }
            interpreter = bytes.subarray(0, -1).toString("utf8");
            interpreterRange = { offset: fileOffset, size: fileSize };
          }
        }
        const interpreterIsLoadable = interpreterRange !== undefined && loadFileRanges.some(
          (range) =>
            interpreterRange.offset >= range.offset &&
            interpreterRange.offset - range.offset <= range.size &&
            interpreterRange.size <= range.size - (interpreterRange.offset - range.offset),
        );
        if (
          !hasLoadSegment ||
          !hasExecutableEntryPoint ||
          !interpreterIsLoadable ||
          interpreter !== expectedInterpreter
        ) {
          throw new Error("ELF lacks glibc interpreter evidence");
        }
        return;
      }

      if (metadata.os === "darwin") {
        const expectedCpu = metadata.cpu === "arm64" ? 0x0100000c : 0x01000007;
        if (
          binary.length < 32 ||
          binary.readUInt32LE(0) !== 0xfeedfacf ||
          binary.readUInt32LE(4) !== expectedCpu ||
          binary.readUInt32LE(12) !== 2
        ) {
          throw new Error("invalid Mach-O executable header");
        }
        const commandCount = binary.readUInt32LE(16);
        const commandBytes = binary.readUInt32LE(20);
        checkedRange(32, commandBytes, binary.length, label, "release-binary-target-mismatch");
        let cursor = 32;
        const executableVirtualRanges = [];
        let preferredLoadAddress;
        let entryOffset;
        let entryMechanismCount = 0;
        for (let index = 0; index < commandCount; index += 1) {
          checkedRange(cursor, 8, 32 + commandBytes, label, "release-binary-target-mismatch");
          const command = binary.readUInt32LE(cursor);
          const commandSize = binary.readUInt32LE(cursor + 4);
          if (commandSize < 8 || commandSize % 8 !== 0) {
            throw new Error("invalid Mach-O load command");
          }
          checkedRange(
            cursor,
            commandSize,
            32 + commandBytes,
            label,
            "release-binary-target-mismatch",
          );
          if (command === 0x19) {
            if (commandSize < 72) throw new Error("invalid Mach-O segment");
            const sectionCount = binary.readUInt32LE(cursor + 64);
            if (commandSize !== 72 + (sectionCount * 80)) {
              throw new Error("invalid Mach-O segment section table");
            }
            const segmentName = binary.subarray(cursor + 8, cursor + 24)
              .toString("ascii").replace(/\0.*$/, "");
            const virtualAddress = readCheckedUInt64LE(binary, cursor + 24, label);
            const virtualSize = readCheckedUInt64LE(binary, cursor + 32, label);
            const fileOffset = readCheckedUInt64LE(binary, cursor + 40, label);
            const fileSize = readCheckedUInt64LE(binary, cursor + 48, label);
            const maximumProtection = binary.readUInt32LE(cursor + 56);
            const initialProtection = binary.readUInt32LE(cursor + 60);
            if (
              fileSize > virtualSize ||
              (initialProtection & ~maximumProtection) !== 0
            ) {
              throw new Error("invalid Mach-O segment protections");
            }
            checkedRange(
              fileOffset,
              fileSize,
              binary.length,
              label,
              "release-binary-target-mismatch",
            );
            if (segmentName === "__TEXT" && fileOffset === 0 && fileSize > 0) {
              if (preferredLoadAddress !== undefined) {
                throw new Error("duplicate Mach-O preferred load segment");
              }
              preferredLoadAddress = virtualAddress;
            }
            if (virtualSize > 0 && (initialProtection & 4) !== 0) {
              executableVirtualRanges.push({ address: virtualAddress, size: fileSize });
            }
          } else if (command === 0x80000028) {
            entryMechanismCount += 1;
            if (commandSize !== 24 || entryOffset !== undefined) {
              throw new Error("invalid Mach-O entry command");
            }
            entryOffset = readCheckedUInt64LE(binary, cursor + 8, label);
          } else if (command === 0x5) {
            entryMechanismCount += 1;
          }
          cursor += commandSize;
        }
        let entryAddress;
        if (
          preferredLoadAddress !== undefined &&
          entryOffset !== undefined &&
          preferredLoadAddress <= Number.MAX_SAFE_INTEGER - entryOffset
        ) {
          entryAddress = preferredLoadAddress + entryOffset;
        }
        const hasExecutableEntryPoint = entryAddress !== undefined && entryOffset !== 0 &&
          executableVirtualRanges.some(
            (range) =>
              entryAddress >= range.address &&
              entryAddress - range.address < range.size,
          );
        if (
          commandCount === 0 ||
          cursor !== 32 + commandBytes ||
          entryMechanismCount !== 1 ||
          !hasExecutableEntryPoint
        ) {
          throw new Error("Mach-O lacks executable segment evidence");
        }
        return;
      }

      const expectedMachine = metadata.cpu === "arm64" ? 0xaa64 : 0x8664;
      if (binary.length < 64 || binary.subarray(0, 2).toString("ascii") !== "MZ") {
        throw new Error("invalid DOS header");
      }
      const peOffset = binary.readUInt32LE(0x3c);
      checkedRange(peOffset, 24, binary.length, label, "release-binary-target-mismatch");
      if (
        !binary.subarray(peOffset, peOffset + 4).equals(Buffer.from("PE\0\0")) ||
        binary.readUInt16LE(peOffset + 4) !== expectedMachine
      ) {
        throw new Error("invalid PE signature");
      }
      const sectionCount = binary.readUInt16LE(peOffset + 6);
      const optionalSize = binary.readUInt16LE(peOffset + 20);
      const characteristics = binary.readUInt16LE(peOffset + 22);
      const optionalOffset = peOffset + 24;
      if (
        sectionCount === 0 ||
        sectionCount > 96 ||
        optionalSize < 112 ||
        (characteristics & 0x0002) === 0 ||
        (characteristics & 0x2000) !== 0
      ) {
        throw new Error("PE is not an executable image");
      }
      checkedRange(optionalOffset, optionalSize, binary.length, label, "release-binary-target-mismatch");
      if (binary.readUInt16LE(optionalOffset) !== 0x20b) {
        throw new Error("PE is not a PE32+ image");
      }
      const dataDirectoryCount = binary.readUInt32LE(optionalOffset + 108);
      if (optionalSize !== 112 + (dataDirectoryCount * 8)) {
        throw new Error("PE optional header does not contain its data directories");
      }
      const entryPoint = binary.readUInt32LE(optionalOffset + 16);
      const sectionAlignment = binary.readUInt32LE(optionalOffset + 32);
      const fileAlignment = binary.readUInt32LE(optionalOffset + 36);
      const sizeOfImage = binary.readUInt32LE(optionalOffset + 56);
      const sizeOfHeaders = binary.readUInt32LE(optionalOffset + 60);
      const fileAlignmentIsPowerOfTwo =
        fileAlignment >= 0x200 &&
        fileAlignment <= 0x10000 &&
        (fileAlignment & (fileAlignment - 1)) === 0;
      if (
        entryPoint === 0 ||
        !fileAlignmentIsPowerOfTwo ||
        sectionAlignment < fileAlignment ||
        (sectionAlignment < 0x1000 && sectionAlignment !== fileAlignment) ||
        sizeOfImage === 0 ||
        sizeOfImage % sectionAlignment !== 0
      ) {
        throw new Error("invalid PE optional header");
      }
      const sectionOffset = optionalOffset + optionalSize;
      const sectionTableSize = sectionCount * 40;
      checkedRange(
        sectionOffset,
        sectionTableSize,
        binary.length,
        label,
        "release-binary-target-mismatch",
      );
      const sectionTableEnd = sectionOffset + sectionTableSize;
      const alignedSectionTableEnd = sectionTableEnd +
        ((fileAlignment - (sectionTableEnd % fileAlignment)) % fileAlignment);
      if (
        sizeOfHeaders === 0 ||
        sizeOfHeaders % fileAlignment !== 0 ||
        sizeOfHeaders < alignedSectionTableEnd ||
        sizeOfHeaders > binary.length ||
        sizeOfHeaders > sizeOfImage ||
        entryPoint >= sizeOfImage
      ) {
        throw new Error("invalid PE image dimensions");
      }
      let hasExecutableEntryPoint = false;
      let expectedVirtualAddress;
      let previousRawEnd;
      for (let index = 0; index < sectionCount; index += 1) {
        const section = sectionOffset + (index * 40);
        const virtualSize = binary.readUInt32LE(section + 8);
        const virtualAddress = binary.readUInt32LE(section + 12);
        const rawSize = binary.readUInt32LE(section + 16);
        const rawOffset = binary.readUInt32LE(section + 20);
        const sectionFlags = binary.readUInt32LE(section + 36);
        if (rawSize > 0) {
          if (
            rawOffset < sizeOfHeaders ||
            rawOffset % fileAlignment !== 0 ||
            rawSize % fileAlignment !== 0
          ) {
            throw new Error("invalid PE section file range");
          }
          checkedRange(rawOffset, rawSize, binary.length, label, "release-binary-target-mismatch");
          const rawEnd = rawOffset + rawSize;
          const roundedRawEnd = rawEnd +
            ((fileAlignment - (rawEnd % fileAlignment)) % fileAlignment);
          if (previousRawEnd !== undefined && rawOffset < previousRawEnd) {
            throw new Error("PE section file ranges overlap or are out of RVA order");
          }
          previousRawEnd = roundedRawEnd;
        } else if (rawOffset !== 0 && rawOffset % fileAlignment !== 0) {
          throw new Error("invalid PE section file offset");
        }
        const mappedSize = Math.max(virtualSize, rawSize);
        if (
          virtualAddress % sectionAlignment !== 0 ||
          (mappedSize > 0 && (
            virtualAddress >= sizeOfImage ||
            mappedSize > sizeOfImage - virtualAddress
          ))
        ) {
          throw new Error("invalid PE mapped section range");
        }
        if (mappedSize > 0) {
          if (sectionAlignment < 0x1000 && rawOffset !== virtualAddress) {
            throw new Error("low-alignment PE section file offset differs from its RVA");
          }
          if (
            expectedVirtualAddress !== undefined &&
            virtualAddress !== expectedVirtualAddress
          ) {
            throw new Error("PE mapped sections overlap or are not ascending and adjacent");
          }
          const mappedEnd = virtualAddress + mappedSize;
          expectedVirtualAddress = mappedEnd +
            ((sectionAlignment - (mappedEnd % sectionAlignment)) % sectionAlignment);
        }
        if (
          (sectionFlags & 0x20000000) !== 0 &&
          entryPoint >= virtualAddress &&
          entryPoint - virtualAddress < rawSize
        ) {
          hasExecutableEntryPoint = true;
        }
      }
      if (!hasExecutableEntryPoint) throw new Error("PE entry point is not executable");
    } catch (error) {
      if (error instanceof ReleaseError) throw error;
      fail(
        "release-binary-target-mismatch",
        `${label} does not match executable target ${target}: ${error.message}`,
      );
    }
  }

  function stageNative(target, binaryPath, destination) {
    if (!targets.includes(target)) {
      fail("release-target-unsupported", `unknown release target ${target}`);
    }
    const targetMetadata = matrix[target];
    requireFile(binaryPath, "release-binary-missing", `missing native binary ${binaryPath ?? ""}`);
    if (!destination) fail("release-destination-missing", "release destination is required");

    const assemblyRoot = mkdtempSync(path.join(tmpdir(), `satelle-${target}-`));
    try {
      const packageRoot = path.join(assemblyRoot, `satelle-${target}`);
      const packagedBinary = path.join(packageRoot, targetMetadata.binaryPath);
      mkdirSync(path.dirname(packagedBinary), { recursive: true });
      mkdirSync(path.join(assemblyRoot, "scripts"), { recursive: true });

      // Snapshot the caller-owned binary into the private assembly tree first. The
      // exact snapshot validated below is then packed without reopening the mutable
      // build output path, while copyFileSync retains native executable metadata.
      copyFileSync(binaryPath, packagedBinary);
      const binarySize = statSync(packagedBinary).size;
      if (binarySize === 0 || binarySize > maximumNativeBinaryBytes) {
        fail(
          "release-binary-missing",
          `native binary ${binaryPath} must be between 1 and ${maximumNativeBinaryBytes} bytes`,
        );
      }
      validateNativeBinary(target, readFileSync(packagedBinary), binaryPath);
      const version = expectedVersion(process.env.RELEASE_TAG);

      copyFileSync(packageManifestPath(targetMetadata.packageName), path.join(packageRoot, "package.json"));
      copyFileSync(
        path.join(npmRoot, "scripts", "verify-native-package.cjs"),
        path.join(assemblyRoot, "scripts", "verify-native-package.cjs"),
      );

      const packed = npmPack(packageRoot, destination);
      const stableName = npmArtifactName(targetMetadata.packageName);
      const stablePath = path.resolve(destination, stableName);
      validatePackedArtifact(targetMetadata.packageName, packed.archivePath, version);
      renameSync(packed.archivePath, stablePath);
      return {
        package: targetMetadata.packageName,
        version,
        target,
        file: stableName,
        integrity: sha512Integrity(stablePath),
      };
    } finally {
      rmSync(assemblyRoot, { recursive: true, force: true });
    }
  }

  function stageLaunchers(destination) {
    if (!destination) fail("release-destination-missing", "release destination is required");
    const version = expectedVersion(process.env.RELEASE_TAG);
    return topLevelPackages.map((packageName) => {
      const packed = npmPack(
        path.dirname(packageManifestPath(packageName)),
        destination,
        { ignoreScripts: true },
      );
      const stableName = npmArtifactName(packageName);
      const stablePath = path.resolve(destination, stableName);
      validatePackedArtifact(packageName, packed.archivePath, version);
      renameSync(packed.archivePath, stablePath);
      return {
        package: packageName,
        version,
        file: stableName,
        integrity: sha512Integrity(stablePath),
      };
    });
  }

  function validateNativeReleaseArchives(directory, stagingDirectory) {
    if (!directory) fail("release-destination-missing", "release destination is required");
    if (!stagingDirectory) {
      fail(
        "release-destination-missing",
        "a fresh immutable staging destination is required",
      );
    }
    const sourceDirectory = path.resolve(directory);
    const stagingRoot = path.resolve(stagingDirectory);
    if (existsSync(stagingRoot)) {
      fail("release-destination-invalid", `staging destination already exists: ${stagingRoot}`);
    }

    const deadline = performance.now() + nativeArchiveValidationTimeoutMilliseconds;
    const releaseState = validateReleaseState(process.env.RELEASE_TAG);
    const { version } = releaseState;
    const expectedArchives = targets.map((target) => expectedArchiveName(version, target)).sort();
    const archivePrefix = `satelle-v${version}-`;
    const actualArchives = readdirSync(sourceDirectory, { withFileTypes: true })
      .filter((entry) => entry.name.startsWith(archivePrefix))
      .map((entry) => entry.name)
      .sort();
    if (!sameJson(actualArchives, expectedArchives)) {
      fail(
        "release-archive-set-incomplete",
        "version-matched release archives do not exactly match the canonical target matrix",
      );
    }

    mkdirSync(stagingRoot, { mode: 0o700 });
    const githubRoot = path.join(stagingRoot, "github");
    const npmArtifactRoot = path.join(stagingRoot, "npm");
    mkdirSync(githubRoot, { mode: 0o700 });
    mkdirSync(npmArtifactRoot, { mode: 0o700 });
    let complete = false;
    let snapshots = [];
    try {
      for (const target of targets) {
        const archive = expectedArchiveName(version, target);
        const npmArtifact = npmArtifactName(matrix[target].packageName);
        const archiveSnapshot = snapshotArtifact(
          path.join(sourceDirectory, archive),
          path.join(githubRoot, archive),
          archive,
          maximumNativeReleaseArchiveBytes,
          deadline,
        );
        let npmSnapshot;
        try {
          npmSnapshot = snapshotArtifact(
            path.join(sourceDirectory, npmArtifact),
            path.join(npmArtifactRoot, npmArtifact),
            npmArtifact,
            maximumNpmArtifactBytes,
            deadline,
          );
        } catch (error) {
          closeSync(archiveSnapshot.handle);
          archiveSnapshot.handle = undefined;
          throw error;
        }
        snapshots.push({
          target,
          archive,
          npmArtifact,
          archiveSnapshot,
          npmSnapshot,
        });
      }

      afterNativeArchiveSnapshots?.();
      for (const snapshot of snapshots.flatMap(({ archiveSnapshot, npmSnapshot }) => [
        archiveSnapshot,
        npmSnapshot,
      ])) {
        validateSnapshotSource(snapshot);
      }

      remainingDeadline(deadline, "native release archive validation");

      const requests = snapshots.flatMap((snapshot, snapshotIndex) => {
        const metadata = matrix[snapshot.target];
        const executableName = metadata.os === "win32" ? "satelle.exe" : "satelle";
        const expectedManifest = releaseState.manifestBytes.get(metadata.packageName);
        return [
          {
            archiveHandle: snapshot.archiveSnapshot.handle,
            format: metadata.os === "win32" ? "zip" : "tar.gz",
            label: snapshot.archive,
            limits: nativeArchiveLimits,
            postInventoryDelayMilliseconds:
              snapshotIndex === 0 ? nativeArchivePostInventoryDelayMilliseconds : 0,
            repositoryRoot,
            matrixSnapshot: matrix,
            selections: [{
              kind: "native",
              member: executableName,
              target: snapshot.target,
            }],
          },
          {
            archiveHandle: snapshot.npmSnapshot.handle,
            format: "tar.gz",
            label: snapshot.npmArtifact,
            limits: nativeArchiveLimits,
            postInventoryDelayMilliseconds: 0,
            repositoryRoot,
            matrixSnapshot: matrix,
            selections: [
              {
                expectedName: metadata.packageName,
                expectedSha256: sha256Bytes(expectedManifest),
                expectedVersion: version,
                kind: "manifest",
                member: "package/package.json",
              },
              {
                kind: "native",
                member: `package/${metadata.binaryPath}`,
                target: snapshot.target,
              },
            ],
          },
        ];
      });
      const inventories = inspectArchiveSnapshots(requests, deadline);
      if (!Array.isArray(inventories) || inventories.length !== requests.length) {
        fail("release-archive-invalid", "native release inventory is incomplete");
      }

      const archives = snapshots.map((snapshot, index) => {
        const metadata = matrix[snapshot.target];
        const archiveInventory = inventories[index * 2];
        const npmInventory = inventories[(index * 2) + 1];
        validateArchiveInventory(snapshot.target, snapshot.archive, archiveInventory);
        const expectedNpmMembers = [
          "package/package.json",
          `package/${metadata.binaryPath}`,
        ].sort();
        const actualNpmMembers = npmInventory.members
          .filter(({ type }) => type === "file")
          .map(({ name }) => name)
          .sort();
        if (
          npmInventory.members.some(({ type }) => type !== "file") ||
          !sameJson(actualNpmMembers, expectedNpmMembers)
        ) {
          fail(
            "release-artifact-invalid",
            `${snapshot.npmArtifact} contains unexpected package members`,
          );
        }
        const archiveDigest = archiveInventory.selections.find(
          ({ member }) => member === (metadata.os === "win32" ? "satelle.exe" : "satelle"),
        )?.sha256;
        const npmDigest = npmInventory.selections.find(
          ({ member }) => member === `package/${metadata.binaryPath}`,
        )?.sha256;
        if (
          !/^[0-9a-f]{64}$/.test(archiveDigest ?? "") ||
          !/^[0-9a-f]{64}$/.test(npmDigest ?? "")
        ) {
          fail("release-archive-invalid", `${snapshot.archive} has incomplete binary validation`);
        }
        if (archiveDigest !== npmDigest) {
          fail(
            "release-native-digest-mismatch",
            `${snapshot.archive} executable differs from ${snapshot.npmArtifact}`,
          );
        }
        return {
          target: snapshot.target,
          archive: snapshot.archive,
          archivePath: snapshot.archiveSnapshot.snapshotPath,
          archiveSha256: snapshot.archiveSnapshot.digest,
          npmArtifact: snapshot.npmArtifact,
          npmArtifactPath: snapshot.npmSnapshot.snapshotPath,
          npmArtifactSha256: snapshot.npmSnapshot.digest,
          executableSha256: archiveDigest,
        };
      });
      remainingDeadline(deadline, "native release archive validation");
      beforeNativeArchiveFinalSourceValidation?.();
      for (const snapshot of snapshots.flatMap(({ archiveSnapshot, npmSnapshot }) => [
        archiveSnapshot,
        npmSnapshot,
      ])) {
        validateSnapshotSource(snapshot);
        const handleState = fstatSync(snapshot.handle, { bigint: true });
        let pathState;
        try {
          pathState = lstatSync(snapshot.snapshotPath, { bigint: true });
        } catch {
          fail("release-integrity-mismatch", `${snapshot.label} staging path was replaced`);
        }
        if (
          !sameOpenFileState(snapshot.initialState, handleState) ||
          !pathState.isFile() ||
          pathState.isSymbolicLink() ||
          !sameFileIdentity(handleState, pathState)
        ) {
          fail("release-integrity-mismatch", `${snapshot.label} staging bytes changed`);
        }
        closeSync(snapshot.handle);
        snapshot.handle = undefined;
        chmodSync(snapshot.snapshotPath, 0o400);
      }
      chmodSync(githubRoot, 0o500);
      chmodSync(npmArtifactRoot, 0o500);
      chmodSync(stagingRoot, 0o500);
      complete = true;
      return { version, stagingDirectory: stagingRoot, archives };
    } finally {
      for (const snapshot of snapshots.flatMap(({ archiveSnapshot, npmSnapshot }) => [
        archiveSnapshot,
        npmSnapshot,
      ])) {
        if (snapshot.handle !== undefined) closeSync(snapshot.handle);
      }
      if (!complete) {
        for (const directory of [githubRoot, npmArtifactRoot, stagingRoot]) {
          try {
            const state = lstatSync(directory);
            if (state.isDirectory() && !state.isSymbolicLink()) chmodSync(directory, 0o700);
          } catch {
            // Preserve the validation failure; recursive cleanup below remains best effort.
          }
        }
        rmSync(stagingRoot, { recursive: true, force: true });
      }
    }
  }

  function validateNpmArtifacts(directory, options = {}) {
    if (!directory) fail("release-destination-missing", "release destination is required");
    const version = expectedVersion(process.env.RELEASE_TAG);
    const packages = publicationOrder.map((packageName) => {
      const file = npmArtifactName(packageName);
      const artifactPath = path.join(directory, file);
      requireFile(
        artifactPath,
        "release-artifact-set-incomplete",
        `missing release artifact ${file}`,
      );
      const artifactSize = statSync(artifactPath).size;
      if (artifactSize === 0) {
        fail("release-artifact-set-incomplete", `release artifact ${file} is empty`);
      }
      if (artifactSize >= maximumNpmArtifactBytes) {
        fail(
          "release-artifact-invalid",
          `release artifact ${file} must be smaller than ${maximumNpmArtifactBytes} bytes`,
        );
      }
      const integrity = sha512Integrity(artifactPath);
      validatePackedArtifact(packageName, artifactPath, version);
      const target = targets.find((candidate) => matrix[candidate].packageName === packageName);
      return {
        package: packageName,
        version,
        ...(target ? { target } : {}),
        file,
        integrity,
      };
    });
    validatePackedLaunchers(directory, version);
    for (const artifact of packages) {
      if (sha512Integrity(path.join(directory, artifact.file)) !== artifact.integrity) {
        fail(
          "release-integrity-mismatch",
          `release artifact ${artifact.file} changed during validation`,
        );
      }
    }
    const manifest = {
      schemaVersion: "satelle.npm-artifacts.v1",
      version,
      packages,
    };
    const manifestPath = path.join(directory, "npm-artifacts.json");
    const serialized = `${JSON.stringify(manifest, null, 2)}\n`;
    if (options.writeManifest) {
      const temporaryDirectory = mkdtempSync(path.join(directory, ".npm-artifacts-"));
      const temporaryPath = path.join(temporaryDirectory, "npm-artifacts.json");
      try {
        writeFileSync(temporaryPath, serialized, { flag: "wx", mode: 0o600 });
        renameSync(temporaryPath, manifestPath);
      } catch {
        fail(
          "release-integrity-write-failed",
          "npm-artifacts.json could not be atomically replaced",
        );
      } finally {
        rmSync(temporaryDirectory, { recursive: true, force: true });
      }
    }
    if (!existsSync(manifestPath)) {
      fail("release-integrity-missing", "npm-artifacts.json is missing");
    }
    if (readFileSync(manifestPath, "utf8") !== serialized) {
      fail("release-integrity-mismatch", "npm-artifacts.json does not match package bytes");
    }
    return manifest;
  }

  function localTarget() {
    let libc;
    if (process.platform === "linux") {
      const report = process.report?.getReport?.();
      if (report?.header?.glibcVersionRuntime) libc = "glibc";
      else if (report?.sharedObjects?.some((item) => item.toLowerCase().includes("musl"))) {
        libc = "musl";
      }
    }
    return targets.find((target) => {
      const metadata = matrix[target];
      return (
        metadata.os === process.platform &&
        metadata.cpu === process.arch &&
        (metadata.libc === undefined || metadata.libc === libc)
      );
    });
  }

  function installPackedLauncherDependencies(smokeRoot) {
    runNpm(
      [
        "install",
        "--global=false",
        "--force",
        "--ignore-scripts",
        "--offline",
        "--no-audit",
        "--no-fund",
        "--package-lock=false",
        "--silent",
      ],
      smokeRoot,
    );
  }

  function validatePackedLaunchers(directory, version) {
    const smokeRoot = mkdtempSync(path.join(tmpdir(), "satelle-release-smoke-"));
    try {
      const expectedTarget = localTarget();
      const smokePackages = [
        ...(expectedTarget ? [matrix[expectedTarget].packageName] : []),
        ...topLevelPackages,
      ];
      const dependencies = {};
      for (const packageName of smokePackages) {
        const artifactName = npmArtifactName(packageName);
        copyFileSync(path.join(directory, artifactName), path.join(smokeRoot, artifactName));
        dependencies[packageName] = `file:./${artifactName}`;
      }
      writeFileSync(
        path.join(smokeRoot, "package.json"),
        `${JSON.stringify({ private: true, dependencies }, null, 2)}\n`,
      );
      installPackedLauncherDependencies(smokeRoot);
      // Package installation has the independently configured npm command bound.
      // This deadline covers only the four required launcher executions.
      afterLauncherInstall?.();
      const smokeDeadline = Date.now() + launcherSmokeTimeoutMilliseconds;

      const launcherPaths = topLevelPackages.map((packageName) => ({
        packageName,
        launcherPath: path.join(
          smokeRoot,
          "node_modules",
          ...packageName.split("/"),
          "bin",
          "satelle.cjs",
        ),
      }));
      for (const { packageName, launcherPath } of launcherPaths) {
        const child = spawnSync(process.execPath, [launcherPath, "--version"], {
          cwd: smokeRoot,
          encoding: "utf8",
          env: { ...process.env, npm_config_user_agent: "npm/release-validation" },
          killSignal: "SIGKILL",
          timeout: Math.max(1, smokeDeadline - Date.now()),
        });
        const validResult = expectedTarget
          ? child.status === 0 && child.stdout === `satelle ${version}\n` && child.stderr === ""
          : child.status === 1 &&
            child.stdout === "" &&
            child.stderr.startsWith("satelle: unsupported-local-platform:");
        if (!validResult) {
          fail(
            "release-executable-mismatch",
            `${packageName} packed executable does not preserve native launch behavior`,
          );
        }
      }

      // Removing native packages verifies the launchers' deterministic recovery boundary separately.
      for (const packageName of nativePackages) {
        rmSync(path.join(smokeRoot, "node_modules", ...packageName.split("/")), {
          recursive: true,
          force: true,
        });
      }
      for (const { packageName, launcherPath } of launcherPaths) {
        const child = spawnSync(process.execPath, [launcherPath], {
          cwd: smokeRoot,
          encoding: "utf8",
          env: { ...process.env, npm_config_user_agent: "npm/release-validation" },
          killSignal: "SIGKILL",
          timeout: Math.max(1, smokeDeadline - Date.now()),
        });
        const expectedError = expectedTarget
          ? "satelle: native-binary-package-missing:"
          : "satelle: unsupported-local-platform:";
        if (
          child.status !== 1 ||
          child.stdout !== "" ||
          !child.stderr.startsWith(expectedError)
        ) {
          fail(
            "release-executable-mismatch",
            `${packageName} packed executable does not preserve launcher behavior`,
          );
        }
      }
    } catch (error) {
      if (error instanceof ReleaseError) throw error;
      fail("release-executable-mismatch", `packed launcher smoke test failed: ${error.message}`);
    } finally {
      rmSync(smokeRoot, { recursive: true, force: true });
    }
  }

  function validateLaunchers(directory) {
    if (!directory) fail("release-destination-missing", "release destination is required");
    validatePackedLaunchers(directory, expectedVersion(process.env.RELEASE_TAG));
  }

  function validatePackedArtifact(packageName, artifactPath, version) {
    let members;
    let verboseMembers;
    let packed;
    let packedManifest;
    let packedNativeBinary;
    try {
      members = new Set(
        runTar(["-tzf", artifactPath], { encoding: "utf8" })
          .trim()
          .split(/\r?\n/),
      );
      verboseMembers = runTar(["-tvzf", artifactPath], { encoding: "utf8" })
        .trim()
        .split(/\r?\n/)
        .map((line) => {
          const normalized = line.trim();
          return {
            permissions: normalized.slice(0, 10),
            name: normalized.slice(normalized.lastIndexOf(" ") + 1),
          };
        });
      packedManifest = runTar([
        "-xOzf",
        artifactPath,
        "package/package.json",
      ]);
      packed = JSON.parse(packedManifest.toString("utf8"));
    } catch {
      fail("release-artifact-invalid", `${path.basename(artifactPath)} is not a valid npm archive`);
    }
    const sourceManifestPath = packageManifestPath(packageName);
    if (
      packed.name !== packageName ||
      packed.version !== version ||
      !packedManifest.equals(readFileSync(sourceManifestPath))
    ) {
      fail(
        "release-artifact-metadata-mismatch",
        `${path.basename(artifactPath)} does not contain ${packageName}@${version}`,
      );
    }
    const expectedMembers = new Set([
      "package/package.json",
      ...(packed.files ?? []).map((fileName) => `package/${fileName}`),
    ]);
    if (
      members.size !== expectedMembers.size ||
      verboseMembers.length !== expectedMembers.size ||
      [...members].some((member) => !expectedMembers.has(member)) ||
      verboseMembers.some(
        (entry) => !expectedMembers.has(entry.name) || entry.permissions[0] !== "-",
      )
    ) {
      fail(
        "release-artifact-invalid",
        `${path.basename(artifactPath)} contains unexpected package members`,
      );
    }
    const target = targets.find((candidate) => matrix[candidate].packageName === packageName);
    for (const fileName of packed.files ?? []) {
      const archiveName = `package/${fileName}`;
      const archiveEntries = verboseMembers.filter((entry) => entry.name === archiveName);
      if (
        !members.has(archiveName) ||
        archiveEntries.length !== 1 ||
        archiveEntries[0].permissions[0] !== "-"
      ) {
        fail(
          "release-artifact-invalid",
          `${path.basename(artifactPath)} is missing package file ${fileName}`,
        );
      }
      if (
        target &&
        matrix[target].os !== "win32" &&
        ![3, 6, 9].every((index) => archiveEntries[0].permissions[index] === "x")
      ) {
        fail(
          "release-artifact-permission-mismatch",
          `${path.basename(artifactPath)} native binary is not executable`,
        );
      }
      if (target) {
        try {
          packedNativeBinary = runTar(["-xOzf", artifactPath, archiveName], {
            maxBuffer: maximumNativeBinaryBytes,
          });
        } catch {
          fail(
            "release-artifact-invalid",
            `${path.basename(artifactPath)} native binary cannot be read within the size limit`,
          );
        }
        validateNativeBinary(
          target,
          packedNativeBinary,
          `${path.basename(artifactPath)} member ${fileName}`,
        );
      }
      if (topLevelPackages.includes(packageName)) {
        const sourceFile = readFileSync(
          path.join(path.dirname(packageManifestPath(packageName)), fileName),
        );
        let packedFile;
        try {
          packedFile = runTar(["-xOzf", artifactPath, archiveName], {
            maxBuffer: sourceFile.length + 1,
          });
        } catch (error) {
          if (error.code === "ETIMEDOUT") {
            fail(
              "release-artifact-invalid",
              `${path.basename(artifactPath)} package file ${fileName} exceeded the archive deadline`,
            );
          }
          fail(
            "release-executable-mismatch",
            `${path.basename(artifactPath)} package file ${fileName} cannot be extracted`,
          );
        }
        if (!packedFile.equals(sourceFile)) {
          fail(
            "release-executable-mismatch",
            `${path.basename(artifactPath)} package file ${fileName} differs from its source`,
          );
        }
      }
    }
    return packedNativeBinary;
  }

  return {
    check,
    stageLaunchers,
    stageNative,
    validateNativeBinary,
    validateLaunchers,
    validateNativeReleaseArchives,
    validateNpmArtifacts,
  };
}

function runCli() {
  const release = createReleaseContext();
  const [command, ...argumentsList] = process.argv.slice(2);
  let output;
  switch (command) {
    case "check":
      output = release.check(process.env.RELEASE_TAG);
      break;
    case "stage-native":
      output = release.stageNative(argumentsList[0], argumentsList[1], argumentsList[2]);
      break;
    case "stage-launchers":
      output = release.stageLaunchers(argumentsList[0]);
      break;
    case "validate-npm-artifacts":
      output = release.validateNpmArtifacts(argumentsList[0], {
        writeManifest: argumentsList.includes("--write-manifest"),
      });
      break;
    case "validate-native-release-archives":
      output = release.validateNativeReleaseArchives(argumentsList[0], argumentsList[1]);
      break;
    default:
      fail("release-command-invalid", `unknown release command ${command ?? ""}`);
  }
  process.stdout.write(`${JSON.stringify(output)}\n`);
}

if (require.main === module) {
  try {
    if (process.argv[2] === archiveWorkerCommand) runArchiveWorker();
    else runCli();
  } catch (error) {
    const code = error instanceof ReleaseError ? error.code : "release-command-failed";
    process.stderr.write(`${JSON.stringify({ code, message: error.message })}\n`);
    process.exitCode = 1;
  }
}

module.exports = {
  ReleaseError,
  createReleaseContext,
  zipInflateMaximumOutputLength,
};
