"use strict";

const assert = require("node:assert/strict");
const { execFileSync } = require("node:child_process");
const { readFileSync } = require("node:fs");
const { createReleaseContext } = require("./release.cjs");

const repository = "https://github.com/Microck/satelle";
const workflowPath = ".github/workflows/release.yml";
const predicateType = "https://slsa.dev/provenance/v1";
const userAgent = "OpenAI File Downloader, XaiImageApiFetch/1.0";

function assertProvenanceIdentity(statement, entry, version, sourceDigest) {
  const ref = `refs/tags/v${version}`;
  const packageUrl = `pkg:npm/${entry.package.replace("@", "%40")}@${version}`;
  const digest = Buffer.from(entry.integrity.slice("sha512-".length), "base64").toString("hex");
  assert.equal(statement._type, "https://in-toto.io/Statement/v1");
  assert.equal(statement.predicateType, predicateType);
  assert.deepEqual(statement.subject, [{ name: packageUrl, digest: { sha512: digest } }]);
  const definition = statement.predicate.buildDefinition;
  assert.deepEqual(definition.externalParameters.workflow, {
    ref,
    repository,
    path: workflowPath,
  });
  assert.deepEqual(definition.resolvedDependencies, [{
    uri: `git+${repository}@${ref}`,
    digest: { gitCommit: sourceDigest },
  }]);
}

async function verifyRegistryProvenance(manifestPath, version, sourceDigest) {
  assert.match(sourceDigest, /^[a-f0-9]{40}$/);
  const manifest = JSON.parse(readFileSync(manifestPath, "utf8"));
  const plan = createReleaseContext().check(`v${version}`);
  assert.equal(manifest.version, version);
  assert.deepEqual(manifest.packages.map(entry => entry.package), plan.publicationOrder);
  const sigstore = require("sigstore");
  for (const entry of manifest.packages) {
    assert.match(entry.integrity, /^sha512-[A-Za-z0-9+/]{86}==$/);
    const spec = `${entry.package}@${version}`;
    const dist = JSON.parse(execFileSync("npm", [
      "view", spec, "dist", "--json", `--user-agent=${userAgent}`,
    ], { encoding: "utf8", timeout: 120_000 }));
    assert.equal(dist.integrity, entry.integrity, `${spec} registry integrity differs`);
    // Fetch only the registry endpoint, never an arbitrary URL from metadata.
    const response = await fetch(
      `https://registry.npmjs.org/-/npm/v1/attestations/${encodeURIComponent(spec)}`,
      { headers: { "User-Agent": userAgent }, redirect: "error", signal: AbortSignal.timeout(30_000) },
    );
    assert.equal(response.ok, true, `${spec} attestations returned HTTP ${response.status}`);
    const attestations = (await response.json()).attestations;
    const provenance = attestations.filter(entry => entry.predicateType === predicateType);
    assert.equal(provenance.length, 1, `${spec} must have exactly one provenance statement`);
    const bundle = provenance[0].bundle;
    await sigstore.verify(bundle, {
      certificateIssuer: "https://token.actions.githubusercontent.com",
      certificateIdentityURI: `${repository}/${workflowPath}@refs/tags/v${version}`,
    });
    const statement = JSON.parse(Buffer.from(bundle.dsseEnvelope.payload, "base64"));
    assertProvenanceIdentity(statement, entry, version, sourceDigest);
    console.log(`Verified signed-tag npm provenance: ${spec}`);
  }
}

if (require.main === module) {
  verifyRegistryProvenance(...process.argv.slice(2)).catch(error => {
    console.error(JSON.stringify({ code: "npm-provenance-invalid", message: error.message }));
    process.exitCode = 1;
  });
}

module.exports = { assertProvenanceIdentity, verifyRegistryProvenance };
