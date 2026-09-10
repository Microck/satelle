const assert = require("node:assert/strict");
const { readFileSync } = require("node:fs");
const path = require("node:path");
const test = require("node:test");

// Rust compares its encoder with these exact fixtures. Check the other side
// of that boundary against the pinned upstream implementation on every run.
test("TOON output fixtures agree with the upstream encoder and decoder", async () => {
  const { encode, decode } = await import("@toon-format/toon");
  const fixtures = JSON.parse(readFileSync(path.join(
    __dirname,
    "../../crates/satelle-cli/tests/fixtures/toon-reference.json",
  ), "utf8"));
  assert.equal(fixtures.reference, "@toon-format/toon@4.1.1");
  for (const fixture of fixtures.cases) {
    assert.equal(encode(fixture.input, { indent: 2, delimiter: "," }), fixture.toon, fixture.name);
    assert.deepEqual(decode(fixture.toon), fixture.input, fixture.name);
  }
});
