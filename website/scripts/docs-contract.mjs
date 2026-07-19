import { execFileSync } from 'node:child_process';
import { existsSync, readFileSync, readdirSync, statSync, writeFileSync } from 'node:fs';
import { dirname, extname, join, relative, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import process from 'node:process';

const repositoryRoot = resolve(dirname(fileURLToPath(import.meta.url)), '../..');
const docsRoot = join(repositoryRoot, 'docs');
const generatedReference = join(docsRoot, 'reference/generated-cli.mdx');
const mode = process.argv[2];
const binary = process.env.SATELLE_DOCS_BINARY
  ? resolve(process.env.SATELLE_DOCS_BINARY)
  : undefined;
const publicSchemaSources = [
  'crates/satelle-core/src/lib.rs',
  'crates/satelle-core/src/events.rs',
  'crates/satelle-cli/src/output.rs',
  'crates/satelle-cli/src/error-output.rs',
  'crates/satelle-host/src/log-page.rs',
];

if (!['generate', 'check', 'schema-check'].includes(mode)) {
  fail('usage: node website/scripts/docs-contract.mjs <generate|check|schema-check>');
}

if (mode === 'schema-check') {
  const schemaVersions = readPublicSchemaVersions();
  validateGeneratedSchemaVersions(schemaVersions);
  console.log(`Validated ${schemaVersions.length} public schema versions against their production sources`);
  process.exit(0);
}

if (!binary) {
  fail('SATELLE_DOCS_BINARY must identify the matching release binary for generate or check mode');
}
if (!existsSync(binary)) fail(`Satelle binary does not exist: ${binary}`);

const releaseVersion = readPackageVersion(join(repositoryRoot, 'package.json'));
const websiteVersion = readPackageVersion(join(repositoryRoot, 'website/package.json'));
const binaryVersion = runBinary(['--version']).trim().replace(/^satelle\s+/, '');

if (binaryVersion !== releaseVersion || websiteVersion !== releaseVersion) {
  fail(`version mismatch: binary=${binaryVersion}, repository=${releaseVersion}, website=${websiteVersion}`);
}

const generated = generateReference(binaryVersion);
if (mode === 'generate') {
  writeFileSync(generatedReference, generated);
  console.log(`Generated ${relative(repositoryRoot, generatedReference)} for Satelle ${binaryVersion}`);
  process.exit(0);
}

if (!existsSync(generatedReference) || readFileSync(generatedReference, 'utf8') !== generated) {
  fail('generated CLI reference is stale; run the docs contract in generate mode with the matching binary');
}

const documentationFiles = walk(docsRoot).filter((path) => ['.md', '.mdx'].includes(extname(path)));
validateLinksAndAssets(documentationFiles);
const exampleCount = validateShellExamples(documentationFiles);
validateVisibleVersion(binaryVersion);
console.log(
  `Validated ${documentationFiles.length} documentation files and ${exampleCount} Satelle command examples for Satelle ${binaryVersion}`,
);

function generateReference(version) {
  const commandSections = [];
  const pending = [[]];
  const visited = new Set();

  while (pending.length > 0) {
    const commandPath = pending.shift();
    const key = commandPath.join(' ');
    if (visited.has(key)) continue;
    visited.add(key);

    const help = runBinary([...commandPath, '--help']).trimEnd();
    const label = ['satelle', ...commandPath].join(' ');
    commandSections.push(`## \`${label}\`\n\n\`\`\`text\n${help}\n\`\`\``);
    for (const subcommand of parseSubcommands(help)) {
      if (subcommand !== 'help') pending.push([...commandPath, subcommand]);
    }
  }

  const schemaVersions = readPublicSchemaVersions();

  return `---
title: Generated CLI and schema reference
description: Binary-derived command help and public schema versions for Satelle ${version}.
---

This page describes **Satelle ${version}**. The documentation contract regenerates
the command sections from \`satelle --help\` and derives schema identifiers from
public Satelle result and event schema sources. CI rejects hand-edited or stale output.

## Public schema versions

| Public schema source | Production source | Serialized schema version |
| --- | --- | --- |
${schemaVersions.map(({ source, symbol, version: schema }) => `| \`${symbol}\` | \`${source}\` | \`${schema}\` |`).join('\n')}

${commandSections.join('\n\n')}
`;
}

function parseSubcommands(help) {
  const commands = help.match(/(?:^|\n)Commands:\n([\s\S]*?)(?:\n\n|$)/)?.[1] ?? '';
  return [...commands.matchAll(/^  ([a-z][a-z0-9-]*)[ \t]+/gm)].map((match) => match[1]);
}

function readPublicSchemaVersions() {
  const versions = publicSchemaSources.flatMap(readSchemaVersionsFromSource);
  const tokenOwners = new Map();

  for (const version of versions) {
    if (!/^satelle(?:\.[a-z0-9-]+)+\.v[1-9]\d*$/.test(version.version)) {
      fail(`${version.source} defines an invalid public schema token: ${version.version}`);
    }
    const existingOwner = tokenOwners.get(version.version);
    if (existingOwner) {
      fail(`public schema token ${version.version} is defined by both ${existingOwner} and ${version.source}:${version.symbol}`);
    }
    tokenOwners.set(version.version, `${version.source}:${version.symbol}`);
  }

  return versions.sort((left, right) => left.version.localeCompare(right.version));
}

function readSchemaVersionsFromSource(source) {
  const contents = readFileSync(join(repositoryRoot, source), 'utf8');
  const versions = [];
  const enumPattern = /(?:pub(?:\(crate\))?\s+)?enum\s+(\w*SchemaVersion)\s*\{([\s\S]*?)\n\}/g;
  for (const match of contents.matchAll(enumPattern)) {
    for (const rename of match[2].matchAll(/#\[serde\(rename = "([^"]+)"\)\]/g)) {
      versions.push({ source, symbol: match[1], version: rename[1] });
    }
  }

  const constantPattern = /(?:pub(?:\(crate\))?\s+)?const\s+([A-Z][A-Z0-9_]*_SCHEMA_VERSION)\s*:\s*&str\s*=\s*"([^"]+)";/g;
  for (const match of contents.matchAll(constantPattern)) {
    versions.push({ source, symbol: match[1], version: match[2] });
  }

  const customSchemaPattern = /struct\s+(\w+Schema)\s*;[\s\S]*?impl\s+Serialize\s+for\s+\1\s*\{([\s\S]*?)\n\}/g;
  for (const match of contents.matchAll(customSchemaPattern)) {
    const token = match[2].match(/serializer\.serialize_str\("([^"]+)"\)/)?.[1];
    if (token) versions.push({ source, symbol: match[1], version: token });
  }

  if (versions.length === 0) {
    fail(`${source} no longer exposes a recognized public schema definition`);
  }

  return versions;
}

function validateGeneratedSchemaVersions(expected) {
  if (!existsSync(generatedReference)) fail('generated CLI reference does not exist');
  const generated = readFileSync(generatedReference, 'utf8');
  const table = generated.match(/## Public schema versions\n\n([\s\S]*?)\n\n## /)?.[1];
  if (!table) fail('generated CLI reference has no public schema version table');

  const actual = [...table.matchAll(/^\| `([^`]+)` \| `([^`]+)` \| `([^`]+)` \|$/gm)].map((match) => ({
    source: match[2],
    symbol: match[1],
    version: match[3],
  }));

  if (JSON.stringify(actual) !== JSON.stringify(expected)) {
    fail('generated public schema version table is stale; regenerate it from the canonical production sources');
  }
}

function validateLinksAndAssets(files) {
  const linkPattern = /!?\[[^\]]*\]\(([^)\s]+)(?:\s+['"][^'"]*['"])?\)/g;
  const mdxAttributePattern = /\b(?:href|src)=["']([^"']+)["']/g;
  for (const file of files) {
    const source = readFileSync(file, 'utf8');
    const destinations = [
      ...[...source.matchAll(linkPattern)].map((match) => match[1]),
      ...[...source.matchAll(mdxAttributePattern)].map((match) => match[1]),
    ];
    for (const rawDestination of destinations) {
      const destination = rawDestination.replace(/^<|>$/g, '');
      if (/^(?:https?:|mailto:|tel:)/.test(destination)) continue;
      const [pathname, fragment] = destination.split('#', 2);
      const target = resolveDocumentationTarget(file, pathname);
      if (!target) fail(`${relative(repositoryRoot, file)} has a broken local link: ${destination}`);
      if (fragment && !headingIds(readFileSync(target, 'utf8')).has(decodeURIComponent(fragment))) {
        fail(`${relative(repositoryRoot, file)} links to missing heading #${fragment} in ${relative(repositoryRoot, target)}`);
      }
    }
  }
}

function resolveDocumentationTarget(sourceFile, pathname) {
  if (!pathname) return sourceFile;
  if (pathname.startsWith('/docs')) {
    const slug = pathname.replace(/^\/docs\/?/, '');
    return firstExisting([
      join(docsRoot, `${slug}.mdx`),
      join(docsRoot, `${slug}.md`),
      join(docsRoot, slug, 'index.mdx'),
      join(docsRoot, slug, 'index.md'),
    ]);
  }
  if (pathname.startsWith('/')) return firstExisting([join(repositoryRoot, 'website/public', pathname)]);
  const resolved = resolve(dirname(sourceFile), pathname);
  return firstExisting([resolved, `${resolved}.mdx`, `${resolved}.md`, join(resolved, 'index.mdx'), join(resolved, 'index.md')]);
}

function headingIds(source) {
  const ids = new Set();
  for (const match of source.matchAll(/^#{1,6}\s+(.+)$/gm)) {
    const explicit = match[1].match(/\s+\{#([^}]+)\}\s*$/)?.[1];
    const generated = match[1]
      .replace(/\s+\{#[^}]+\}\s*$/, '')
      .replace(/[`*_~]/g, '')
      .toLowerCase()
      .replace(/[^a-z0-9\s-]/g, '')
      .trim()
      .replace(/\s+/g, '-');
    ids.add(explicit ?? generated);
  }
  return ids;
}

function validateShellExamples(files) {
  let count = 0;
  for (const file of files) {
    const source = readFileSync(file, 'utf8');
    for (const block of source.matchAll(/```(?:sh|bash|shell)\n([\s\S]*?)```/g)) {
      const logicalLines = block[1].replace(/\\\n/g, ' ').split('\n');
      for (const line of logicalLines) {
        const trimmed = line.trim();
        if (!trimmed || trimmed.startsWith('#')) continue;
        const words = shellWords(trimmed);
        const executable = words[0];
        if (executable !== 'satelle' && !/(?:^|\/)satelle(?:\.exe)?$/.test(executable)) continue;
        const args = words.slice(1).map(normalizePlaceholder);
        try {
          runBinary([...args, '--help']);
        } catch (error) {
          fail(`${relative(repositoryRoot, file)} has an invalid Satelle example:\n  ${trimmed}\n${error.stderr?.toString() ?? error.message}`);
        }
        count += 1;
      }
    }
  }
  if (count === 0) fail('no Satelle shell examples were found');
  return count;
}

function shellWords(line) {
  const words = [];
  let current = '';
  let quote = null;
  let escaped = false;
  for (const character of line) {
    if (escaped) {
      current += character;
      escaped = false;
    } else if (character === '\\' && quote !== "'") {
      escaped = true;
    } else if (quote) {
      if (character === quote) quote = null;
      else current += character;
    } else if (character === "'" || character === '"') {
      quote = character;
    } else if (/\s/.test(character)) {
      if (current) words.push(current);
      current = '';
    } else {
      current += character;
    }
  }
  if (quote || escaped) fail(`invalid shell syntax in documentation: ${line}`);
  if (current) words.push(current);
  return words;
}

function normalizePlaceholder(word) {
  if (/^<[^>]+>$/.test(word)) return `docs-${word.slice(1, -1).replace(/[^a-z0-9-]/gi, '-')}`;
  return word;
}

function validateVisibleVersion(version) {
  const index = readFileSync(join(docsRoot, 'index.mdx'), 'utf8');
  if (!index.includes(`Satelle ${version}`)) fail(`docs/index.mdx does not identify Satelle ${version}`);
}

function runBinary(args) {
  return execFileSync(binary, args, { encoding: 'utf8', env: { ...process.env, NO_COLOR: '1' } });
}

function readPackageVersion(path) {
  return JSON.parse(readFileSync(path, 'utf8')).version;
}

function walk(directory) {
  return readdirSync(directory).flatMap((name) => {
    const path = join(directory, name);
    return statSync(path).isDirectory() ? walk(path) : [path];
  });
}

function firstExisting(paths) {
  return paths.find((path) => existsSync(path) && statSync(path).isFile());
}

function fail(message) {
  console.error(`docs contract failed: ${message}`);
  process.exit(1);
}
