import { existsSync, readFileSync } from 'node:fs';

// Resolve from this script, not the caller's working directory.
const canonicalUrl = new URL('../../scripts/install.sh', import.meta.url);
if (!existsSync(canonicalUrl)) {
  // Partial checkouts (e.g. hosting builds rooted at website/) have no
  // canonical copy to compare against; full checkouts still enforce parity.
  console.warn('check-installer: skipping parity check outside a full checkout');
  process.exit(0);
}
const pairs = [
  ['../../scripts/install.sh', '../public/install'],
  ['../../scripts/install.ps1', '../public/install.ps1'],
];
for (const [canonicalPath, publishedPath] of pairs) {
  const canonical = readFileSync(new URL(canonicalPath, import.meta.url));
  const published = readFileSync(new URL(publishedPath, import.meta.url));

  if (!canonical.equals(published)) {
    throw new Error(
      'Installer copies differ. Update ' +
        canonicalPath.replace('../../', '') +
        ', then copy it to website/public/' +
        publishedPath.replace('../public/', '') +
        ' before building the website.',
    );
  }
}
