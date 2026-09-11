import { existsSync, readFileSync } from 'node:fs';

// Resolve from this script, not the caller's working directory.
const pairs = [
  ['../../scripts/install.sh', '../public/install'],
  ['../../scripts/install.ps1', '../public/install.ps1'],
];
let checked = 0;
for (const [canonicalPath, publishedPath] of pairs) {
  const canonicalUrl = new URL(canonicalPath, import.meta.url);
  // Partial checkouts and minimal fixtures may not carry every installer;
  // only enforce parity for pairs whose canonical copy exists.
  if (!existsSync(canonicalUrl)) continue;
  checked += 1;
  const canonical = readFileSync(canonicalUrl);
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
if (checked === 0) {
  // Partial checkouts (e.g. hosting builds rooted at website/) have no
  // canonical copy to compare against; full checkouts still enforce parity.
  console.warn('check-installer: skipping parity check outside a full checkout');
}
