import { existsSync, readFileSync } from 'node:fs';

// Resolve from this script, not the caller's working directory.
const canonicalUrl = new URL('../../scripts/install.sh', import.meta.url);
if (!existsSync(canonicalUrl)) {
  // Partial checkouts (e.g. hosting builds rooted at website/) have no
  // canonical copy to compare against; full checkouts still enforce parity.
  console.warn('check-installer: skipping parity check outside a full checkout');
  process.exit(0);
}
const canonical = readFileSync(canonicalUrl);
const published = readFileSync(new URL('../public/install', import.meta.url));

if (!canonical.equals(published)) {
  throw new Error(
    'Installer copies differ. Update scripts/install.sh, then copy it to ' +
    'website/public/install before building the website.',
  );
}
