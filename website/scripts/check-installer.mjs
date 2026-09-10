import { readFileSync } from 'node:fs';

// Resolve from this script, not the caller's working directory.
const canonical = readFileSync(new URL('../../scripts/install.sh', import.meta.url));
const published = readFileSync(new URL('../public/install', import.meta.url));

if (!canonical.equals(published)) {
  throw new Error(
    'Installer copies differ. Update scripts/install.sh, then copy it to ' +
    'website/public/install before building the website.',
  );
}
