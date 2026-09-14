import { createMDX } from 'fumadocs-mdx/next';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const withMDX = createMDX();
const projectRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');

export default withMDX({
  output: 'export',
  reactStrictMode: true,
  // The LAN preview needs the browser's origin to load and hydrate Next's
  // development resources. Without this, controls can render but stay static.
  allowedDevOrigins: ['10.0.0.228', '100.124.44.113'],
  turbopack: {
    root: projectRoot,
  },
});
