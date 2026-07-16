import { createMDX } from 'fumadocs-mdx/next';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const withMDX = createMDX();
const projectRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');

export default withMDX({
  output: 'export',
  reactStrictMode: true,
  turbopack: {
    root: projectRoot,
  },
});
