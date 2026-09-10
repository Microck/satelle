import { DocsLayout } from 'fumadocs-ui/layouts/docs';
import { RootProvider } from 'fumadocs-ui/provider/next';
import { source } from '@/lib/source';
import 'fumadocs-ui/css/black.css';
import 'fumadocs-ui/css/preset.css';

// The Fumadocs preset and provider live here rather than in the root layout so
// the landing page at / is not styled by the docs theme.
export default function Layout({ children }: Readonly<{ children: React.ReactNode }>) {
  return (
    <RootProvider>
      <DocsLayout
        tree={source.pageTree}
        nav={{ title: 'Satelle' }}
        githubUrl="https://github.com/Microck/satelle"
      >
        {children}
      </DocsLayout>
    </RootProvider>
  );
}
