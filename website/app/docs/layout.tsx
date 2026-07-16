import { DocsLayout } from 'fumadocs-ui/layouts/docs';
import { source } from '@/lib/source';

export default function Layout({ children }: Readonly<{ children: React.ReactNode }>) {
  return (
    <DocsLayout
      tree={source.pageTree}
      nav={{ title: 'Satelle' }}
      githubUrl="https://github.com/Microck/satelle"
    >
      {children}
    </DocsLayout>
  );
}
