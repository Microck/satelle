import type { Metadata } from 'next';

// The root layout carries no styling. The landing page and the Fumadocs docs
// tree are separate visual systems, so each imports its own stylesheet in its
// own segment layout: app/(landing)/layout.tsx and app/docs/layout.tsx.
export const metadata: Metadata = {
  title: {
    default: 'Satelle',
    template: '%s | Satelle',
  },
  description:
    'Satelle is a self-hosted control plane for durable native Computer Use. You own the Host, the credentials, and every boundary that matters.',
  metadataBase: new URL('https://satelle.micr.dev'),
};

export default function RootLayout({ children }: Readonly<{ children: React.ReactNode }>) {
  return (
    <html lang="en" suppressHydrationWarning>
      <body>{children}</body>
    </html>
  );
}
