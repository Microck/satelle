import type { Metadata } from 'next';
import { RootProvider } from 'fumadocs-ui/provider/next';
import 'fumadocs-ui/css/black.css';
import 'fumadocs-ui/css/preset.css';

export const metadata: Metadata = {
  title: {
    default: 'Satelle',
    template: '%s | Satelle',
  },
  description: 'Operate Satelle controllers and native Computer Use Hosts.',
};

export default function RootLayout({ children }: Readonly<{ children: React.ReactNode }>) {
  return (
    <html lang="en" suppressHydrationWarning>
      <body>
        <RootProvider>{children}</RootProvider>
      </body>
    </html>
  );
}
