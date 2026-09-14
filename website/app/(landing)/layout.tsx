import type { Metadata } from 'next';
import { THEME_BOOTSTRAP } from './theme-toggle';
import './landing.css';

export const metadata: Metadata = {
  title: 'Satelle: durable native Computer Use on a Host you control',
};

// `.sa` scopes every landing token, so nothing here reaches /docs.
export default function LandingLayout({ children }: Readonly<{ children: React.ReactNode }>) {
  return (
    <>
      {/* Applies a stored theme choice before first paint. */}
      <script dangerouslySetInnerHTML={{ __html: THEME_BOOTSTRAP }} />
      <div className="sa">{children}</div>
    </>
  );
}
