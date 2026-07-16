import Link from 'next/link';

export default function HomePage() {
  return (
    <main className="mx-auto flex min-h-screen max-w-3xl flex-col justify-center gap-6 px-6 py-20">
      <p className="text-sm font-medium text-fd-muted-foreground">Pre-release</p>
      <h1 className="text-5xl font-semibold tracking-tight">Satelle</h1>
      <p className="text-xl text-fd-muted-foreground">
        Durable remote Computer Use on an operator-controlled native Host.
      </p>
      <div>
        <Link
          className="inline-flex rounded-lg bg-fd-primary px-4 py-2 text-fd-primary-foreground"
          href="/docs"
        >
          Read the documentation
        </Link>
      </div>
    </main>
  );
}
