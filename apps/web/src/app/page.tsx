import Link from "next/link";

export default function Home() {
  return (
    <main className="flex flex-1 flex-col items-center justify-center gap-6 p-8">
      <h1 className="text-4xl font-bold tracking-tight">AgentBlackBox</h1>
      <p className="max-w-xl text-center text-lg text-neutral-500">
        The flight recorder for AI agents. A tamper-evident record of
        everything your agents do, and the credentials you forgot they had.
      </p>
      <Link
        href="/dashboard"
        className="rounded-lg bg-neutral-900 px-5 py-2.5 text-white transition-colors hover:bg-neutral-700 dark:bg-white dark:text-black dark:hover:bg-neutral-200"
      >
        Open dashboard
      </Link>
    </main>
  );
}
