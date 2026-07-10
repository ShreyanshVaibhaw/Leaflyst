import { UserButton } from "@clerk/nextjs";
import { currentUser } from "@clerk/nextjs/server";
import { clerkEnabled } from "@/lib/auth";

export default async function Dashboard() {
  const user = clerkEnabled ? await currentUser() : null;

  return (
    <main className="flex flex-1 flex-col gap-6 p-8">
      <header className="flex items-center justify-between">
        <h1 className="text-2xl font-semibold">Dashboard</h1>
        {clerkEnabled ? (
          <UserButton />
        ) : (
          <span className="rounded-full bg-amber-100 px-3 py-1 text-sm text-amber-800 dark:bg-amber-900 dark:text-amber-100">
            auth disabled (no Clerk keys)
          </span>
        )}
      </header>
      <p className="text-neutral-500">
        {user
          ? `Signed in as ${user.primaryEmailAddress?.emailAddress ?? user.id}.`
          : "Local development mode."}{" "}
        Findings, agents, and sessions arrive in later phases.
      </p>
    </main>
  );
}
