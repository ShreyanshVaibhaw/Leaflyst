import Link from "next/link";
import { PageHeader, Panel } from "@/components/ui";
import { runPocketOSDemo } from "./actions";

export const dynamic = "force-dynamic";

export default async function DemoPage({
  searchParams,
}: {
  searchParams: Promise<{ share?: string; error?: string }>;
}) {
  const result = await searchParams;
  const sharePath = result.share?.match(/^\/share\/abx_share_[A-Za-z0-9_-]+$/)?.[0];
  const completed = Boolean(sharePath);
  const steps = [
    ["01", "Scanner warning", "A read-only scan finds an over-scoped AWS access key with AdministratorAccess."],
    ["02", "Sandboxed attempt", "PocketOS attempts DROP DATABASE against production. The sandbox denies it; no destructive command runs."],
    ["03", "Live alert", "The destructive-operation and credential-scope rules evaluate the recorded event."],
    ["04", "Evidence", "Replay, hash verification, blast radius, incident report, and guided revocation are ready."],
  ];
  return <>
    <PageHeader
      eyebrow="Two-minute reenactment"
      title="PocketOS incident demo"
      description="A public, deterministic scenario using isolated tenant state and fake credentials. It exercises the real graph, ingest, rules, and replay paths without executing the captured destructive command."
      action={<form action={runPocketOSDemo}><button className="rounded-lg bg-rose-600 px-4 py-2.5 text-sm font-semibold text-white shadow-sm">{completed ? "Run again" : "Run isolated demo"}</button></form>}
    />
    <div className="grid gap-4 lg:grid-cols-4">
      {steps.map(([number, title, body]) => <Panel className="p-5" key={number}><p className="font-mono text-xs font-bold text-cyan-700">{number}</p><h2 className="mt-3 font-semibold">{title}</h2><p className="mt-2 text-sm leading-6 text-slate-600">{body}</p></Panel>)}
    </div>
    {completed ? <Panel className="mt-6 border-emerald-200 bg-emerald-50 p-6">
      <p className="text-xs font-bold uppercase tracking-[0.18em] text-emerald-700">Reenactment complete</p>
      <h2 className="mt-2 text-xl font-semibold text-emerald-950">The warning became verified incident evidence.</h2>
      <p className="mt-2 text-sm text-emerald-900">This visitor received a separate sandbox tenant and an expiring read-only replay. No workspace or provider credentials were used.</p>
      <div className="mt-5 flex flex-wrap gap-3">
        <Link className="rounded-lg bg-[#081a2c] px-4 py-2 text-sm font-semibold text-white" href={sharePath ?? "/demo"}>Open read-only replay</Link>
        <Link className="rounded-lg border border-emerald-700 px-4 py-2 text-sm font-semibold text-emerald-900" href="/onboarding">Create a workspace</Link>
      </div>
    </Panel> : <Panel className={`mt-6 p-6 ${result.error ? "border-amber-200 bg-amber-50" : ""}`}><p className="text-sm text-slate-600">{result.error ? "The public sandbox is unavailable or has reached its hourly run limit. Try again later." : "Run the reenactment without signing in. Demo records are fake, rate-limited, and isolated from every real workspace."}</p></Panel>}
  </>;
}
