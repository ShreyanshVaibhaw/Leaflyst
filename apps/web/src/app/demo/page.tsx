import Link from "next/link";
import { PageHeader, Panel } from "@/components/ui";
import { restoreWorkspace, runPocketOSDemo } from "./actions";

export const dynamic = "force-dynamic";

export default async function DemoPage({
  searchParams,
}: {
  searchParams: Promise<{ session?: string; credential?: string; finding?: string }>;
}) {
  const result = await searchParams;
  const completed = Boolean(result.session && result.credential && result.finding);
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
      description="A deterministic end-to-end scenario using the real graph, ingest, rules, replay, report, and containment paths. It is sandboxed and never executes the captured destructive command."
      action={<form action={runPocketOSDemo}><button className="rounded-lg bg-rose-600 px-4 py-2.5 text-sm font-semibold text-white shadow-sm">{completed ? "Run again" : "Run demo"}</button></form>}
    />
    <div className="grid gap-4 lg:grid-cols-4">
      {steps.map(([number, title, body]) => <Panel className="p-5" key={number}><p className="font-mono text-xs font-bold text-cyan-700">{number}</p><h2 className="mt-3 font-semibold">{title}</h2><p className="mt-2 text-sm leading-6 text-slate-600">{body}</p></Panel>)}
    </div>
    {completed ? <Panel className="mt-6 border-emerald-200 bg-emerald-50 p-6">
      <p className="text-xs font-bold uppercase tracking-[0.18em] text-emerald-700">Reenactment complete</p>
      <h2 className="mt-2 text-xl font-semibold text-emerald-950">The warning became verified incident evidence.</h2>
      <div className="mt-5 flex flex-wrap gap-3">
        <Link className="rounded-lg bg-[#081a2c] px-4 py-2 text-sm font-semibold text-white" href={`/findings/${result.finding}`}>Pre-incident warning</Link>
        <Link className="rounded-lg bg-[#081a2c] px-4 py-2 text-sm font-semibold text-white" href={`/sessions/${result.session}`}>Replay and blast radius</Link>
        <Link className="rounded-lg bg-[#081a2c] px-4 py-2 text-sm font-semibold text-white" href={`/credentials/${result.credential}`}>Guided revocation</Link>
        <a className="rounded-lg border border-emerald-700 px-4 py-2 text-sm font-semibold text-emerald-900" href={`/api/exports/sessions/${result.session}/report/pdf`}>Incident PDF</a>
        <form action={restoreWorkspace}><button className="rounded-lg border border-emerald-700 px-4 py-2 text-sm font-semibold text-emerald-900">Return to workspace</button></form>
      </div>
    </Panel> : <Panel className="mt-6 p-6"><p className="text-sm text-slate-600">Enable <code className="rounded bg-slate-100 px-1.5 py-1">ABX_DEMO_ENABLED=true</code>, then run the reenactment. Demo records are isolated to the selected tenant.</p></Panel>}
  </>;
}
