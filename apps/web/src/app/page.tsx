import Link from "next/link";
import { ErrorState, PageHeader, Panel, SeverityBadge } from "@/components/ui";
import { apiGet, formatDate, type Integration, type Overview } from "@/lib/api";

export const dynamic = "force-dynamic";

export default async function Home() {
  let overview: Overview;
  let integrations: Integration[];
  try {
    [overview, integrations] = await Promise.all([
      apiGet<Overview>("/v1/dashboard/overview"),
      apiGet<Integration[]>("/v1/dashboard/integrations"),
    ]);
  } catch (error) {
    return <><PageHeader eyebrow="Security posture" title="Credential command center" description="Connect a provider to reveal forgotten credentials and their reachable resources." /><ErrorState message={error instanceof Error ? error.message : "Unknown API error"} /></>;
  }
  const severities = ["critical", "high", "medium", "low"];
  return <>
    <PageHeader eyebrow="Security posture" title="Credential command center" description="A read-only view of what your agents can reach, which credentials are exposed, and where attention is needed first." action={<Link href="/integrations" className="rounded-lg bg-[#081a2c] px-4 py-2.5 text-sm font-semibold text-white shadow-sm">Connect provider</Link>} />
    <Panel className="relative overflow-hidden !bg-[#081a2c] p-7 text-white sm:p-9">
      <div className="absolute -right-20 -top-20 h-64 w-64 rounded-full border-[34px] border-cyan-300/10" />
      <p className="text-xs font-bold uppercase tracking-[0.2em] text-cyan-300">Highest-priority signal</p>
      <p className="relative mt-4 max-w-3xl text-2xl font-semibold leading-tight sm:text-3xl">{overview.scary_number}</p>
      <div className="relative mt-7 flex flex-wrap gap-5 text-sm text-slate-300"><span><b className="text-white">{overview.credentials}</b> {countLabel(overview.credentials, "credential")} mapped</span><span><b className="text-white">{overview.agents}</b> probable {countLabel(overview.agents, "agent")}</span><span><b className="text-white">{overview.providers_scanned.length}</b> {countLabel(overview.providers_scanned.length, "provider")} scanned</span></div>
    </Panel>
    <div className="mt-6 grid gap-4 sm:grid-cols-2 xl:grid-cols-4">
      {severities.map((severity) => <Panel className="p-5" key={severity}><div className="flex items-center justify-between"><SeverityBadge severity={severity} /><span className="text-3xl font-semibold tabular-nums">{overview.findings_by_severity[severity] ?? 0}</span></div><p className="mt-5 text-xs text-slate-500">Open {severity} findings</p></Panel>)}
    </div>
    <div className="mt-6 grid gap-6 xl:grid-cols-[1.4fr_1fr]">
      <Panel><div className="flex items-center justify-between border-b border-slate-100 p-6"><div><h2 className="font-semibold">Risk distribution</h2><p className="mt-1 text-xs text-slate-500">Open findings, excluding informational blast-radius maps</p></div><Link href="/findings" className="text-sm font-semibold text-cyan-700">Review all →</Link></div><div className="space-y-5 p-6">{severities.map((severity) => { const count = overview.findings_by_severity[severity] ?? 0; const width = overview.open_findings ? Math.max(3, count / overview.open_findings * 100) : 0; return <div key={severity}><div className="mb-2 flex justify-between text-xs"><span className="capitalize text-slate-600">{severity}</span><span className="font-medium">{count}</span></div><div className="h-2 overflow-hidden rounded-full bg-slate-100"><div className="h-full rounded-full bg-[#0d879b]" style={{ width: `${width}%` }} /></div></div>; })}</div></Panel>
      <Panel><div className="border-b border-slate-100 p-6"><h2 className="font-semibold">Provider status</h2><p className="mt-1 text-xs text-slate-500">Read-only scanner connections</p></div><div className="divide-y divide-slate-100">{integrations.map((integration) => <div className="flex items-center justify-between p-5" key={integration.provider}><div><p className="font-medium capitalize">{integration.provider}</p><p className="mt-1 text-xs text-slate-500">{integration.account ?? (integration.connected ? "Connected" : "Not connected")}</p></div><div className="text-right"><span className={`inline-flex h-2.5 w-2.5 rounded-full ${integration.connected ? "bg-emerald-500" : "bg-slate-300"}`} /><p className="mt-1 text-[11px] text-slate-500">{formatDate(integration.last_scan)}</p></div></div>)}</div></Panel>
    </div>
  </>;
}

function countLabel(count: number, singular: string) {
  return count === 1 ? singular : `${singular}s`;
}
