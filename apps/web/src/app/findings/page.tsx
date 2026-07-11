import Link from "next/link";
import { EmptyState, ErrorState, PageHeader, Panel, SeverityBadge } from "@/components/ui";
import { apiGet, humanize, type Finding } from "@/lib/api";

export const dynamic = "force-dynamic";

export default async function FindingsPage({ searchParams }: { searchParams: Promise<{ severity?: string; provider?: string; finding_type?: string }> }) {
  const filters = await searchParams;
  let findings: Finding[];
  try { findings = await apiGet<Finding[]>("/v1/dashboard/findings", Object.fromEntries(Object.entries(filters).filter((entry): entry is [string, string] => Boolean(entry[1])))); }
  catch (error) { return <><PageHeader eyebrow="Credential graph" title="Findings" description="Prioritized evidence from deterministic rules over your credential graph." /><ErrorState message={error instanceof Error ? error.message : "Unknown API error"} /></>; }
  return <>
    <PageHeader eyebrow="Credential graph" title="Findings" description="Prioritized, explainable risks with the evidence and remediation needed to act safely." action={<div className="flex gap-2"><Link href="/api/exports/findings/csv" className="rounded-lg border border-slate-300 bg-white px-3 py-2 text-xs font-semibold">CSV</Link><Link href="/api/exports/findings/json" className="rounded-lg border border-slate-300 bg-white px-3 py-2 text-xs font-semibold">JSON</Link><Link href="/api/exports/findings/md" className="rounded-lg border border-slate-300 bg-white px-3 py-2 text-xs font-semibold">Markdown</Link></div>} />
    <Panel className="mb-5 flex flex-wrap gap-2 p-4">
      {["", "critical", "high", "medium"].map((severity) => <Link key={severity || "all"} href={`/findings${severity ? `?severity=${severity}` : ""}`} className={`rounded-full px-3 py-1.5 text-xs font-medium ${filters.severity === severity || (!filters.severity && !severity) ? "bg-slate-950 text-white" : "bg-slate-100 text-slate-600"}`}>{severity ? humanize(severity) : "All severities"}</Link>)}
      <span className="mx-1 h-7 w-px bg-slate-200" />
      {["aws", "github"].map((provider) => <Link key={provider} href={`/findings?provider=${provider}`} className={`rounded-full px-3 py-1.5 text-xs font-medium ${filters.provider === provider ? "bg-cyan-700 text-white" : "bg-cyan-50 text-cyan-800"}`}>{provider.toUpperCase()}</Link>)}
    </Panel>
    {!findings.length ? <EmptyState title="No matching findings" body="The selected filters have no open findings. Try a broader view or connect another provider." href="/integrations" label="Manage integrations" /> : <Panel className="overflow-hidden"><div className="hidden grid-cols-[110px_110px_1.3fr_1fr_130px] gap-4 border-b border-slate-100 bg-slate-50 px-6 py-3 text-[11px] font-bold uppercase tracking-wider text-slate-500 md:grid"><span>Severity</span><span>Provider</span><span>Finding</span><span>Credential owner</span><span></span></div><div className="divide-y divide-slate-100">{findings.map((finding) => <Link href={`/findings/${finding.id}`} key={finding.id} className="grid gap-3 px-6 py-5 transition hover:bg-slate-50 md:grid-cols-[110px_110px_1.3fr_1fr_130px] md:items-center md:gap-4"><span><SeverityBadge severity={finding.severity} /></span><span className="text-xs font-semibold uppercase text-slate-500">{finding.provider ?? "graph"}</span><span><b className="block text-sm">{humanize(finding.finding_type)}</b><span className="mt-1 block truncate font-mono text-xs text-slate-500">{finding.fingerprint ?? "No credential"}</span></span><span className="truncate text-sm text-slate-600">{finding.owner ?? "Unknown"}</span><span className="text-right text-xs font-semibold text-cyan-700">View evidence →</span></Link>)}</div></Panel>}
  </>;
}
