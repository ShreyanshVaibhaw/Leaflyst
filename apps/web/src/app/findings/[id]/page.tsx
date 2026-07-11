import Link from "next/link";
import { ErrorState, PageHeader, Panel, SeverityBadge } from "@/components/ui";
import { apiGet, humanize, type Finding } from "@/lib/api";

export const dynamic = "force-dynamic";

export default async function FindingPage({ params }: { params: Promise<{ id: string }> }) {
  const { id } = await params;
  let finding: Finding;
  try { finding = await apiGet<Finding>(`/v1/dashboard/findings/${id}`); }
  catch (error) { return <ErrorState message={error instanceof Error ? error.message : "Finding unavailable"} />; }
  return <>
    <Link href="/findings" className="mb-5 inline-block text-sm font-medium text-slate-500">← Back to findings</Link>
    <PageHeader eyebrow={`${finding.provider ?? "Graph"} finding`} title={humanize(finding.finding_type)} description="Review the evidence before applying the recommended remediation." action={<SeverityBadge severity={finding.severity} />} />
    <div className="grid gap-6 xl:grid-cols-[1.4fr_1fr]">
      <Panel className="p-6"><h2 className="font-semibold">Evidence</h2><dl className="mt-5 divide-y divide-slate-100">{Object.entries(finding.evidence ?? {}).map(([key, value]) => <div className="grid gap-2 py-4 sm:grid-cols-[180px_1fr]" key={key}><dt className="text-xs font-semibold uppercase tracking-wide text-slate-500">{humanize(key)}</dt><dd className="break-words font-mono text-sm text-slate-800">{typeof value === "object" ? JSON.stringify(value) : String(value)}</dd></div>)}</dl></Panel>
      <Panel className="h-fit overflow-hidden"><div className="bg-[#081a2c] p-6 text-white"><p className="text-xs font-bold uppercase tracking-widest text-cyan-300">Recommended action</p><p className="mt-4 text-sm leading-6 text-slate-200">{finding.remediation}</p></div><div className="p-6"><p className="text-xs text-slate-500">Credential fingerprint</p><p className="mt-2 break-all font-mono text-sm">{finding.fingerprint ?? "Not linked"}</p><p className="mt-5 text-xs text-slate-500">Owner</p><p className="mt-2 text-sm">{finding.owner ?? "Unknown"}</p></div></Panel>
    </div>
  </>;
}
