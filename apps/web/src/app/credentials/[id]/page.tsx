import Link from "next/link";
import { ErrorState, PageHeader, Panel, SeverityBadge } from "@/components/ui";
import { apiGet, formatDate, humanize, type Credential } from "@/lib/api";

export const dynamic = "force-dynamic";

export default async function CredentialPage({ params }: { params: Promise<{ id: string }> }) {
  const { id } = await params;
  let credential: Credential;
  try { credential = await apiGet<Credential>(`/v1/dashboard/credentials/${id}`); }
  catch (error) { return <ErrorState message={error instanceof Error ? error.message : "Credential unavailable"} />; }
  return <>
    <Link href="/credentials" className="mb-5 inline-block text-sm font-medium text-slate-500">← Back to credentials</Link>
    <PageHeader eyebrow={`${credential.provider} credential`} title={humanize(credential.kind)} description={credential.fingerprint} action={<span className="rounded-full bg-emerald-100 px-3 py-1.5 text-xs font-bold uppercase text-emerald-800">{credential.status}</span>} />
    <div className="grid gap-6 xl:grid-cols-[1.4fr_1fr]">
      <Panel><div className="border-b border-slate-100 p-6"><h2 className="font-semibold">Permissions and reach</h2><p className="mt-1 text-xs text-slate-500">Resources reachable through the credential owner&apos;s grants</p></div><div className="divide-y divide-slate-100">{credential.permissions?.length ? credential.permissions.map((permission, index) => <div className="grid gap-3 p-5 sm:grid-cols-[1fr_1.4fr_80px]" key={`${permission.scope}-${permission.resource}-${index}`}><span className="font-mono text-xs">{permission.scope}</span><span className="break-all font-mono text-xs text-slate-600">{permission.resource ?? "No resource mapped"}</span><span className="text-xs font-semibold uppercase text-cyan-700">{permission.access ?? "—"}</span></div>) : <p className="p-6 text-sm text-slate-500">No permission edges were discovered.</p>}</div></Panel>
      <div className="space-y-6"><Panel className="p-6"><h2 className="font-semibold">Observed metadata</h2><dl className="mt-5 space-y-4 text-sm"><div><dt className="text-xs text-slate-500">Owner</dt><dd className="mt-1 break-all">{credential.owner ?? "Unknown"}</dd></div><div><dt className="text-xs text-slate-500">Created</dt><dd className="mt-1">{formatDate(credential.created_at)}</dd></div><div><dt className="text-xs text-slate-500">Last used</dt><dd className="mt-1">{formatDate(credential.last_used_at)}</dd></div></dl></Panel><Panel className="p-6"><h2 className="font-semibold">Open findings</h2><div className="mt-4 space-y-3">{credential.findings?.length ? credential.findings.map((finding) => <Link href={`/findings/${finding.id}`} className="flex items-center justify-between rounded-lg border border-slate-200 p-3" key={finding.id}><span className="text-sm font-medium">{humanize(finding.finding_type)}</span><SeverityBadge severity={finding.severity} /></Link>) : <p className="text-sm text-emerald-700">No open risk findings.</p>}</div></Panel></div>
    </div>
  </>;
}
