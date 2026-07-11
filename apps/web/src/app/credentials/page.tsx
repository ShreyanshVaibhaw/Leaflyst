import Link from "next/link";
import { EmptyState, ErrorState, PageHeader, Panel, SeverityBadge } from "@/components/ui";
import { apiGet, formatDate, humanize, type Credential } from "@/lib/api";

export const dynamic = "force-dynamic";

export default async function CredentialsPage() {
  let credentials: Credential[];
  try { credentials = await apiGet<Credential[]>("/v1/dashboard/credentials"); }
  catch (error) { return <><PageHeader eyebrow="Credential graph" title="Credential inventory" description="Fingerprints only—secret values are never collected or stored." /><ErrorState message={error instanceof Error ? error.message : "Unknown API error"} /></>; }
  return <>
    <PageHeader eyebrow="Credential graph" title="Credential inventory" description="Every non-human credential discovered across connected providers, with its owner, activity, and open risks." />
    {!credentials.length ? <EmptyState title="No credentials scanned" body="Connect AWS or GitHub to build your credential inventory. Scans are read-only by construction." href="/integrations" label="Connect a provider" /> : <Panel className="overflow-hidden"><div className="hidden grid-cols-[100px_1.2fr_1fr_150px_100px] gap-4 border-b border-slate-100 bg-slate-50 px-6 py-3 text-[11px] font-bold uppercase tracking-wider text-slate-500 md:grid"><span>Provider</span><span>Credential</span><span>Owner</span><span>Last used</span><span>Risk</span></div><div className="divide-y divide-slate-100">{credentials.map((credential) => <Link href={`/credentials/${credential.id}`} key={credential.id} className="grid gap-3 px-6 py-5 transition hover:bg-slate-50 md:grid-cols-[100px_1.2fr_1fr_150px_100px] md:items-center md:gap-4"><span className="text-xs font-bold uppercase text-cyan-700">{credential.provider}</span><span><b className="block text-sm">{humanize(credential.kind)}</b><span className="mt-1 block truncate font-mono text-xs text-slate-500">{credential.fingerprint}</span></span><span className="truncate text-sm text-slate-600">{credential.owner ?? "Unknown"}</span><span className="text-xs text-slate-600">{formatDate(credential.last_used_at)}</span><span>{credential.open_findings ? <SeverityBadge severity={credential.open_findings > 1 ? "high" : "medium"} /> : <span className="text-xs font-semibold text-emerald-700">Clear</span>}</span></Link>)}</div></Panel>}
  </>;
}
