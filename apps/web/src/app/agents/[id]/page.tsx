import Link from "next/link";
import { ErrorState, PageHeader, Panel } from "@/components/ui";
import { apiGet, formatDate, type Agent, type SessionSummary } from "@/lib/api";

export const dynamic = "force-dynamic";

export default async function AgentPage({ params }: { params: Promise<{ id: string }> }) {
  const { id } = await params;
  let agents: Agent[];
  let sessions: SessionSummary[];
  try {
    [agents, sessions] = await Promise.all([apiGet<Agent[]>("/v1/replay/agents"), apiGet<SessionSummary[]>(`/v1/replay/agents/${encodeURIComponent(id)}/sessions`)]);
  } catch (error) { return <ErrorState message={error instanceof Error ? error.message : "Agent unavailable"} />; }
  const agent = agents.find((item) => item.agent_id === id);
  return <><Link href="/agents" className="mb-5 inline-block text-sm text-slate-500">← Back to agents</Link><PageHeader eyebrow="Recorded agent" title={id} description={`${sessions.length} forensic sessions available`} /><div className="grid gap-6 xl:grid-cols-[1.5fr_1fr]"><Panel className="overflow-hidden"><div className="border-b border-slate-100 p-5 font-semibold">Sessions</div><div className="divide-y divide-slate-100">{sessions.map((session) => <Link key={session.session_id} href={`/sessions/${encodeURIComponent(session.session_id)}`} className="grid gap-3 px-5 py-4 hover:bg-slate-50 sm:grid-cols-[1fr_auto_auto]"><div><b className="block font-mono text-sm">{session.session_id}</b><span className="text-xs text-slate-500">{formatDate(session.started_at)}</span></div><span className="text-sm">{session.event_count} events</span><span className={session.error_count ? "text-sm text-rose-700" : "text-sm text-emerald-700"}>{session.error_count ? `${session.error_count} errors` : "Successful"}</span></Link>)}</div></Panel><Panel className="p-6"><h2 className="font-semibold">Credentials held</h2><div className="mt-4 space-y-2">{agent?.credentials.map((credential) => <Link key={credential.id} href={`/credentials/${credential.id}`} className="block rounded-lg border border-slate-200 p-3 font-mono text-xs">{credential.fingerprint}</Link>)}</div></Panel></div></>;
}
