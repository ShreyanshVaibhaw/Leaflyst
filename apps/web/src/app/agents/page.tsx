import Link from "next/link";
import { EmptyState, ErrorState, PageHeader, Panel } from "@/components/ui";
import { apiGet, formatDate, type Agent } from "@/lib/api";

export const dynamic = "force-dynamic";

export default async function AgentsPage() {
  let agents: Agent[];
  try { agents = await apiGet<Agent[]>("/v1/replay/agents"); }
  catch (error) { return <><PageHeader eyebrow="Flight recorder" title="Agents" description="Recorded identities joined to the credentials they hold." /><ErrorState message={error instanceof Error ? error.message : "Agents unavailable"} /></>; }
  return <><PageHeader eyebrow="Flight recorder" title="Agents" description="Follow each runtime identity from credential reach to recorded sessions." />{agents.length ? <Panel className="overflow-hidden"><div className="divide-y divide-slate-100">{agents.map((agent) => <Link href={`/agents/${encodeURIComponent(agent.agent_id)}`} key={agent.agent_id} className="grid gap-4 px-6 py-5 hover:bg-slate-50 md:grid-cols-[1.4fr_110px_110px_1fr] md:items-center"><div><b className="block">{agent.agent_id}</b><span className="text-xs text-slate-500">Last seen {formatDate(agent.last_seen)}</span></div><span className="text-sm"><b>{agent.session_count}</b> sessions</span><span className="text-sm"><b>{agent.event_count}</b> events</span><div className="flex flex-wrap gap-1">{agent.credentials.map((credential) => <span key={credential.id} className="rounded bg-cyan-50 px-2 py-1 font-mono text-[10px] text-cyan-800">{credential.fingerprint}</span>)}</div></Link>)}</div></Panel> : <EmptyState title="No agents recorded" body="Connect the MCP tap or SDK to make agent sessions visible here." href="/integrations" label="Set up recording" />}</>;
}
