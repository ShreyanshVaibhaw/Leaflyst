import { ErrorState, PageHeader } from "@/components/ui";
import { SessionReplay } from "@/components/session-replay";
import { apiGet, type SessionDetail } from "@/lib/api";
import { createSessionShare } from "./actions";

export const dynamic = "force-dynamic";

export default async function SessionPage({ params, searchParams }: { params: Promise<{ id: string }>; searchParams: Promise<{ tab?: string }> }) {
  const [{ id }, query] = await Promise.all([params, searchParams]);
  let detail: SessionDetail;
  try { detail = await apiGet<SessionDetail>(`/v1/replay/sessions/${encodeURIComponent(id)}`); }
  catch (error) { return <ErrorState message={error instanceof Error ? error.message : "Session unavailable"} />; }
  const action = createSessionShare.bind(null, id);
  return <><PageHeader eyebrow="Forensic replay" title={detail.session.agent_id} description={`Session ${detail.session.session_id} · ${detail.session.event_count} recorded events`} action={<form action={action}><button className="rounded-lg bg-slate-950 px-4 py-2 text-sm font-semibold text-white">Create read-only link</button></form>} /><SessionReplay detail={detail} tab={query.tab} /></>;
}
