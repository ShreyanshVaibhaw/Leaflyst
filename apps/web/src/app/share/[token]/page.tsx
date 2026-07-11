import { ErrorState, PageHeader } from "@/components/ui";
import { SessionReplay } from "@/components/session-replay";
import { publicApiGet, type SessionDetail } from "@/lib/api";

export const dynamic = "force-dynamic";

export default async function SharedPage({ params }: { params: Promise<{ token: string }> }) {
  const { token } = await params;
  let detail: SessionDetail;
  try { detail = await publicApiGet<SessionDetail>(`/v1/replay/shared/${encodeURIComponent(token)}`); }
  catch (error) { return <ErrorState message={error instanceof Error ? error.message : "Shared replay unavailable"} />; }
  return <><PageHeader eyebrow="Read-only incident replay" title={detail.session.agent_id} description={`Shared session · ${detail.session.event_count} immutable recorded events`} /><SessionReplay detail={detail} shared /></>;
}
