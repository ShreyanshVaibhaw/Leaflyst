import Link from "next/link";
import { formatDate, humanize, type SessionDetail, type TimelineEvent } from "@/lib/api";
import { Panel } from "@/components/ui";

export function SessionReplay({ detail, tab = "timeline", shared = false }: { detail: SessionDetail; tab?: string; shared?: boolean }) {
  const base = shared ? "" : `/sessions/${encodeURIComponent(detail.session.session_id)}`;
  return <>
    <div className="mb-6 flex flex-wrap items-center justify-between gap-3">
      <div className="flex rounded-xl bg-slate-200 p-1 text-sm font-semibold">
        <Link href={shared ? "#timeline" : base} className={`rounded-lg px-4 py-2 ${tab !== "blast-radius" ? "bg-white shadow-sm" : "text-slate-600"}`}>Timeline</Link>
        <Link href={shared ? "#blast-radius" : `${base}?tab=blast-radius`} className={`rounded-lg px-4 py-2 ${tab === "blast-radius" ? "bg-white shadow-sm" : "text-slate-600"}`}>Blast radius · {detail.blast_radius.length}</Link>
      </div>
      <span className={`rounded-full px-3 py-1.5 text-xs font-bold uppercase tracking-wide ${detail.verification.valid ? "bg-emerald-100 text-emerald-800" : "bg-rose-100 text-rose-800"}`}>{detail.verification.valid ? "Record verified" : "Verification failed"}</span>
    </div>
    {shared ? <div className="space-y-8"><div id="timeline"><Timeline detail={detail} shared /></div><BlastRadius detail={detail} shared /></div> : tab === "blast-radius" ? <BlastRadius detail={detail} shared={false} /> : <Timeline detail={detail} />}
  </>;
}

function Timeline({ detail, shared = false }: { detail: SessionDetail; shared?: boolean }) {
  return <Panel className="overflow-hidden"><div className="divide-y divide-slate-100">{detail.timeline.map((item, index) => item.kind === "gap" ? <div key={`gap-${index}`} className="bg-amber-50 px-6 py-4 text-center text-xs font-semibold text-amber-800">Recording gap: {item.missing_count} {item.missing_count === 1 ? "step" : "steps"} missing between sequence {item.after_seq} and {item.before_seq}</div> : <EventRow event={item} shared={shared} key={item.event_id} />)}</div></Panel>;
}

function EventRow({ event, shared }: { event: TimelineEvent; shared: boolean }) {
  return <article id={`event-${event.event_id}`} className="grid gap-4 p-6 md:grid-cols-[64px_1fr_auto]">
    <div><span className="grid h-10 w-10 place-items-center rounded-full bg-[#081a2c] font-mono text-xs font-bold text-cyan-300">{event.seq}</span></div>
    <div className="min-w-0"><div className="flex flex-wrap items-center gap-2"><h3 className="font-semibold">{humanize(event.operation)}</h3><span className={`rounded-full px-2 py-0.5 text-[10px] font-bold uppercase ${event.outcome === "error" ? "bg-rose-100 text-rose-800" : "bg-emerald-100 text-emerald-800"}`}>{event.outcome}</span><span className="text-xs text-slate-400">{event.duration_ms ?? 0} ms</span></div><p className="mt-1 break-all text-sm text-slate-600">{event.target ?? event.provider ?? "No target recorded"}</p><div className="mt-3 flex flex-wrap gap-2">{event.credential && !shared ? <Link href={`/credentials/${event.credential.id}`} className="rounded-md bg-cyan-50 px-2 py-1 font-mono text-[11px] text-cyan-800">{event.credential.fingerprint}</Link> : event.credential_ref ? <span className="rounded-md bg-slate-100 px-2 py-1 font-mono text-[11px]">{event.credential_ref}</span> : null}{event.resource_refs.map((resource) => <span key={resource} className="max-w-full truncate rounded-md bg-slate-100 px-2 py-1 font-mono text-[11px] text-slate-600">{resource}</span>)}</div>{event.payload !== null ? <details className="mt-4 rounded-lg border border-slate-200 bg-slate-50"><summary className="cursor-pointer px-4 py-2 text-xs font-semibold text-slate-600">Redacted payload {event.redactions.length ? `· ${event.redactions.length} redactions` : ""}</summary><pre className="max-h-80 overflow-auto whitespace-pre-wrap break-all border-t border-slate-200 p-4 text-xs text-slate-700">{event.payload}</pre></details> : null}</div>
    <time className="text-xs text-slate-400">{formatDate(event.ts)}</time>
  </article>;
}

function BlastRadius({ detail, shared }: { detail: SessionDetail; shared: boolean }) {
  const groups = detail.blast_radius.reduce<Record<string, typeof detail.blast_radius>>((all, resource) => { const key = `${resource.provider}:${resource.kind}`; (all[key] ??= []).push(resource); return all; }, {});
  return <div id="blast-radius" className="space-y-5">{!shared ? <div className="flex justify-end gap-2"><Link href={`/api/exports/sessions/${encodeURIComponent(detail.session.session_id)}/blast-radius/csv`} className="rounded-lg border border-slate-300 bg-white px-3 py-2 text-xs font-semibold">CSV</Link><Link href={`/api/exports/sessions/${encodeURIComponent(detail.session.session_id)}/blast-radius/json`} className="rounded-lg border border-slate-300 bg-white px-3 py-2 text-xs font-semibold">JSON</Link></div> : null}{Object.entries(groups).map(([group, resources]) => <Panel key={group} className="overflow-hidden"><div className="border-b border-slate-100 bg-slate-50 px-6 py-3 text-xs font-bold uppercase tracking-wider text-slate-600">{group.replace(":", " · ")} · {resources.length}</div><div className="divide-y divide-slate-100">{resources.map((resource) => <div key={resource.resource_ref} className="grid gap-3 px-6 py-5 md:grid-cols-[1fr_auto]"><div><p className="break-all font-mono text-sm">{resource.resource_ref}</p><div className="mt-2 flex flex-wrap gap-2">{resource.event_ids.map((id) => <Link key={id} href={`#event-${id}`} className="text-xs font-semibold text-cyan-700">Event {id.slice(0, 8)}</Link>)}</div></div><div className="flex flex-wrap gap-2">{resource.credentials.map((credential) => <Link key={credential.id} href={`/credentials/${credential.id}`} className="rounded-md bg-cyan-50 px-2 py-1 font-mono text-[11px] text-cyan-800">{credential.fingerprint}</Link>)}</div></div>)}</div></Panel>)}</div>;
}
