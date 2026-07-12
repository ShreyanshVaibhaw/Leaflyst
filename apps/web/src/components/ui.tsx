import Link from "next/link";

export function PageHeader({ eyebrow, title, description, action }: { eyebrow: string; title: string; description: string; action?: React.ReactNode }) {
  return <header className="mb-8 flex flex-col justify-between gap-5 sm:flex-row sm:items-end">
    <div><p className="text-xs font-semibold uppercase tracking-[0.2em] text-cyan-700">{eyebrow}</p><h1 className="mt-2 text-3xl font-semibold tracking-tight text-slate-950 sm:text-4xl">{title}</h1><p className="mt-2 max-w-2xl text-sm leading-6 text-slate-600">{description}</p></div>{action}
  </header>;
}

export function Panel({ children, className = "" }: { children: React.ReactNode; className?: string }) {
  return <section className={`rounded-2xl border border-slate-200 bg-white shadow-[0_10px_30px_rgba(15,23,42,0.04)] ${className}`}>{children}</section>;
}

const severityStyle: Record<string, string> = {
  critical: "bg-rose-100 text-rose-800 ring-rose-200",
  high: "bg-orange-100 text-orange-800 ring-orange-200",
  medium: "bg-amber-100 text-amber-800 ring-amber-200",
  low: "bg-sky-100 text-sky-800 ring-sky-200",
  info: "bg-slate-100 text-slate-700 ring-slate-200",
};

export function SeverityBadge({ severity }: { severity: string }) {
  return <span className={`inline-flex rounded-full px-2.5 py-1 text-[11px] font-bold uppercase tracking-wider ring-1 ring-inset ${severityStyle[severity] ?? severityStyle.info}`}>{severity}</span>;
}

export function EmptyState({ title, body, href, label }: { title: string; body: string; href?: string; label?: string }) {
  return <Panel className="p-10 text-center"><div className="mx-auto grid h-12 w-12 place-items-center rounded-full bg-slate-100 text-xl">◇</div><h2 className="mt-4 font-semibold">{title}</h2><p className="mx-auto mt-2 max-w-md text-sm leading-6 text-slate-600">{body}</p>{href && label ? <Link href={href} className="mt-5 inline-flex rounded-lg bg-slate-950 px-4 py-2 text-sm font-medium text-white">{label}</Link> : null}</Panel>;
}

export function ErrorState({ message }: { message: string }) {
  return <Panel className="border-amber-200 bg-amber-50 p-6"><p className="font-semibold text-amber-950">Dashboard data is unavailable</p><p className="mt-1 text-sm text-amber-800">{message}</p><p className="mt-3 text-xs text-amber-700">Complete <Link className="font-semibold underline" href="/onboarding">workspace setup</Link> and ensure the API is running.</p></Panel>;
}
