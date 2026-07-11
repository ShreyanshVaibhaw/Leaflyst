import Link from "next/link";

const nav = [
  ["Overview", "/"],
  ["Findings", "/findings"],
  ["Credentials", "/credentials"],
  ["Agents", "/agents"],
  ["Integrations", "/integrations"],
] as const;

export function AppShell({ children }: { children: React.ReactNode }) {
  return (
    <div className="min-h-screen bg-[#f3f5f7] text-slate-950">
      <header className="border-b border-slate-200 bg-[#081a2c] text-white lg:hidden">
        <div className="mx-auto flex max-w-7xl items-center justify-between px-5 py-4">
          <Link href="/" className="font-semibold tracking-tight">AgentBlackBox</Link>
          <nav className="flex gap-4 text-xs text-slate-300">
            {nav.slice(1).map(([label, href]) => <Link href={href} key={href}>{label}</Link>)}
          </nav>
        </div>
      </header>
      <aside className="fixed inset-y-0 left-0 hidden w-64 flex-col bg-[#081a2c] px-5 py-7 text-white lg:flex">
        <Link href="/" className="flex items-center gap-3 px-2">
          <span className="grid h-9 w-9 place-items-center rounded-xl bg-cyan-400 font-black text-[#081a2c]">AB</span>
          <span>
            <span className="block font-semibold tracking-tight">AgentBlackBox</span>
            <span className="block text-[11px] uppercase tracking-[0.18em] text-slate-400">Security recorder</span>
          </span>
        </Link>
        <nav className="mt-10 space-y-2">
          {nav.map(([label, href], index) => (
            <Link key={href} href={href} className="flex items-center gap-3 rounded-lg px-3 py-2.5 text-sm text-slate-300 transition hover:bg-white/10 hover:text-white">
              <span className="w-5 text-center text-xs text-cyan-300">0{index + 1}</span>{label}
            </Link>
          ))}
        </nav>
        <div className="mt-auto rounded-xl border border-white/10 bg-white/5 p-4">
          <p className="text-xs font-medium text-cyan-300">Recording integrity</p>
          <p className="mt-1 text-sm text-slate-300">Hash chaining active</p>
          <div className="mt-3 h-1.5 overflow-hidden rounded-full bg-white/10"><div className="h-full w-full bg-emerald-400" /></div>
        </div>
      </aside>
      <main className="lg:pl-64">
        <div className="mx-auto min-h-screen max-w-7xl px-5 py-8 sm:px-8 lg:px-10 lg:py-10">{children}</div>
      </main>
    </div>
  );
}
