"use client";

import Link from "next/link";
import { useActionState } from "react";
import { bootstrapTenant, type OnboardingState } from "./actions";

const initialState: OnboardingState = { status: "idle" };

export function OnboardingForm() {
  const [state, action, pending] = useActionState(bootstrapTenant, initialState);
  return <form action={action} className="space-y-5">
    <label className="block"><span className="text-sm font-semibold text-slate-800">Workspace name</span><input name="tenant_name" required maxLength={200} placeholder="Acme Security" className="mt-2 w-full rounded-lg border border-slate-300 px-3 py-2.5 text-sm outline-none focus:border-cyan-600" /></label>
    <button disabled={pending} className="rounded-lg bg-[#081a2c] px-4 py-2.5 text-sm font-semibold text-white disabled:opacity-50">{pending ? "Creating…" : "Create workspace"}</button>
    {state.message ? <div className={`rounded-lg p-4 text-sm ${state.status === "error" ? "bg-rose-50 text-rose-900" : "bg-emerald-50 text-emerald-900"}`}>
      <p>{state.message}</p>
      {state.ingestToken ? <Token label="Recording token" value={state.ingestToken} /> : null}
      {state.scanToken ? <Token label="Local scanner upload token" value={state.scanToken} /> : null}
      {state.status === "success" ? <div className="mt-4 flex flex-wrap gap-3"><Link className="font-semibold underline" href="/integrations">Connect and scan</Link><Link className="font-semibold underline" href="/">Open overview</Link></div> : null}
    </div> : null}
  </form>;
}

function Token({ label, value }: { label: string; value: string }) {
  return <div className="mt-3"><p className="text-xs font-semibold">{label}</p><pre className="mt-1 overflow-x-auto rounded bg-slate-950 p-3 text-xs text-cyan-100">{value}</pre></div>;
}
