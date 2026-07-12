"use client";

import { useActionState } from "react";
import { createScopedToken, type TokenState } from "./actions";

const initial: TokenState = { status: "idle" };

export function TokenForm() {
  const [state, action, pending] = useActionState(createScopedToken, initial);
  return <form action={action} className="space-y-4">
    <div className="grid gap-3 sm:grid-cols-[1fr_1fr_auto]">
      <select name="kind" className="rounded-lg border border-slate-300 px-3 py-2 text-sm"><option value="recording">Recording token</option><option value="local_scan">Local scanner token</option></select>
      <input name="label" required maxLength={100} placeholder="Production tap" className="rounded-lg border border-slate-300 px-3 py-2 text-sm" />
      <button disabled={pending} className="rounded-lg bg-[#081a2c] px-4 py-2 text-sm font-semibold text-white disabled:opacity-50">{pending ? "Creating…" : "Create token"}</button>
    </div>
    {state.message ? <div className={`rounded-lg p-3 text-sm ${state.status === "error" ? "bg-rose-50 text-rose-900" : "bg-emerald-50 text-emerald-900"}`}><p>{state.message}</p>{state.token ? <pre className="mt-2 overflow-x-auto rounded bg-slate-950 p-3 text-xs text-cyan-100">{state.token}</pre> : null}</div> : null}
  </form>;
}
