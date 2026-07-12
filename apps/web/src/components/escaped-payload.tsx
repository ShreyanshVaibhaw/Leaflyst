/** Render captured content exclusively as a React text node. */
export function EscapedPayload({ value }: { value: string }) {
  return <pre className="max-h-80 overflow-auto whitespace-pre-wrap break-all border-t border-slate-200 p-4 text-xs text-slate-700">{value}</pre>;
}
