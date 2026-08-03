import { PageHeader, Panel } from "@/components/ui";

// Rendered per request so the Content Security Policy nonce set in proxy.ts
// can be stamped into this page's inline scripts. A cached HTML body carries
// whatever nonce existed when it was built, which never matches the nonce sent
// with the response, so the browser blocks hydration on a page that looks fine.
export const dynamic = "force-dynamic";

export default function SecurityPage() {
  return <>
    <PageHeader eyebrow="Trust center" title="Security and responsible disclosure" description="How Leaflyst protects recorded agent activity and how to report a vulnerability." />
    <div className="grid gap-6 lg:grid-cols-2">
      <Panel className="p-6"><h2 className="font-semibold">Security boundaries</h2><ul className="mt-4 list-disc space-y-3 pl-5 text-sm leading-6 text-slate-600"><li>Ingest tokens are write-only and stored only as hashes.</li><li>Credential graphs contain fingerprints, never secret values.</li><li>Provider scans are read-only; revocation uses separate credentials and an explicit confirmation.</li><li>Captured payloads are redacted, stored separately, and rendered only as escaped text.</li><li>Every event is hash chained and checkpoints can be anchored in object-locked storage.</li></ul></Panel>
      <Panel className="p-6"><h2 className="font-semibold">Responsible disclosure</h2><p className="mt-4 text-sm leading-6 text-slate-600">Send vulnerability reports to <a className="font-semibold text-cyan-700" href="mailto:security@leaflyst.dev">security@leaflyst.dev</a>. Include affected components, reproduction steps, and impact. Please avoid accessing other tenants, disrupting service, or including live secrets in the report.</p><p className="mt-4 text-sm leading-6 text-slate-600">We will acknowledge reports within three business days, provide status updates during investigation, and coordinate remediation and disclosure timing with the reporter.</p></Panel>
    </div>
  </>;
}
