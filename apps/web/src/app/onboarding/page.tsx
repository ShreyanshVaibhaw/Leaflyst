import { PageHeader, Panel } from "@/components/ui";
import { OnboardingForm } from "./onboarding-form";

export default function OnboardingPage() {
  return <>
    <PageHeader eyebrow="Start recording" title="Create your security workspace" description="One workspace connects the read-only credential graph to your agent recordings. No backend setup is required." />
    <div className="grid gap-6 lg:grid-cols-[1fr_1.1fr]">
      <Panel className="p-6"><OnboardingForm /></Panel>
      <Panel className="p-6"><h2 className="font-semibold">Cold-start path</h2><ol className="mt-4 space-y-4 text-sm leading-6 text-slate-600"><li><b className="text-slate-900">1. Connect and scan.</b> Use the hosted read-only AWS/GitHub connection or run the scanner locally.</li><li><b className="text-slate-900">2. See the scary number.</b> The overview ranks over-scoped, stale, and orphaned credentials.</li><li><b className="text-slate-900">3. Install the tap or SDK.</b> Use the one-time write-only token shown here.</li><li><b className="text-slate-900">4. Record and alert.</b> Sessions become replayable, verifiable evidence with live anomaly rules.</li></ol></Panel>
    </div>
  </>;
}
