import { EmptyState, PageHeader } from "@/components/ui";

// Rendered per request for the same reason as every other page: a prerendered
// body cannot carry the Content Security Policy nonce that proxy.ts sends with
// the response, so its inline scripts would be blocked and every 404 would log
// a policy violation.
export const dynamic = "force-dynamic";

export default function NotFound() {
  return <>
    <PageHeader eyebrow="404" title="Page not found" description="That address does not match anything in this workspace." />
    <EmptyState
      title="Nothing here"
      body="The link may be out of date, or the record may have been removed under a retention policy."
      href="/"
      label="Return to the overview"
    />
  </>;
}
