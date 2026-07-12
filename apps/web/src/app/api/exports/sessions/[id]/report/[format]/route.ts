import { chromium, type Browser } from "playwright";
import { apiGet, type IncidentReport } from "@/lib/api";
import { reportHtml } from "@/lib/report-html";

export const maxDuration = 60;
const maxConcurrentRenders = 2;
let activeRenders = 0;

export async function GET(_request: Request, { params }: { params: Promise<{ id: string; format: string }> }) {
  const { id, format } = await params;
  if (!new Set(["md", "pdf"]).has(format)) return new Response("Not found", { status: 404 });
  const reserved = format === "pdf";
  if (reserved && activeRenders >= maxConcurrentRenders) {
    return new Response("PDF renderer is busy; retry shortly", { status: 429, headers: { "Retry-After": "5" } });
  }
  if (reserved) activeRenders += 1;
  let browser: Browser | undefined;
  try {
    const report = await apiGet<IncidentReport>(`/v1/reports/sessions/${encodeURIComponent(id)}`);
    const safeId = id.replaceAll(/[^a-zA-Z0-9_-]/g, "_");
    if (format === "md") return new Response(report.markdown, { headers: { "Content-Type": "text/markdown; charset=utf-8", "Content-Disposition": `attachment; filename="incident-${safeId}.md"` } });
    const channel = process.env.ABX_CHROMIUM_CHANNEL;
    browser = await chromium.launch(channel ? { channel: channel as "chrome" | "msedge", timeout: 20_000 } : { timeout: 20_000 });
    const page = await browser.newPage();
    await page.setContent(reportHtml(report), { waitUntil: "load", timeout: 15_000 });
    const pdf = await page.pdf({ format: "A4", printBackground: true, margin: { top: "12mm", right: "12mm", bottom: "12mm", left: "12mm" } });
    return new Response(new Uint8Array(pdf), { headers: { "Content-Type": "application/pdf", "Content-Disposition": `attachment; filename="incident-${safeId}.pdf"` } });
  } finally {
    await browser?.close();
    if (reserved) activeRenders -= 1;
  }
}
