import "server-only";

export type Overview = {
  tenant_id: string;
  findings_by_severity: Record<string, number>;
  open_findings: number;
  credentials: number;
  agents: number;
  providers_scanned: string[];
  scary_number: string;
};

export type Finding = {
  id: string;
  finding_type: string;
  severity: string;
  provider: string | null;
  fingerprint: string | null;
  owner: string | null;
  remediation: string;
  evidence?: Record<string, unknown>;
};

export type Credential = {
  id: string;
  provider: string;
  kind: string;
  fingerprint: string;
  owner: string | null;
  last_used_at: string | null;
  status: string;
  open_findings: number;
  created_at?: string | null;
  permissions?: Array<{ scope: string; resource: string | null; access: string | null }>;
  findings?: Finding[];
};

export type Integration = {
  provider: string;
  connected: boolean;
  last_scan: string | null;
  credentials_found: number;
  account: string | null;
};

export type InstallLink = { configured: boolean; install_url: string | null };

const apiUrl = process.env.ABX_API_URL ?? "http://localhost:8000";
const adminKey = process.env.ABX_ADMIN_KEY ?? "dev-admin-key";

export const tenantId = process.env.ABX_TENANT_ID ?? "";

export async function apiGet<T>(path: string, params: Record<string, string> = {}): Promise<T> {
  if (!tenantId) {
    throw new Error("ABX_TENANT_ID is not configured for the dashboard");
  }
  const url = new URL(path, apiUrl);
  url.searchParams.set("tenant_id", tenantId);
  for (const [key, value] of Object.entries(params)) {
    if (value) url.searchParams.set(key, value);
  }
  const response = await fetch(url, {
    headers: { "X-ABX-Admin-Key": adminKey },
    cache: "no-store",
  });
  if (!response.ok) {
    throw new Error(`AgentBlackBox API returned ${response.status}`);
  }
  return (await response.json()) as T;
}

export function humanize(value: string): string {
  return value.replaceAll("_", " ").replace(/\b\w/g, (letter) => letter.toUpperCase());
}

export function formatDate(value: string | null | undefined): string {
  if (!value) return "Never";
  return new Intl.DateTimeFormat("en", {
    dateStyle: "medium",
    timeStyle: "short",
  }).format(new Date(value));
}
