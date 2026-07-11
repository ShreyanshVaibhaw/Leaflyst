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

export type CredentialLink = { id: string; provider: string; kind: string; fingerprint: string };
export type SessionSummary = { session_id: string; agent_id: string; started_at: string; ended_at: string; event_count: number; error_count: number };
export type Agent = { agent_id: string; framework: string; status: string; last_seen: string | null; session_count: number; event_count: number; credentials: CredentialLink[] };
export type TimelineEvent = { kind: "event"; event_id: string; session_id: string; seq: number; ts: string; source: string; event_type: string; operation: string; provider: string | null; target: string | null; outcome: string; duration_ms: number | null; credential: CredentialLink | null; credential_ref: string | null; resource_refs: string[]; payload: string | null; payload_truncated: boolean; redactions: string[] };
export type GapMarker = { kind: "gap"; after_seq: number; before_seq: number; missing_count: number };
export type BlastResource = { resource_ref: string; provider: string; kind: string; event_ids: string[]; credentials: CredentialLink[] };
export type SessionDetail = { session: SessionSummary; timeline: Array<TimelineEvent | GapMarker>; blast_radius: BlastResource[]; verification: { valid: boolean; events_checked: number; first_divergent_event_id: string | null; head_matches_checkpoint: boolean | null }; read_only: boolean };

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

export async function apiPost<T>(path: string, body: unknown): Promise<T> {
  if (!tenantId) throw new Error("ABX_TENANT_ID is not configured for the dashboard");
  const url = new URL(path, apiUrl);
  url.searchParams.set("tenant_id", tenantId);
  const response = await fetch(url, { method: "POST", headers: { "X-ABX-Admin-Key": adminKey, "Content-Type": "application/json" }, body: JSON.stringify(body), cache: "no-store" });
  if (!response.ok) throw new Error(`AgentBlackBox API returned ${response.status}`);
  return (await response.json()) as T;
}

export async function publicApiGet<T>(path: string): Promise<T> {
  const response = await fetch(new URL(path, apiUrl), { cache: "no-store" });
  if (!response.ok) throw new Error(`Shared replay is unavailable (${response.status})`);
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
