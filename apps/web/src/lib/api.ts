import "server-only";

import { getTenantId } from "@/lib/tenant";

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
export type Alert = { id: string; rule_id: string; severity: string; title: string; agent_id: string; credential_ref: string | null; event_id: string; session_id: string; evidence: Record<string, unknown>; status: string; hit_count: number; first_seen: string; last_seen: string; dispatch_status: Record<string, unknown> };
export type AlertChannel = { kind: string; target: string; enabled: boolean; secret_configured: boolean };
export type ImpactPreview = { credential_id: string; provider: string; kind: string; fingerprint: string; status: string; cold: boolean; one_click: boolean; write_credential_configured: boolean; last_used_at: string | null; events_last_30d: number; last_recorded_at: string | null; agent_consumers: string[]; reachable_resources: string[]; next_action: string; guided_commands: string[] };
export type IncidentReport = { report_id: string; generated_at: string; summary: string; session: SessionSummary; credentials: Array<{ id: string | null; provider: string; kind: string; fingerprint: string; owner: string | null; scopes: string[]; reachable_resources: string[] }>; timeline: Array<{ kind: string; event_id: string | null; seq: number | null; ts: string | null; operation: string | null; target: string | null; outcome: string | null; duration_ms: number | null; credential_ref: string | null; missing_count: number | null }>; blast_radius: Array<{ provider: string; kind: string; resource_ref: string; event_count: number; credential_refs: string[] }>; alerts: Array<{ rule_id: string; severity: string; title: string; event_id: string; status: string; last_seen: string }>; verification: { valid: boolean; events_checked: number; first_divergent_event_id: string | null; head_matches_checkpoint: boolean | null }; chain_head_hash: string | null; chain_head_seq: number | null; anchor_ref: string | null; anchor_status: string; markdown: string };
export type TenantSettings = { tenant_id: string; tenant_name: string; created_at: string; members: Array<{ user_ref: string; role: string }>; tokens: Array<{ id: string; kind: "recording" | "local_scan"; label: string; created_at: string; revoked_at: string | null }>; retention_days: number; capture_payloads: boolean; redaction_rules: string[] };

const apiUrl = process.env.ABX_API_URL ?? "http://localhost:8000";
const adminKey = process.env.ABX_ADMIN_KEY ?? "dev-admin-key";

export async function apiGet<T>(path: string, params: Record<string, string> = {}): Promise<T> {
  const tenantId = await getTenantId();
  if (!tenantId) {
    throw new Error("No workspace is selected. Complete onboarding first.");
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
  const tenantId = await getTenantId();
  if (!tenantId) throw new Error("No workspace is selected. Complete onboarding first.");
  const url = new URL(path, apiUrl);
  url.searchParams.set("tenant_id", tenantId);
  const response = await fetch(url, { method: "POST", headers: { "X-ABX-Admin-Key": adminKey, "Content-Type": "application/json" }, body: JSON.stringify(body), cache: "no-store" });
  if (!response.ok) throw new Error(`AgentBlackBox API returned ${response.status}`);
  return (await response.json()) as T;
}

export async function apiPut<T>(path: string, body: unknown): Promise<T> {
  const tenantId = await getTenantId();
  if (!tenantId) throw new Error("No workspace is selected. Complete onboarding first.");
  const url = new URL(path, apiUrl);
  url.searchParams.set("tenant_id", tenantId);
  const response = await fetch(url, { method: "PUT", headers: { "X-ABX-Admin-Key": adminKey, "Content-Type": "application/json" }, body: JSON.stringify(body), cache: "no-store" });
  if (!response.ok) throw new Error(`AgentBlackBox API returned ${response.status}`);
  return (await response.json()) as T;
}

export async function adminApiPost<T>(path: string, body: unknown): Promise<T> {
  const response = await fetch(new URL(path, apiUrl), {
    method: "POST",
    headers: { "X-ABX-Admin-Key": adminKey, "Content-Type": "application/json" },
    body: JSON.stringify(body),
    cache: "no-store",
  });
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
