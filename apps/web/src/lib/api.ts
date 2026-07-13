import "server-only";

import type {
  AgentSummary,
  AlertView,
  BlastResource,
  ChannelConfig,
  CredentialDetail,
  CredentialLink,
  CredentialSummary,
  FindingDetail,
  FindingSummary,
  GapMarker,
  GitHubInstallLink,
  ImpactPreview,
  IncidentReport,
  IntegrationStatus,
  Overview,
  PermissionReach,
  SessionDetail,
  SessionSummary,
  SettingsView,
  TimelineEvent,
  VerifyResult,
} from "@/lib/generated/api-contracts";
import { getTenantId } from "@/lib/tenant";

export type { BlastResource, CredentialLink, GapMarker, ImpactPreview, IncidentReport, Overview, SessionDetail, SessionSummary, TimelineEvent };
export type Finding = FindingSummary & Partial<Pick<FindingDetail, "evidence">>;
export type Credential = CredentialSummary &
  Partial<Pick<CredentialDetail, "created_at" | "findings" | "permissions">>;
export type Integration = IntegrationStatus;
export type InstallLink = GitHubInstallLink;
export type Agent = AgentSummary & { credentials: CredentialLink[] };
export type ChainVerification = VerifyResult;
export type Alert = AlertView;
export type AlertChannel = ChannelConfig;
export type TenantSettings = SettingsView;
export type Permission = PermissionReach;

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
