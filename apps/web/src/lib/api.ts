import "server-only";

import type { components } from "@/lib/generated/api-contracts";
import { getTenantId } from "@/lib/tenant";

type Schemas = components["schemas"];
type AgentSummary = Schemas["AgentSummary"];
type AlertView = Schemas["AlertView"];
export type BlastResource = Schemas["BlastResource"];
type ChannelConfig = Schemas["ChannelConfig"];
type CredentialDetail = Schemas["CredentialDetail"];
export type CredentialLink = Schemas["CredentialLink"];
type CredentialSummary = Schemas["CredentialSummary"];
type FindingDetail = Schemas["FindingDetail"];
type FindingSummary = Schemas["FindingSummary"];
export type GapMarker = Schemas["GapMarker"];
type GitHubInstallLink = Schemas["GitHubInstallLink"];
type GcpConnectInfo = Schemas["GcpConnectInfo"];
export type ImpactPreview = Schemas["ImpactPreview"];
export type IncidentReport = Schemas["IncidentReport"];
type IntegrationStatus = Schemas["IntegrationStatus"];
export type Overview = Schemas["Overview"];
type PermissionReach = Schemas["PermissionReach"];
export type SessionDetail = Schemas["SessionDetail"];
export type SessionSummary = Schemas["SessionSummary"];
type SettingsView = Schemas["SettingsView"];
export type TimelineEvent = Schemas["TimelineEvent"];
type VerifyResult = Schemas["VerifyResult"];

export type Finding = FindingSummary & Partial<Pick<FindingDetail, "evidence">>;
export type Credential = CredentialSummary &
  Partial<Pick<CredentialDetail, "created_at" | "findings" | "permissions">>;
export type Integration = IntegrationStatus;
export type InstallLink = GitHubInstallLink;
export type GcpConnectionInfo = GcpConnectInfo;
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
    throw new Error(`Leaflyst API returned ${response.status}`);
  }
  return (await response.json()) as T;
}

export async function apiPost<T>(path: string, body: unknown): Promise<T> {
  const tenantId = await getTenantId();
  if (!tenantId) throw new Error("No workspace is selected. Complete onboarding first.");
  const url = new URL(path, apiUrl);
  url.searchParams.set("tenant_id", tenantId);
  const response = await fetch(url, { method: "POST", headers: { "X-ABX-Admin-Key": adminKey, "Content-Type": "application/json" }, body: JSON.stringify(body), cache: "no-store" });
  if (!response.ok) throw new Error(`Leaflyst API returned ${response.status}`);
  return (await response.json()) as T;
}

export async function apiPut<T>(path: string, body: unknown): Promise<T> {
  const tenantId = await getTenantId();
  if (!tenantId) throw new Error("No workspace is selected. Complete onboarding first.");
  const url = new URL(path, apiUrl);
  url.searchParams.set("tenant_id", tenantId);
  const response = await fetch(url, { method: "PUT", headers: { "X-ABX-Admin-Key": adminKey, "Content-Type": "application/json" }, body: JSON.stringify(body), cache: "no-store" });
  if (!response.ok) throw new Error(`Leaflyst API returned ${response.status}`);
  return (await response.json()) as T;
}

export async function adminApiPost<T>(path: string, body: unknown): Promise<T> {
  const response = await fetch(new URL(path, apiUrl), {
    method: "POST",
    headers: { "X-ABX-Admin-Key": adminKey, "Content-Type": "application/json" },
    body: JSON.stringify(body),
    cache: "no-store",
  });
  if (!response.ok) throw new Error(`Leaflyst API returned ${response.status}`);
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
