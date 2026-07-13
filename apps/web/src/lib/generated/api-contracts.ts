/* Generated from FastAPI OpenAPI. Do not edit by hand. */

export type AgentSummary = { agent_id: string; credentials?: Array<CredentialLink>; event_count?: number; framework?: string; last_seen?: string | null; session_count?: number; status?: string };

export type AlertView = { agent_id: string; credential_ref: string | null; dispatch_status: { [key: string]: unknown }; event_id: string; evidence: { [key: string]: unknown }; first_seen: string; hit_count: number; id: string; last_seen: string; rule_id: string; session_id: string; severity: string; status: string; title: string };

export type AuthorizationResult = { authorized: boolean };

export type BlastResource = { credentials: Array<CredentialLink>; event_ids: Array<string>; kind: string; provider: string; resource_ref: string };

export type BootstrapRequest = { tenant_name: string; user_ref: string };

export type BootstrapResult = { created: boolean; ingest_token: string | null; scan_token: string | null; tenant_id: string };

export type ChannelConfig = { enabled?: boolean; kind: string; secret_configured?: boolean; target?: string };

export type ChannelUpdate = { enabled?: boolean; kind: string; target?: string };

export type CredentialDetail = { created_at: string | null; findings: Array<FindingSummary>; fingerprint: string; id: string; kind: string; last_used_at: string | null; open_findings: number; owner: string | null; permissions: Array<PermissionReach>; provider: string; status: string };

export type CredentialLink = { fingerprint: string; id: string; kind: string; provider: string };

export type CredentialSummary = { fingerprint: string; id: string; kind: string; last_used_at: string | null; open_findings: number; owner: string | null; provider: string; status: string };

export type DemoResult = { agent_id: string; alert_ids: Array<string>; credential_id: string; destructive_attempt: string; finding_id: string; sandboxed?: boolean; scanner_warning: string; session_id: string; tenant_id: string };

export type EventType = "llm_call" | "tool_call" | "mcp_request" | "mcp_response" | "agent_step" | "http_call" | "file_op" | "db_op" | "credential_revocation";

export type ExportJSON = { findings: Array<{ [key: string]: unknown }>; tenant_id: string };

export type FindingDetail = { evidence: { [key: string]: unknown }; finding_type: string; fingerprint: string | null; id: string; owner: string | null; provider: string | null; remediation: string; severity: string };

export type FindingSummary = { finding_type: string; fingerprint: string | null; id: string; owner: string | null; provider: string | null; remediation: string; severity: string };

export type GapMarker = { after_seq: number; before_seq: number; kind: "gap"; missing_count: number };

export type GitHubInstallLink = { configured: boolean; install_url: string | null };

export type HTTPValidationError = { detail?: Array<ValidationError> };

export type ImpactPreview = { agent_consumers: Array<string>; cold: boolean; credential_id: string; events_last_30d: number; fingerprint: string; guided_commands: Array<string>; kind: string; last_recorded_at: string | null; last_used_at: string | null; next_action: string; one_click: boolean; provider: string; reachable_resources: Array<string>; status: string; write_credential_configured: boolean };

export type IncidentReport = { alerts: Array<ReportAlert>; anchor_ref: string | null; anchor_status: string; blast_radius: Array<ReportResource>; chain_head_hash: string | null; chain_head_seq: number | null; credentials: Array<ReportCredential>; generated_at: string; markdown: string; report_id: string; session: SessionSummary; summary: string; timeline: Array<ReportEvent>; verification: VerifyResult };

export type IngestBatch = { events: Array<IngestEvent> };

export type IngestEvent = { agent_id: string; credential_ref?: string | null; event_id: string; event_type: EventType; operation: Operation; payload?: string | null; resource_refs: Array<ResourceRef>; seq: number; session_id: string; source: Source; ts: string };

export type IngestResult = { accepted: number; chain_head: string };

export type IntegrationStatus = { account?: string | null; connected: boolean; credentials_found: number; last_scan: string | null; provider: string };

export type LocalEvidence = { age_days?: number | null; destructive_actions?: Array<string>; grants?: Array<LocalGrant>; never_used?: boolean | null; reach_count?: number; reachable_resources?: Array<string> };

export type LocalFinding = { credential_kind?: string; evidence: LocalEvidence; finding_type: "orphaned_credential" | "over_privileged" | "stale_authorization" | "blast_radius"; fingerprint: string; natural_key: string; owner: string; provider: "aws"; remediation: string; severity: "critical" | "high" | "medium" | "low" | "info" };

export type LocalGrant = { access: "read" | "write" | "admin"; action: string; environment?: "prod" | "staging" | "dev" | "unknown"; kind: string; resource: string };

export type LocalScanUpload = { api_calls: number; findings: Array<LocalFinding>; scope: string };

export type MemberView = { role?: string; user_ref: string };

export type Operation = { duration_ms?: number | null; name: string; outcome: Outcome; provider?: string | null; target?: string | null };

export type Outcome = "success" | "error" | "denied" | "unknown";

export type Overview = { agents: number; credentials: number; findings_by_severity: { [key: string]: number }; open_findings: number; providers_scanned: Array<string>; scary_number: string; tenant_id: string };

export type PermissionReach = { access: string | null; resource: string | null; scope: string };

export type ReportAlert = { event_id: string; last_seen: string; rule_id: string; severity: string; status: string; title: string };

export type ReportCredential = { fingerprint: string; id: string | null; kind: string; owner: string | null; provider: string; reachable_resources?: Array<string>; scopes?: Array<string> };

export type ReportEvent = { credential_ref?: string | null; duration_ms?: number | null; event_id?: string | null; kind: string; missing_count?: number | null; operation?: string | null; outcome?: string | null; seq?: number | null; target?: string | null; ts?: string | null };

export type ReportResource = { credential_refs: Array<string>; event_count: number; kind: string; provider: string; resource_ref: string };

export type ResourceRef = string;

export type RevokeRequest = { action: "deactivate" | "delete" | "revoke"; confirmation: string };

export type RevokeResult = { action: string; credential_status: string; status: string };

export type SessionDetail = { blast_radius: Array<BlastResource>; read_only?: boolean; session: SessionSummary; timeline: Array<TimelineEvent | GapMarker>; verification: VerifyResult };

export type SessionSummary = { agent_id: string; ended_at: string; error_count: number; event_count: number; session_id: string; started_at: string };

export type SettingsUpdate = { capture_payloads: boolean; retention_days: number; tenant_name: string };

export type SettingsView = { capture_payloads: boolean; created_at: string; members: Array<MemberView>; redaction_rules: Array<string>; retention_days: number; tenant_id: string; tenant_name: string; tokens: Array<TokenView> };

export type ShareCreated = { expires_at: string; share_path: string; token: string };

export type ShareRequest = { expires_in_hours?: number };

export type Source = "mcp_tap" | "sdk_langgraph" | "otel_ingest" | "admin_api";

export type TimelineEvent = { credential: CredentialLink | null; credential_ref: string | null; duration_ms: number | null; event_id: string; event_type: string; kind: "event"; operation: string; outcome: string; payload: string | null; payload_truncated: boolean; provider: string | null; redactions: Array<string>; resource_refs: Array<string>; seq: number; session_id: string; source: string; target: string | null; ts: string };

export type TokenCreate = { kind: "recording" | "local_scan"; label: string };

export type TokenCreated = { id: string; kind: string; label: string; token: string };

export type TokenView = { created_at: string; id: string; kind: "recording" | "local_scan"; label: string; revoked_at: string | null };

export type ValidationError = { ctx?: Record<string, unknown>; input?: unknown; loc: Array<string | number>; msg: string; type: string };

export type VerifyResult = { anchor_head_seq?: number | null; anchor_ref?: string | null; events_checked: number; first_divergent_event_id?: string | null; head_matches_checkpoint?: boolean | null; valid: boolean; verification_mode?: "full" | "range" | "anchored_suffix" | "anchor_failed" };
