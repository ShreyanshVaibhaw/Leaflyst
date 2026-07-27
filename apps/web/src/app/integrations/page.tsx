import { ErrorState, PageHeader, Panel } from "@/components/ui";
import {
  apiGet,
  formatDate,
  type GcpConnectionInfo,
  type InstallLink,
  type Integration,
} from "@/lib/api";
import { connectGcp } from "./actions";

export const dynamic = "force-dynamic";

type IntegrationParams = {
  github?: string;
  org?: string;
  gcp?: string;
  project?: string;
};

export default async function IntegrationsPage({
  searchParams,
}: {
  searchParams: Promise<IntegrationParams>;
}) {
  const status = await searchParams;
  let integrations: Integration[];
  let githubLink: InstallLink;
  let gcpInfo: GcpConnectionInfo;
  try {
    [integrations, githubLink, gcpInfo] = await Promise.all([
      apiGet<Integration[]>("/v1/dashboard/integrations"),
      apiGet<InstallLink>("/v1/integrations/github/install-url"),
      apiGet<GcpConnectionInfo>("/v1/integrations/gcp/connect-info"),
    ]);
  } catch (error) {
    return (
      <>
        <PageHeader
          eyebrow="Connections"
          title="Integrations"
          description="Read-only provider connections and recording setup."
        />
        <ErrorState
          message={error instanceof Error ? error.message : "Unknown API error"}
        />
      </>
    );
  }

  const byProvider = Object.fromEntries(
    integrations.map((item) => [item.provider, item]),
  );
  const awsTemplate = process.env.ABX_AWS_TEMPLATE_URL ?? "";
  const awsLink = awsTemplate
    ? `https://console.aws.amazon.com/cloudformation/home#/stacks/create/review?templateURL=${encodeURIComponent(awsTemplate)}&stackName=LeaflystScanner`
    : "";

  return (
    <>
      <PageHeader
        eyebrow="Connections"
        title="Integrations"
        description="Connect read-only scanner identities. Revocation credentials are intentionally separate and are never requested here."
      />
      {status.github === "connected" ? (
        <Notice>
          GitHub organization <b>{status.org}</b> connected. Its first read-only scan
          has been queued.
        </Notice>
      ) : null}
      {status.gcp === "queued" ? (
        <Notice>
          Google Cloud project <b>{status.project}</b> connected. Its first read-only
          scan has been queued.
        </Notice>
      ) : null}
      {status.gcp === "invalid" ? (
        <Warning>Enter a valid Google Cloud project ID.</Warning>
      ) : null}
      {status.gcp === "unavailable" ? (
        <Warning>The Google Cloud scan could not be queued. Check worker configuration.</Warning>
      ) : null}

      <div className="grid gap-6 xl:grid-cols-3">
        <Panel className="overflow-hidden">
          <ProviderHeader
            eyebrow="Amazon Web Services"
            title="AWS credential scanner"
            color="text-orange-600"
            connected={byProvider.aws?.connected}
          />
          <div className="p-6">
            <p className="text-sm leading-6 text-slate-600">
              Creates a cross-account role with AWS-managed SecurityAudit and
              ViewOnlyAccess policies plus ExternalId protection.
            </p>
            <ScopeList
              items={[
                "IAM users, roles, access keys and last-used data",
                "Policy reach and Access Advisor signals",
                "Zero write API permissions",
              ]}
            />
            <p className="mt-5 text-xs text-slate-500">
              Last scan: {formatDate(byProvider.aws?.last_scan)}
            </p>
            {awsLink ? (
              <a href={awsLink} className="mt-5 inline-flex rounded-lg bg-[#081a2c] px-4 py-2.5 text-sm font-semibold text-white">
                Open CloudFormation quick create
              </a>
            ) : (
              <Warning>
                Set ABX_AWS_TEMPLATE_URL to enable hosted quick create. Local scanning
                remains available through boto3 credentials.
              </Warning>
            )}
          </div>
        </Panel>

        <Panel className="overflow-hidden">
          <ProviderHeader
            eyebrow="GitHub"
            title="GitHub credential scanner"
            color="text-violet-600"
            connected={byProvider.github?.connected}
          />
          <div className="p-6">
            <p className="text-sm leading-6 text-slate-600">
              Install the read-only GitHub App to inventory fine-grained PATs,
              deploy keys, and App installations.
            </p>
            <ScopeList
              items={[
                "Personal access tokens: read",
                "Organization members and administration: read",
                "Repository metadata and deploy keys: read",
              ]}
            />
            <div className="mt-5 rounded-lg border border-violet-200 bg-violet-50 p-3 text-xs leading-5 text-violet-900">
              <b>Visibility limit:</b> GitHub does not expose classic PATs through an
              organization API. Block classic PAT access in organization policy.
            </div>
            {githubLink.configured && githubLink.install_url ? (
              <a href={githubLink.install_url} className="mt-5 inline-flex rounded-lg bg-[#081a2c] px-4 py-2.5 text-sm font-semibold text-white">
                Install GitHub App
              </a>
            ) : (
              <Warning>
                Configure the GitHub App slug, ID, and private key to enable installation.
              </Warning>
            )}
          </div>
        </Panel>

        <Panel className="overflow-hidden">
          <ProviderHeader
            eyebrow="Google Cloud"
            title="Service-account key scanner"
            color="text-blue-600"
            connected={byProvider.gcp?.connected}
          />
          <div className="p-6">
            <p className="text-sm leading-6 text-slate-600">
              Inventory user-managed service-account key IDs and the IAM resources
              their principals can reach. Tokens and private-key material never enter
              the queue or graph.
            </p>
            <ScopeList items={gcpInfo.required_roles} />
            <div className="mt-5 rounded-lg border border-blue-200 bg-blue-50 p-3 text-xs leading-5 text-blue-900">
              <b>Visibility limit:</b> Google Cloud key inventory has no last-used
              timestamp. Age and IAM reach are shown without claiming usage freshness.
              Key disable/delete remains a separate guided action.
            </div>
            <p className="mt-5 text-xs text-slate-500">
              Last scan: {formatDate(byProvider.gcp?.last_scan)}
            </p>
            {gcpInfo.configured ? (
              <form action={connectGcp} className="mt-5 space-y-3">
                <label className="block text-xs font-semibold text-slate-700" htmlFor="project_id">
                  Project ID
                </label>
                <input
                  id="project_id"
                  name="project_id"
                  required
                  pattern="[a-z][a-z0-9-]{4,28}[a-z0-9]"
                  placeholder="my-production-project"
                  className="w-full rounded-lg border border-slate-300 px-3 py-2 text-sm"
                />
                <button className="rounded-lg bg-[#081a2c] px-4 py-2.5 text-sm font-semibold text-white">
                  Queue read-only scan
                </button>
                <p className="break-all text-[11px] text-slate-500">
                  Scanner principal: {gcpInfo.scanner_principal}
                </p>
              </form>
            ) : (
              <Warning>
                Set ABX_GCP_SCANNER_PRINCIPAL and grant the listed read roles before
                connecting a project.
              </Warning>
            )}
          </div>
        </Panel>
      </div>

      <div className="mt-8">
        <h2 className="text-lg font-semibold">Recording sources</h2>
        <p className="mt-1 text-sm text-slate-600">
          Capture setup for the onboarding path.
        </p>
        <div className="mt-4 grid gap-4 lg:grid-cols-2">
          <Panel className="p-6">
            <p className="text-xs font-bold uppercase tracking-widest text-cyan-700">MCP tap</p>
            <h3 className="mt-2 font-semibold">Out-of-band tool recording</h3>
            <pre className="mt-4 overflow-x-auto rounded-lg bg-slate-950 p-4 text-xs text-cyan-100">abx-tap install --client claude-code --agent my-agent</pre>
          </Panel>
          <Panel className="p-6">
            <p className="text-xs font-bold uppercase tracking-widest text-slate-500">Python SDK</p>
            <h3 className="mt-2 font-semibold">LangGraph and OTLP depth</h3>
            <pre className="mt-4 overflow-x-auto rounded-lg bg-slate-100 p-4 text-xs text-slate-500">instrument(agent_id=&quot;my-agent&quot;)</pre>
          </Panel>
        </div>
      </div>
    </>
  );
}

function ProviderHeader({
  eyebrow,
  title,
  color,
  connected,
}: {
  eyebrow: string;
  title: string;
  color: string;
  connected?: boolean;
}) {
  return (
    <div className="flex items-start justify-between border-b border-slate-100 p-6">
      <div>
        <p className={`text-xs font-bold uppercase tracking-widest ${color}`}>{eyebrow}</p>
        <h2 className="mt-2 text-xl font-semibold">{title}</h2>
      </div>
      <Status connected={connected} />
    </div>
  );
}

function Notice({ children }: { children: React.ReactNode }) {
  return (
    <div className="mb-6 rounded-xl border border-emerald-200 bg-emerald-50 p-4 text-sm text-emerald-900">
      {children}
    </div>
  );
}

function Warning({ children }: { children: React.ReactNode }) {
  return <p className="mt-5 rounded-lg bg-amber-50 p-3 text-xs text-amber-800">{children}</p>;
}

function Status({ connected }: { connected?: boolean }) {
  return (
    <span className={`rounded-full px-3 py-1 text-xs font-bold ${connected ? "bg-emerald-100 text-emerald-800" : "bg-slate-100 text-slate-600"}`}>
      {connected ? "Connected" : "Not connected"}
    </span>
  );
}

function ScopeList({ items }: { items: string[] }) {
  return (
    <ul className="mt-5 space-y-2">
      {items.map((item) => (
        <li className="flex gap-2 text-xs text-slate-600" key={item}>
          <span className="text-emerald-600">✓</span>
          {item}
        </li>
      ))}
    </ul>
  );
}
