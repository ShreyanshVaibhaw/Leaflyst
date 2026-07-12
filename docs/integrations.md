# Integration guides

## MCP tap

Set `ABX_INGEST_URL` to the API origin and `ABX_INGEST_TOKEN` to the one-time write-only token, then wrap configured stdio servers:

```text
abx-tap install --client claude-code --agent billing-bot
abx-tap install --client claude-desktop --agent desktop-agent
abx-tap install --client cursor --agent cursor-agent
```

The tap forwards original bytes unchanged. If recording fails, traffic continues and events spool locally.

## Python SDK

```python
from abx import instrument

callback = instrument(agent_id="billing-bot")
result = graph.invoke(inputs, {"callbacks": [callback]})
callback.shutdown()
```

Set `ABX_INGEST_TOKEN` and optionally `ABX_OTLP_ENDPOINT`. Captured message content is disabled by default; enable it only after reviewing the server-side redaction policy.

## OTLP/HTTP

Send OTLP protobuf traces to `POST /v1/otlp/traces` with:

```text
Authorization: Bearer <write-only-ingest-token>
Content-Type: application/x-protobuf
```

The normalizer accepts current and legacy GenAI, OpenLLMetry, and OpenInference attributes. Raw experimental attribute names remain isolated to the normalizer and SDK conventions modules.

## AWS hosted scanner

Deploy `infra/aws/scanner-role.yaml` in the customer account. It grants AWS-managed `SecurityAudit` and `ViewOnlyAccess` to a cross-account role protected by an ExternalId. It has no write actions. Configure the returned role ARN through the integration screen.

Revocation is a separate, optional identity configured from `infra/aws/revoker-policy.yaml`; scanner credentials are never reused for containment.

## AWS local scanner

Run with ambient AWS credentials inside the customer environment:

```text
abx-scanner-local --output
ABX_SCAN_TOKEN=<local-scanner-token> abx-scanner-local --api-url https://api.example.com
```

Every AWS call passes through the scanner's read-only allowlist. Uploads require HTTPS, refuse redirects, and use a dedicated write-only scan token supplied through the environment. They contain typed findings, credential fingerprints, owners, and normalized resource references only—never policy documents or credential values.

## GitHub

Configure a GitHub App with organization members, administration, repository metadata, fine-grained PAT, and deploy-key read access. Set `ABX_GITHUB_APP_SLUG`, `ABX_GITHUB_APP_ID`, `ABX_GITHUB_PRIVATE_KEY`, and `ABX_GITHUB_STATE_SECRET`, then use **Install GitHub App** under Integrations. The first read-only scan is queued automatically.

GitHub does not expose classic PAT inventory through the organization API; block classic PAT access with organization policy where possible.

## Independent evidence verification

Download **Tenant chain evidence** and verify it on any machine with Python 3.12 or newer:

```text
python tools/abx_verify.py tenant-evidence.ndjson --anchor-hash <trusted-anchor-sha256>
```

The verifier is a single standard-library file and does not contact AgentBlackBox. It recomputes every canonical event hash, checks chain order and previous-hash links from genesis, validates the checkpoint, and requires the object-lock anchor to cover that checkpoint and match a hash obtained independently from the bundle. It exits nonzero and reports the first divergent event after tampering.

Portable bundles are schema-owned NDJSON streams pinned to the latest immutable anchor and exclude payload bodies. The verifier processes them in constant memory. They contain canonical metadata for the complete tenant chain through that anchor because intermediate events are required to prove continuity. Treat bundles as sensitive forensic records.
