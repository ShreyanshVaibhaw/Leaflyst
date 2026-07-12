# AgentBlackBox

The flight recorder for AI agents: an independent, tamper-evident record of every action an agent takes, plus a credential graph scanner for the keys you forgot your agents had.

## Layout

```
apps/api           FastAPI: ingest, app API, chain verification
apps/web           Next.js dashboard
packages/schemas   Canonical event schema (JSON Schema) + generated Pydantic/TS types
packages/abx-sdk   Python SDK (LangGraph instrumentor)
packages/abx-tap   MCP tap CLI
services/scanner   Credential scanner workers (AWS, GitHub)
services/rules     Anomaly rule engine + alerts
infra              docker compose, migrations, DDL
demo               End-to-end demo scenario
tools/abx_verify.py Standalone standard-library evidence verifier
```

## Development

```
uv sync                                  # install python workspace
pnpm -C apps/web install                 # install web deps
docker compose -f infra/docker-compose.dev.yml up -d
uv run python infra/migrate.py           # apply postgres migrations
uv run python packages/schemas/scripts/codegen.py   # regenerate types after schema changes
uv run pytest
uv run ruff check . && uv run mypy
```

## Release images

The API, migration runner, scanner worker, and alert worker share one locked,
non-root Python image. The standalone Next.js image includes the matching
Playwright Chromium runtime used for incident-report PDFs:

```text
docker build -f infra/docker/python.Dockerfile -t agentblackbox-python:local .
docker build -f infra/docker/web.Dockerfile -t agentblackbox-web:local .
uv run python demo/container_smoke.py
```

The smoke check rejects root images and configured secrets, then verifies both
container health checks, the public security page, and the packaged Chromium
binary. Runtime credentials must be injected by the deployment platform. See
[`docs/deployment.md`](docs/deployment.md) for the one-command release topology.

## Dashboard and onboarding

The server-rendered dashboard reads data without exposing the API admin key to
the browser:

```text
ABX_API_URL=http://localhost:8000
ABX_ADMIN_KEY=dev-admin-key
```

Open `/onboarding` to create a workspace and receive a write-only ingest token.
`ABX_TENANT_ID` remains available as a local-development fallback. See
[`docs/onboarding.md`](docs/onboarding.md) for the cold-start and production
path and [`docs/integrations.md`](docs/integrations.md) for tap, SDK, OTLP,
AWS, local-scanner, and GitHub setup.

For the GitHub App connection flow, set `ABX_GITHUB_APP_SLUG`,
`ABX_GITHUB_APP_ID`, `ABX_GITHUB_PRIVATE_KEY`, and a production
`ABX_GITHUB_STATE_SECRET`. Configure the App setup URL as
`<API URL>/v1/integrations/github/setup`, then run the scanner worker with
`uv run abx-scanner-worker`. Provider secrets stay in the API/worker
environment; PostgreSQL stores installation identifiers only.

## Python SDK and OTLP

LangGraph uses the standard callback configuration:

```python
from abx import instrument
callback = instrument(agent_id="billing-bot")
result = graph.invoke(inputs, {"callbacks": [callback]})
```

Set `ABX_INGEST_TOKEN` and optionally `ABX_OTLP_ENDPOINT` (default:
`http://localhost:8000/v1/otlp/traces`). Message content is disabled by
default; opt in with `OTEL_INSTRUMENTATION_GENAI_CAPTURE_MESSAGE_CONTENT=true`.
Call `callback.shutdown()` during application shutdown to flush buffered spans.

Existing OTLP exporters can send protobuf traces to `/v1/otlp/traces` with the
write-only ingest token in the `Authorization: Bearer ...` header. Current and
legacy OTel GenAI, OpenLLMetry, and OpenInference attributes are normalized.

## Alerts and containment

Run `uv run abx-alert-worker` to evaluate queued events without adding work to
the recording path. Slack and email delivery use deployment secrets
`ABX_SLACK_WEBHOOK_URL` and `ABX_RESEND_API_KEY`; the dashboard stores only
non-secret channel settings and email recipients.

Revocation never reuses scanner credentials. AWS containment requires the
separate `ABX_AWS_REVOKE_ACCESS_KEY_ID` and
`ABX_AWS_REVOKE_SECRET_ACCESS_KEY` identity, restricted to
`iam:UpdateAccessKey` and `iam:DeleteAccessKey` using
`infra/aws/revoker-policy.yaml`. GitHub containment uses the separate
`ABX_GITHUB_REVOKE_TOKEN` with Personal access tokens write and repository
Administration write. Warm credentials remain guided-only regardless of
configuration.
