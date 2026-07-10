# Phase 0 Explained - What Was Built and Why

This document explains everything done in Phase 0 in plain language.
Phase 0 is the foundation: no product features yet, just the skeleton every later phase plugs into.
Think of it as pouring the concrete before building the house.

---

## 1. The folder structure (the monorepo)

Everything lives in one repository with a fixed layout.
"Monorepo" just means all the parts of the product (backend, frontend, SDK, scanner) live in one folder instead of separate repositories.

```
apps/api           The backend server (receives events, serves the dashboard's data)
apps/web           The dashboard website people log into
packages/schemas   The "contract" - the official definition of what an event looks like
packages/abx-sdk   The Python library customers add to their agent code (empty stub for now)
packages/abx-tap   The MCP tap - the proxy that records agent tool calls (empty stub for now)
services/scanner   The credential scanner workers (empty stub for now)
services/rules     The anomaly detection engine (empty stub for now)
infra              Database setup, Docker configuration, migrations
demo               Will hold the PocketOS demo scenario later
docs               Will hold public documentation later
```

The stubs exist on purpose.
Creating every package now, even empty, means the wiring between them (imports, builds, tests) is proven before any real code depends on it.

### The two toolchains

- **Python side** is managed by `uv`, a fast Python package manager.
  The root `pyproject.toml` declares a "workspace": one shared setup where all six Python packages are installed together and can import each other.
  Python 3.12 is pinned in `.python-version`.
- **Web side** is managed by `pnpm`, a fast JavaScript package manager, and lives in `apps/web`.

One command installs everything: `uv sync --all-packages` for Python, `pnpm install` for the website.

---

## 2. The event schema (the most important file in the repo)

File: `packages/schemas/schema/event.schema.json`.

Everything AgentBlackBox does revolves around one idea: every action an agent takes becomes one "event" record.
An LLM call is an event. A tool call is an event. An MCP request is an event.
This file is the official, machine-readable definition of what an event must contain.

Every event has:

| Field | Plain meaning |
|---|---|
| `event_id` | A unique ID for this event |
| `tenant_id` | Which customer this belongs to (every record is customer-scoped) |
| `agent_id` | Which agent did it |
| `session_id` | Which run of the agent it happened in |
| `seq` | The event's position in the run (1st, 2nd, 3rd...) so missing events are detectable |
| `ts` | Exact timestamp |
| `source` | Where we captured it from: the MCP tap, the SDK, or another tool's telemetry |
| `event_type` | What kind of action: llm_call, tool_call, mcp_request, etc. |
| `operation` | What exactly happened: name, target, success or failure, how long it took |
| `credential_ref` | Which credential (key/token) was used - a fingerprint, never the secret itself |
| `resource_refs` | What it touched: files, buckets, repos, databases |
| `payload_digest` | A fingerprint (SHA-256 hash) of the full request/response content |
| `payload_ref` | A pointer to where the full content is stored |
| `payload_truncated` | Whether the content was cut for size |
| `redactions` | Which secret-scrubbing rules fired on the content |
| `prev_hash` | The fingerprint of the PREVIOUS event - this makes the chain |
| `event_hash` | The fingerprint of THIS event |

### Why `prev_hash` and `event_hash` matter (the tamper-evidence trick)

Each event contains the hash of the one before it, like links in a chain.
If anyone secretly edits or deletes an event later, every hash after that point stops matching, and verification fails loudly.
That is the whole "flight recorder you can trust" promise, expressed in two fields.

### Why the hash covers the digest but not the content itself

The `event_hash` includes `payload_digest` (the content's fingerprint) but not the content.
So we can DELETE the heavy content later (privacy laws, retention limits, customer requests) and the chain still verifies.
We can always prove "content with fingerprint X existed here" without keeping the content forever.

### Code generation

We do not hand-write the Python and TypeScript versions of this definition.
A script (`packages/schemas/scripts/codegen.py`) generates both automatically from the JSON file:

- Python classes (using Pydantic) into `packages/schemas/src/abx_schemas/generated/event.py`
- TypeScript types into `packages/schemas/generated/event.ts`

This means the backend and the website can never silently disagree about what an event looks like.
CI runs the script in "check mode": if someone changes the schema but forgets to regenerate, the build fails.

---

## 3. The local development stack (Docker)

File: `infra/docker-compose.dev.yml`.

Four services run in Docker containers on your machine, each with a healthcheck so we know they are actually ready:

| Service | What it is | Why we need it |
|---|---|---|
| **Postgres** | A classic relational database | Holds the identity graph: tenants, agents, credentials, permissions, findings. Small, relational data. |
| **ClickHouse** | A database built for huge append-only logs | Holds the events. Agents generate millions of events; ClickHouse stores and queries that cheaply and fast. |
| **Redis** | An in-memory data store | Will queue background jobs (scans, alerts) in later phases. |
| **MinIO** | S3-compatible file storage running locally | Will hold the payload bodies (the deletable content) and the daily chain anchors. |

Start everything with one command:
`docker compose -f infra/docker-compose.dev.yml up -d`

Two problems came up and were fixed:

1. Docker Desktop was not running, so I started it and waited for the engine.
2. Windows reserves port 9001, which MinIO wanted; its ports were moved to 9401/9402.
3. The ClickHouse healthcheck initially used `wget`, which does not exist inside that container image; it now uses `clickhouse-client` and reports healthy.

---

## 4. The database tables

### Postgres: the identity graph (`infra/postgres/migrations/0001_identity_graph.sql`)

This is the "who can do what" map, as tables:

- `tenants` - our customers.
- `ingest_tokens` - the write-only tokens agents use to send us events. We store only the token's hash, never the token, and this token class can never read data back. That is what stops a compromised agent from reading or editing its own record.
- `agents` - each agent a customer runs, with environment labels (prod/staging/dev).
- `principals` - the accounts/identities credentials belong to (an AWS IAM user, a GitHub user or app).
- `credentials` - every key and token we discover. We store a fingerprint only (like the key ID), NEVER the secret value. There is a comment in the SQL saying exactly that, so no future change forgets.
- `permissions` - what each credential is allowed to do.
- `resources` - the things that can be touched (buckets, repos, databases).
- Edge tables like `agent_holds_credential` and `permission_reaches_resource` - the lines connecting the dots. This is what makes "if this agent is compromised, what can it reach?" a simple database query.
- `findings` - what the scanner discovers (orphaned credentials, over-privileged tokens...), with severity, evidence, and a dedup key so re-scans update instead of duplicate.
- `scan_runs` - a log of every scan we perform, so the scanner itself is auditable.
- `chain_heads` - the latest hash of each customer's event chain, updated on every write.

Migrations are applied by a tiny script, `infra/migrate.py`.
It runs each `.sql` file in order and remembers which ones it already applied in a `schema_migrations` table.
Forward-only on purpose: to undo something, you write a new migration.

### ClickHouse: the events table (`infra/clickhouse/init/0001_events.sql`)

One table, `abx.events`, holding every canonical event, sorted by (tenant, session, sequence) and partitioned by month.

The important part is the **user setup**.
The application connects to ClickHouse as a user called `abx_app` which is granted ONLY `INSERT` and `SELECT`.
In ClickHouse, updating or deleting rows requires the `ALTER` permission, which `abx_app` does not have.
So the append-only promise is not a policy we hope to follow - the database physically refuses mutation.

There is a test that proves this (`apps/api/tests/test_event_store.py`):
it inserts an event as `abx_app`, reads it back, then tries `ALTER ... DELETE`, `ALTER ... UPDATE`, `TRUNCATE`, and `DROP` and asserts every one is denied.
Both tests pass against the live containers.

---

## 5. The backend API (`apps/api`)

Just a skeleton for now: a FastAPI application with one endpoint, `/healthz`, which answers `{"status": "ok"}`.
Its only job in Phase 0 is to prove the wiring: dependencies install, imports work, tests run.
Phase 1 turns it into the real ingest collector (redaction, hash chaining, verification endpoint).

---

## 6. The dashboard website (`apps/web`)

Created with `create-next-app`, which shipped **Next.js 16** (the blueprint said 15; 16 is what is current, and one convention changed: the "middleware" file is now called `proxy.ts`).
The blueprint and project docs were updated to record that fact.

What is in it:

- **Home page** (`/`): the product name, a one-line pitch, and a button to the dashboard.
- **Dashboard page** (`/dashboard`): a placeholder that will fill up in later phases.
- **Auth via Clerk** (a login service, so we never build our own password handling):
  - `src/proxy.ts` protects every page except the home and sign-in pages.
  - `src/app/layout.tsx` wraps the app in Clerk's provider.
  - **Graceful degradation**: if no Clerk keys are configured, the app runs in open "local dev mode" and shows an "auth disabled" badge instead of crashing. To turn real login on, copy `apps/web/.env.example` to `.env.local` and paste your Clerk keys.

The app compiles, typechecks, lints, and produces a production build.

---

## 7. Continuous Integration (`.github/workflows/ci.yml`)

Every push and pull request on GitHub automatically runs two jobs:

**Python job:** install everything, then
- `ruff check` - code style and common bugs
- `mypy --strict` - type checking on the core packages (strictest setting)
- codegen drift check - fails if generated types do not match the schema
- `pytest` - all tests

**Web job:** install, then
- `eslint` - JavaScript/TypeScript linting
- `tsc --noEmit` - type checking
- `next build` - the site must actually build

If any step fails, the build is red. Nothing merges on red.

---

## 8. Problems hit along the way (and their fixes)

| Problem | Fix |
|---|---|
| Tests could not find installed packages | Workspace packages need `uv sync --all-packages`, not plain `uv sync` |
| The type checker rejected the generated Python code | Regenerated with `Annotated` style constraints and enabled the Pydantic mypy plugin |
| FastAPI's test client needed an extra library | Added `httpx` to dev dependencies |
| Docker was not running | Started Docker Desktop and waited for the engine |
| Windows blocks port 9001 | Moved MinIO to ports 9401/9402 |
| ClickHouse container showed "unhealthy" while working fine | The healthcheck used `wget`, which the image lacks; switched to `clickhouse-client` |
| Next.js 16 renamed middleware | Used the new `proxy.ts` convention and updated the docs |

---

## 9. Exit criteria - the proof Phase 0 is done

From plan.md, all verified passing:

1. `docker compose up` brings all four services up healthy. ✅
2. Generated Pydantic and TS types compile and match the schema (drift check green). ✅
3. An event row inserts and reads back; the app user is DENIED any modification (tested). ✅
4. Lint, strict type checks, and all 7 tests are green; the web app builds. ✅

## 10. Where this leaves us

The skeleton is standing: databases with the right guarantees, a fixed event contract shared by every component, a website with login, and CI that keeps everything honest.
Phase 1 builds the first real muscle on it: the ingest collector that takes events in, scrubs secrets out of them, chains them together, and can prove to anyone that the record has not been touched.
