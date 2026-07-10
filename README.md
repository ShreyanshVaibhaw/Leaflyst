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
