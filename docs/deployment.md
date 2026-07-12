# Release deployment

`infra/compose.release.yml` is the single-node release and staging topology. It
builds the same two artifacts gated in CI, runs migrations and object-store
initialization once, waits for dependency-aware API readiness, and then starts
the scanner, alert worker, and web application.

Copy `infra/release.env.example` outside the repository, replace every
placeholder with independently generated values, and start the stack:

```text
docker compose --env-file /secure/path/agentblackbox.env -f infra/compose.release.yml up -d --build
curl http://localhost:18000/readyz
curl http://localhost:13000/security
```

The Compose topology is intended for a private staging host or a TLS ingress.
Production ingress must terminate TLS for the web app and public ingest API;
set `ABX_ENV=production`, `ABX_REQUIRE_HTTPS=true`, the public HTTPS
`ABX_API_URL`/`ABX_WEB_URL`, allowed hosts, and CORS origins accordingly. Keep Postgres,
ClickHouse, Redis, MinIO, and the API admin surface off the public network.

Run singleton maintenance jobs from an external scheduler:

```text
docker compose --env-file /secure/path/agentblackbox.env -f infra/compose.release.yml --profile maintenance run --rm anchor
docker compose --env-file /secure/path/agentblackbox.env -f infra/compose.release.yml --profile maintenance run --rm retention
```

The ClickHouse application password is injected at runtime through
`users.d/abx_app.xml`. Its grants remain limited to `SELECT` and `INSERT`; it
cannot mutate or alter stored events. Rotate deployment credentials in the
secret manager, never in source-controlled environment files or image layers.
