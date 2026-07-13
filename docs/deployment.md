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
Production startup also requires `ABX_S3_SERVER_SIDE_ENCRYPTION` to name an
encryption mode actually configured by the object-store provider; do not claim
SSE support by setting a value that the provider cannot fulfill.
The web container also fails startup unless both
`NEXT_PUBLIC_CLERK_PUBLISHABLE_KEY` and `CLERK_SECRET_KEY` are supplied in
production. Both are read at runtime, so the same gated image is promoted
between environments; only the Clerk secret must remain in the secret manager.

Run singleton maintenance jobs from an external scheduler:

```text
docker compose --env-file /secure/path/agentblackbox.env -f infra/compose.release.yml --profile maintenance run --rm anchor
docker compose --env-file /secure/path/agentblackbox.env -f infra/compose.release.yml --profile maintenance run --rm retention
```

The ClickHouse application password is injected at runtime through
`users.d/abx_app.xml`. Its grants remain limited to `SELECT` and `INSERT`; it
cannot mutate or alter stored events. Rotate deployment credentials in the
secret manager, never in source-controlled environment files or image layers.

## Backup and restore drill

The single-node topology uses a coordinated cold snapshot for an RPO of the
last completed shutdown and an RTO dominated by volume size. The automated
drill writes a tenant and event, creates an external anchor control, stops all
writers, archives the four durable volumes, destroys only the isolated drill
stack, restores into fresh volumes, and runs the standalone verifier against
the recovered chain:

```text
uv run python demo/recovery_drill.py --skip-build
```

Run this after every storage-version change and at least monthly. Production
managed services should use provider snapshots/PITR with the same restore
ordering: Postgres, ClickHouse, Redis, object storage, one-shot migrations,
then API/workers. A backup is not accepted until the restored evidence matches
an anchor hash retained outside the failed environment.

Daily anchor versions are written in S3 Compliance mode for
`ABX_ANCHOR_RETENTION_DAYS` (ten years by default). Shortening that period is a
data-governance decision; even privileged application credentials cannot
delete a retained anchor version early.

## Release provenance

CI labels both release images with the checked-out commit, inventories their
operating-system and language packages into CycloneDX SBOMs, and records the
immutable image IDs and SBOM SHA-256 hashes in `release-manifest.json`. It then
verifies that the labels, image IDs, and hashes still agree before exercising
the release topology. Download the retained `release-provenance-<commit>`
artifact with every promoted build and keep it with the deployment record.

To reproduce the gate against locally built release images:

```text
python tools/release_manifest.py --output release-artifacts
python tools/release_manifest.py --verify release-artifacts/release-manifest.json
```
