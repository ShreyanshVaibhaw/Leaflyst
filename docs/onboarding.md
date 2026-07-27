# Self-serve onboarding

1. Sign in and open `/onboarding`.
2. Create a workspace. Copy the recording and local-scanner tokens immediately; Leaflyst stores only their SHA-256 hashes and cannot display them again. The tokens have separate write-only scopes.
3. Open **Integrations** and connect AWS, GitHub, or Google Cloud, or run the AWS scanner locally.
4. Install the MCP tap or Python SDK with the write-only token.
5. Run an agent session, then review **Agents**, **Alerts**, replay, blast radius, and the incident report.

The dashboard stores the selected tenant in a signed, HTTP-only cookie. Set `ABX_TENANT_COOKIE_SECRET` to a strong random value in production. `ABX_TENANT_ID` remains an optional development fallback.

## Production environment

Set `ABX_ENV=production`, `ABX_REQUIRE_HTTPS=true`, a unique `ABX_ADMIN_KEY` and `ABX_GITHUB_STATE_SECRET` of at least 32 characters, `ABX_ALLOWED_HOSTS`, and `ABX_S3_SERVER_SIDE_ENCRYPTION`. The API refuses unsafe production defaults.

Configure Clerk publishable and secret keys for sign-up/sign-in. The web server calls the bootstrap endpoint with its server-only admin key; that key is never exposed to the browser.

## Retention operations

Run the payload-retention job daily from a scheduler:

```text
uv run python -m abx_api.retention
```

Retention removes expired payload bodies from object storage. Canonical event metadata and redacted payload digests remain in the append-only chain, so historical verification and independent evidence bundles continue to work.
