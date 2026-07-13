FROM mcr.microsoft.com/playwright:v1.58.0-noble@sha256:35c7d48b4ccaf3aca5018f5f1bf7f50c7da7d61d176c530741f4f2e9ca336c34 AS build

USER root
RUN corepack enable && corepack prepare pnpm@10.30.3 --activate
WORKDIR /app
COPY apps/web/package.json apps/web/pnpm-lock.yaml apps/web/pnpm-workspace.yaml ./
RUN pnpm install --frozen-lockfile
COPY apps/web ./
ENV NEXT_TELEMETRY_DISABLED=1
RUN ABX_TENANT_COOKIE_SECRET=build-time-placeholder-not-a-runtime-secret pnpm build

FROM mcr.microsoft.com/playwright:v1.58.0-noble@sha256:35c7d48b4ccaf3aca5018f5f1bf7f50c7da7d61d176c530741f4f2e9ca336c34

ARG GIT_COMMIT=unknown
LABEL org.opencontainers.image.source="https://github.com/ShreyanshVaibhaw/Leaflyst" \
      org.opencontainers.image.revision="$GIT_COMMIT"

ENV NODE_ENV=production \
    NEXT_TELEMETRY_DISABLED=1 \
    HOSTNAME=0.0.0.0 \
    PORT=3000 \
    PLAYWRIGHT_BROWSERS_PATH=/ms-playwright
WORKDIR /app
COPY --from=build --chown=pwuser:pwuser /app/.next/standalone ./
COPY --from=build --chown=pwuser:pwuser /app/.next/static ./.next/static
COPY --from=build --chown=pwuser:pwuser /app/public ./public

USER pwuser
EXPOSE 3000
HEALTHCHECK --interval=15s --timeout=3s --start-period=15s --retries=3 \
    CMD ["node", "-e", "fetch('http://127.0.0.1:3000/security').then(r=>{if(!r.ok)process.exit(1)}).catch(()=>process.exit(1))"]

CMD ["sh", "-c", "if [ \"$ABX_ENV\" = production ] && { [ -z \"$NEXT_PUBLIC_CLERK_PUBLISHABLE_KEY\" ] || [ -z \"$CLERK_SECRET_KEY\" ]; }; then echo 'Clerk authentication must be configured in production' >&2; exit 1; fi; exec node server.js"]
