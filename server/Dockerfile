# syntax=docker/dockerfile:1
#
# Heartfulness Remote server image. Build context = repository root:
#   docker build -f server/Dockerfile -t heartfulness-server .
#
# Base images are pinned by tag. They are deliberately NOT pinned by digest:
# the weekly rebuild timer (deploy/heartfulness-rebuild.timer) re-pulls these
# same tags to pick up OS security patches. Digests at the time of writing
# (for audit): node 22.23.3-alpine3.24 sha256:0a7108bf…, golang 1.24.13-alpine
# sha256:8bee1901…, distroless static-debian12:nonroot sha256:afa5c872….
#
# Optional: networks with a TLS-inspecting proxy can pass its CA bundle as a
# BuildKit secret (never stored in any layer):
#   docker build --secret id=extra_ca,src=/path/ca.pem -f server/Dockerfile .

# ---- 1. web client ----
FROM node:22.23.3-alpine3.24 AS web
WORKDIR /src/web
# The wildcards let this COPY succeed when web/ is missing, so the check below
# can print a clear message instead of a cryptic "not found".
COPY server/go.mod we[b]/package.jso[n] we[b]/package-lock.jso[n] ./
RUN if [ ! -f package.json ]; then \
      echo "ERROR: web/package.json is missing. The web client must be in web/ (see docs/ARCHITECTURE.md) before the server image can be built." >&2; exit 1; \
    fi; \
    if [ ! -f package-lock.json ]; then \
      echo "ERROR: web/package-lock.json is missing. Run 'npm install' in web/ and commit the lockfile." >&2; exit 1; \
    fi; \
    rm -f go.mod
RUN --mount=type=secret,id=extra_ca,required=false \
    if [ -f /run/secrets/extra_ca ]; then export NODE_EXTRA_CA_CERTS=/run/secrets/extra_ca; fi; \
    npm ci --no-audit --no-fund --ignore-scripts
# Wildcard again (see above); go.mod is just a file that always exists.
COPY server/go.mod we[b] ./
RUN rm -rf go.mod dist && npm run build && \
    if [ ! -f dist/index.html ]; then echo "ERROR: 'npm run build' did not produce web/dist/index.html" >&2; exit 1; fi

# ---- 2. server binary ----
FROM golang:1.24.13-alpine AS build
ENV CGO_ENABLED=0 GOWORK=off GOTOOLCHAIN=local GOFLAGS=-mod=readonly
WORKDIR /src
COPY proto/ ./proto/
COPY server/go.mod server/go.sum ./server/
RUN --mount=type=secret,id=extra_ca,required=false \
    if [ -f /run/secrets/extra_ca ]; then cat /etc/ssl/certs/ca-certificates.crt /run/secrets/extra_ca > /tmp/ca.pem; export SSL_CERT_FILE=/tmp/ca.pem; fi; \
    cd server && go mod download && rm -f /tmp/ca.pem
COPY server/ ./server/
RUN rm -rf server/internal/webassets/dist
COPY --from=web /src/web/dist/ ./server/internal/webassets/dist/
RUN cd server && go build -trimpath -ldflags "-s -w" -o /out/heartfulness-server ./cmd/heartfulness-server && \
    mkdir -p /out/data

# ---- 3. runtime: static, non-root, no shell ----
FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/heartfulness-server /heartfulness-server
COPY --from=build --chown=65532:65532 /out/data /data
USER 65532:65532
ENV HR_DATA_DIR=/data HR_LISTEN=:8080
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 CMD ["/heartfulness-server", "healthcheck"]
ENTRYPOINT ["/heartfulness-server"]
CMD ["serve"]
