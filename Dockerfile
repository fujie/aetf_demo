# Container image for the deployment (Azure Container Apps): every entity + the web wallet in one
# container (ROLE unset), or the per-entity public proxy (ROLE=proxy). See deploy/azure/.

# ---- web wallet (Go, vcknots wallet) -------------------------------------------------------------
# Base images come from Microsoft Container Registry (no Docker Hub pull limits in ACR builds).
FROM mcr.microsoft.com/oss/go/microsoft/golang:1.25 AS wallet
WORKDIR /src
COPY wallet-instance/go.mod wallet-instance/go.sum ./
RUN go mod download
COPY wallet-instance/ ./
# Microsoft Go defaults to the system (OpenSSL) crypto backend; use Go crypto for a static binary
RUN CGO_ENABLED=0 GOEXPERIMENT=nosystemcrypto go build -trimpath -o /out/wallet-instance .

# ---- entities (TypeScript, vcknots issuer / verifier) -------------------------------------------
FROM mcr.microsoft.com/devcontainers/javascript-node:22-bookworm AS node
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci && npm cache clean --force

FROM mcr.microsoft.com/mirror/docker/library/debian:bookworm-slim
WORKDIR /app
COPY --from=node /usr/local/bin/node /usr/local/bin/node
COPY --from=node /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=node /app/node_modules ./node_modules
COPY package.json tsconfig.json ./
COPY src ./src
COPY --from=wallet /out/wallet-instance /app/bin/wallet-instance
RUN mkdir -p /app/wallet-instance /app/.data
ENV NODE_ENV=production \
    LISTEN_PORT=8080 \
    WALLET_BIN=/app/bin/wallet-instance
EXPOSE 8080
CMD ["sh", "-c", "if [ \"$ROLE\" = proxy ]; then exec node_modules/.bin/tsx src/proxy.ts; else exec node_modules/.bin/tsx src/main.ts --with-wallet; fi"]
