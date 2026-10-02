#!/usr/bin/env bash
# Deploys the demo to Azure Container Apps.
#
# Topology (every entity keeps its own Azure-assigned URL = Entity ID):
#   <prefix>-main               all entities + web wallet in one container (internal ingress, 1 replica)
#   <prefix>-<slug> (x14)       public proxy per entity, https://<prefix>-<slug>.<environment domain>
#                               forwards to <prefix>-main (https://<prefix>-main.internal.<domain>)
#                               with the public host name
# Entity IDs are https://<prefix>-<slug>.<defaultDomain>, computed from the Container Apps
# environment's default domain before the apps are created (ENTITY_URL_TEMPLATE).
#
# Requirements: Azure CLI (az) logged in (`az login`) with rights to create resources in the
# subscription. The image is built in Azure (az acr build), so Docker is not needed locally.
#
# Usage: deploy/azure/deploy.sh            (settings via environment variables below)
set -euo pipefail

PREFIX="${PREFIX:-aetf}"                      # app name prefix (lowercase letters, digits, '-')
RESOURCE_GROUP="${RESOURCE_GROUP:-${PREFIX}-demo-rg}"
LOCATION="${LOCATION:-japaneast}"
ENVIRONMENT="${ENVIRONMENT:-${PREFIX}-env}"
PROXY_MIN_REPLICAS="${PROXY_MIN_REPLICAS:-1}"   # 0 allows scale to zero (slower first requests)
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"

SLUGS=(trust-anchor nii i2 idp attribute-provider issuer gakunin-sp wallet-provider trust-list status-list verifier incommon-sp wallet console)
MAIN="${PREFIX}-main"

step() { printf '\n\033[1;34m== %s\033[0m\n' "$*"; }

command -v az >/dev/null || { echo "Azure CLI (az) is required: https://learn.microsoft.com/cli/azure/install-azure-cli"; exit 1; }
az account show >/dev/null || { echo "Run 'az login' first."; exit 1; }
SUBSCRIPTION_ID="$(az account show --query id -o tsv)"
ACR="${ACR:-${PREFIX//-/}acr$(printf '%s' "$SUBSCRIPTION_ID$RESOURCE_GROUP" | sha256sum | cut -c1-8)}"
TAG="${TAG:-$(git -C "$ROOT" rev-parse --short HEAD 2>/dev/null || date +%s)}"
IMAGE="${ACR}.azurecr.io/aetf-demo:${TAG}"

for s in "${SLUGS[@]}"; do
  name="${PREFIX}-${s}"
  [ ${#name} -le 32 ] || { echo "app name too long (max 32): $name - use a shorter PREFIX"; exit 1; }
done

step "Azure CLI extension / resource providers"
az extension add --name containerapp --upgrade --only-show-errors -y
az provider register --namespace Microsoft.App --wait
az provider register --namespace Microsoft.OperationalInsights --wait
az provider register --namespace Microsoft.ContainerRegistry --wait

step "Resource group ${RESOURCE_GROUP} (${LOCATION})"
az group create -n "$RESOURCE_GROUP" -l "$LOCATION" -o none

step "Container registry ${ACR} and image build (az acr build)"
az acr show -n "$ACR" -g "$RESOURCE_GROUP" -o none 2>/dev/null || az acr create -n "$ACR" -g "$RESOURCE_GROUP" --sku Basic -o none
az acr build -r "$ACR" -t "aetf-demo:${TAG}" "$ROOT" -o none

step "Container Apps environment ${ENVIRONMENT}"
az containerapp env show -n "$ENVIRONMENT" -g "$RESOURCE_GROUP" -o none 2>/dev/null \
  || az containerapp env create -n "$ENVIRONMENT" -g "$RESOURCE_GROUP" -l "$LOCATION" -o none
DOMAIN="$(az containerapp env show -n "$ENVIRONMENT" -g "$RESOURCE_GROUP" --query properties.defaultDomain -o tsv)"
TEMPLATE="https://${PREFIX}-{name}.${DOMAIN}"
echo "Entity URL template: ${TEMPLATE}"

# create_or_update <name> <ingress external|internal> <cpu> <memory> <min> <max> <env vars...>
# (new apps pull from the registry with their system-assigned identity)
create_or_update() {
  local name="$1" ingress="$2" cpu="$3" memory="$4" min="$5" max="$6"; shift 6
  if az containerapp show -n "$name" -g "$RESOURCE_GROUP" -o none 2>/dev/null; then
    az containerapp update -n "$name" -g "$RESOURCE_GROUP" --image "$IMAGE" \
      --cpu "$cpu" --memory "$memory" --min-replicas "$min" --max-replicas "$max" --set-env-vars "$@" -o none
  else
    az containerapp create -n "$name" -g "$RESOURCE_GROUP" --environment "$ENVIRONMENT" --image "$IMAGE" \
      --registry-server "${ACR}.azurecr.io" --registry-identity system \
      --ingress "$ingress" --target-port 8080 \
      --cpu "$cpu" --memory "$memory" --min-replicas "$min" --max-replicas "$max" --env-vars "$@" -o none
  fi
}

# The proxies are created first: the main container reaches the other entities (e.g. the
# Registrar at startup) through their public URLs.
step "Public proxies (one per entity)"
for s in "${SLUGS[@]}"; do
  echo "  ${PREFIX}-${s}"
  # internal ingress redirects plain HTTP to HTTPS, so use the main app's internal HTTPS FQDN
  create_or_update "${PREFIX}-${s}" external 0.25 0.5Gi "$PROXY_MIN_REPLICAS" 2 ROLE=proxy PORT=8080 "UPSTREAM=https://${MAIN}.internal.${DOMAIN}"
done

step "Main container ${MAIN} (all entities, internal ingress, single replica: state is in memory)"
create_or_update "$MAIN" internal 1.0 2.0Gi 1 1 "ENTITY_URL_TEMPLATE=${TEMPLATE}" LISTEN_PORT=8080

step "Checking the assigned host names"
for s in "${SLUGS[@]}"; do
  fqdn="$(az containerapp show -n "${PREFIX}-${s}" -g "$RESOURCE_GROUP" --query properties.configuration.ingress.fqdn -o tsv)"
  expected="${PREFIX}-${s}.${DOMAIN}"
  [ "$fqdn" = "$expected" ] || { echo "unexpected FQDN for ${s}: ${fqdn} (expected ${expected})"; exit 1; }
done
echo "All host names match the entity URL template."

step "Waiting for the federation to come up"
for i in $(seq 1 60); do
  if curl -fsS "https://${PREFIX}-trust-anchor.${DOMAIN}/.well-known/openid-federation" -o /dev/null 2>/dev/null \
    && curl -fsS "https://${PREFIX}-console.${DOMAIN}/" -o /dev/null 2>/dev/null; then
    break
  fi
  sleep 10
done

cat <<EOF

Deployed. Entity IDs (Azure-assigned URLs):
$(for s in "${SLUGS[@]}"; do printf '  %-20s https://%s-%s.%s\n' "$s" "$PREFIX" "$s" "$DOMAIN"; done)

Demo console: https://${PREFIX}-console.${DOMAIN}
Web wallet:   https://${PREFIX}-wallet.${DOMAIN}
Delete everything: az group delete -n ${RESOURCE_GROUP} --yes
EOF
