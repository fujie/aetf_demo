#!/usr/bin/env bash
# Deletes everything created by deploy.sh (the whole resource group).
set -euo pipefail
PREFIX="${PREFIX:-aetf}"
RESOURCE_GROUP="${RESOURCE_GROUP:-${PREFIX}-demo-rg}"
az group delete -n "$RESOURCE_GROUP" --yes
