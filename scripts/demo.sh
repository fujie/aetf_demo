#!/usr/bin/env bash
# End-to-end demo of the IHV scenario without a browser.
# Requires the servers to be running (`npm start`) and Go (for the Wallet Instance).
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
WORK="$(mktemp -d)"
JAR="$WORK/cookies"
trap 'rm -rf "$WORK"' EXIT

BASE_PORT="${BASE_PORT:-8700}"
export BASE_PORT
ISSUER=http://localhost:$((BASE_PORT + 20))
IDP=http://localhost:$((BASE_PORT + 10))
VERIFIER=http://localhost:$((BASE_PORT + 40))
USER_NAME="${1:-taro}"

step() { printf '\n\033[1;34m== %s\033[0m\n' "$*"; }
json() { python3 -c "import sys,json;print(json.load(sys.stdin)$1)"; }

step "0. Build the Wallet Instance (vcknots Go wallet)"
(cd "$ROOT/wallet-instance" && GOTOOLCHAIN=auto go build -o wallet-instance .)
WALLET="$ROOT/wallet-instance/wallet-instance"
export WALLET_DIR="$WORK/wallet" TRUST_ANCHOR="$ROOT/.data/trust-anchor.json"

step "1. Wallet Instance -> Wallet Provider: registration + Wallet Attestation"
"$WALLET" init

step "2. User logs in to the GakuNin Issuer via the Institution IdP ($USER_NAME), attributes from the Attribute Provider"
AUTHZ=$(curl -s -c "$JAR" -b "$JAR" -o /dev/null -w '%{redirect_url}' "$ISSUER/login")
TXN=$(curl -s "$AUTHZ" | grep -o 'name="txn" value="[^"]*"' | sed 's/.*value="//;s/"$//')
curl -s -c "$JAR" -b "$JAR" -L -o /dev/null -d "txn=$TXN&username=$USER_NAME&password=password" "$IDP/login"
OFFER=$(curl -s -c "$JAR" -b "$JAR" -X POST "$ISSUER/offer" | grep -o "receive '[^']*'" | sed "s/^receive '//;s/'$//" | sed 's/&amp;/\&/g')
echo "Credential Offer: ${OFFER:0:120}..."

step "3. Wallet receives the credential (OID4VCI, Wallet Attestation at the token endpoint)"
"$WALLET" receive "$OFFER"

step "4. Verifier creates a presentation request; Wallet authenticates it via the LoTE + access certificate and presents"
REQ=$(curl -s -X POST -H 'Accept: application/json' "$VERIFIER/requests")
"$WALLET" present "$(echo "$REQ" | json '["request_uri"]')"
echo "Verifier result: $(curl -s -H 'Accept: application/json' "$(echo "$REQ" | json '["result_url"]')" | json '["status"]')"

TTL="${STATUS_LIST_TTL:-10}"
CODE=$(curl -s "$ISSUER/admin" | grep -o 'name="code" value="[^"]*"' | tail -1 | sed 's/.*value="//;s/"$//')
set_status() { curl -s -o /dev/null -d "code=$CODE&status=$1" "$ISSUER/admin/status"; }
present() {
  local req; req=$(curl -s -X POST -H 'Accept: application/json' "$VERIFIER/requests")
  "$WALLET" present "$(echo "$req" | json '["request_uri"]')" || true
  echo "Verifier result: $(curl -s -H 'Accept: application/json' "$(echo "$req" | json '["result_url"]')" | json '["status"]')"
}
wait_ttl() { echo "(Status List Token ttl=${TTL}s: waiting for the Verifier cache to expire)"; sleep $((TTL + 1)); }

step "5. Issuer suspends the credential (0x02 SUSPENDED) -> presentation is rejected"
set_status 2; wait_ttl; present
"$WALLET" list | grep 'Token Status List'

step "6. Issuer reinstates the credential (0x00 VALID) -> presentation succeeds"
set_status 0; wait_ttl; present

step "7. Issuer revokes the credential (0x01 INVALID, terminal) -> presentation is rejected"
set_status 1; wait_ttl; present
"$WALLET" list | grep 'Token Status List'
