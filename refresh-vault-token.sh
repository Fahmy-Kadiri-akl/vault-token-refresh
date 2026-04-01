#!/bin/bash
set -euo pipefail

###############################################################################
# refresh-vault-token.sh (API-only, no CLI required)
#
# Rotates a Vault token using cloud identity (GCP, Azure) or AppRole and
# updates the Akeyless Vault Target via REST API. Self-schedules next run
# based on TTL.
#
# Config: source a .env file or set env vars before running.
# Dependencies: curl, jq, at (atd)
###############################################################################

# Load .env if it exists
ENV_FILE="${ENV_FILE:-${HOME}/.vault-refresh.env}"
[ -f "$ENV_FILE" ] && set -a && source "$ENV_FILE" && set +a

# VAULT_AUTH_METHOD defaults to CLOUD_PROVIDER for backward compatibility
VAULT_AUTH_METHOD="${VAULT_AUTH_METHOD:-${CLOUD_PROVIDER:-}}"

# Validate required vars
: "${VAULT_ADDR:?VAULT_ADDR required}"
: "${VAULT_AUTH_METHOD:?VAULT_AUTH_METHOD required (gcp, azure, or approle)}"
: "${AKEYLESS_API:?AKEYLESS_API required}"
: "${AKEYLESS_ACCESS_ID:?AKEYLESS_ACCESS_ID required}"
: "${AKEYLESS_ACCESS_TYPE:?AKEYLESS_ACCESS_TYPE required}"
: "${AKEYLESS_TARGET_NAME:?AKEYLESS_TARGET_NAME required}"
: "${VAULT_URL:?VAULT_URL required}"

# VAULT_ROLE is required for cloud auth, optional for approle
if [ "$VAULT_AUTH_METHOD" != "approle" ]; then
  : "${VAULT_ROLE:?VAULT_ROLE required for cloud auth}"
fi

REFRESH_RATIO="${REFRESH_RATIO:-0.75}"
MIN_MINUTES=1
LOG_FILE="${LOG_FILE:-/var/log/refresh-vault-token.log}"
VERIFY_PATH="${VERIFY_PATH:-}"
SELF_SCHEDULE="${SELF_SCHEDULE:-true}"
UID_TOKEN_FILE="${UID_TOKEN_FILE:-${HOME}/.vault-refresh-uid-token}"
VAULT_APPROLE_MOUNT="${VAULT_APPROLE_MOUNT:-approle}"
VAULT_APPROLE_SECRET_ID_FILE="${VAULT_APPROLE_SECRET_ID_FILE:-${HOME}/.vault-approle-secret-id}"

log() { echo "$(date -u '+%Y-%m-%dT%H:%M:%SZ') $1" | tee -a "$LOG_FILE"; }

log "INFO: Starting Vault token refresh (${VAULT_AUTH_METHOD})"

# --- Step 1: Authenticate to Vault ---
if [ "$VAULT_AUTH_METHOD" = "gcp" ]; then
  CLOUD_JWT=$(curl -sf \
    "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/identity?audience=http://vault/${VAULT_ROLE}&format=full" \
    -H "Metadata-Flavor: Google")
  [ -n "$CLOUD_JWT" ] || { log "ERROR: Failed to get GCP identity token"; exit 1; }

  VAULT_RESP=$(curl -sf "${VAULT_ADDR}/v1/auth/gcp/login" -X POST \
    -d "$(jq -n --arg role "$VAULT_ROLE" --arg jwt "$CLOUD_JWT" '{"role":$role,"jwt":$jwt}')")

elif [ "$VAULT_AUTH_METHOD" = "azure" ]; then
  METADATA=$(curl -sf 'http://169.254.169.254/metadata/instance/compute?api-version=2021-02-01' -H Metadata:true)
  SUB=$(echo "$METADATA" | jq -r '.subscriptionId')
  RG=$(echo "$METADATA" | jq -r '.resourceGroupName')
  VM=$(echo "$METADATA" | jq -r '.name')
  CLOUD_JWT=$(curl -sf 'http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https%3A%2F%2Fmanagement.azure.com%2F' -H Metadata:true | jq -r '.access_token')
  [ -n "$CLOUD_JWT" ] && [ "$CLOUD_JWT" != "null" ] || { log "ERROR: Failed to get Azure JWT"; exit 1; }

  VAULT_RESP=$(curl -sf "${VAULT_ADDR}/v1/auth/azure/login" -X POST \
    -d "$(jq -n --arg role "$VAULT_ROLE" --arg jwt "$CLOUD_JWT" --arg sub "$SUB" --arg rg "$RG" --arg vm "$VM" \
      '{"role":$role,"jwt":$jwt,"subscription_id":$sub,"resource_group_name":$rg,"vm_name":$vm}')")

elif [ "$VAULT_AUTH_METHOD" = "approle" ]; then
  : "${VAULT_APPROLE_ROLE_ID:?VAULT_APPROLE_ROLE_ID required for approle auth}"
  [ -f "$VAULT_APPROLE_SECRET_ID_FILE" ] || { log "ERROR: AppRole secret_id file not found: $VAULT_APPROLE_SECRET_ID_FILE"; exit 1; }
  APPROLE_SECRET_ID=$(cat "$VAULT_APPROLE_SECRET_ID_FILE")
  [ -n "$APPROLE_SECRET_ID" ] || { log "ERROR: AppRole secret_id file is empty"; exit 1; }

  VAULT_RESP=$(curl -sf "${VAULT_ADDR}/v1/auth/${VAULT_APPROLE_MOUNT}/login" -X POST \
    -d "$(jq -n --arg rid "$VAULT_APPROLE_ROLE_ID" --arg sid "$APPROLE_SECRET_ID" \
      '{"role_id":$rid,"secret_id":$sid}')")

else
  log "ERROR: Unsupported VAULT_AUTH_METHOD=$VAULT_AUTH_METHOD (use gcp, azure, or approle)"; exit 1
fi

TOKEN=$(echo "$VAULT_RESP" | jq -r '.auth.client_token')
TTL=$(echo "$VAULT_RESP" | jq -r '.auth.lease_duration')
[ -n "$TOKEN" ] && [ "$TOKEN" != "null" ] || { log "ERROR: Vault auth failed: $VAULT_RESP"; exit 1; }
log "INFO: Got Vault token (TTL: ${TTL}s)"

# --- Step 2: Verify token ---
if [ -n "$VERIFY_PATH" ]; then
  VERIFY=$(curl -sf "${VAULT_ADDR}/v1/${VERIFY_PATH}" \
    -H "X-Vault-Token: $TOKEN" -o /dev/null -w '%{http_code}')
  [ "$VERIFY" = "200" ] || { log "ERROR: Token verify failed (HTTP $VERIFY)"; exit 1; }
  log "INFO: Token verified"
fi

# --- Step 3: Authenticate to Akeyless via REST API ---
if [ "$AKEYLESS_ACCESS_TYPE" = "universal_identity" ]; then
  # UID auth: read token from file, auth, save rotated token back
  [ -f "$UID_TOKEN_FILE" ] || { log "ERROR: UID token file not found: $UID_TOKEN_FILE"; exit 1; }
  UID_TOKEN=$(cat "$UID_TOKEN_FILE")
  [ -n "$UID_TOKEN" ] || { log "ERROR: UID token file is empty: $UID_TOKEN_FILE"; exit 1; }

  AKL_RESP=$(curl -sf "${AKEYLESS_API}/auth" \
    -X POST -H "Content-Type: application/json" \
    -d "$(jq -n --arg aid "$AKEYLESS_ACCESS_ID" --arg atype "universal_identity" --arg uid "$UID_TOKEN" \
      '{"access-id":$aid,"access-type":$atype,"uid_token":$uid}')")
  AKL_TOKEN=$(echo "$AKL_RESP" | jq -r '.token')
  [ -n "$AKL_TOKEN" ] && [ "$AKL_TOKEN" != "null" ] || { log "ERROR: Akeyless UID auth failed: $AKL_RESP"; exit 1; }

  # Save rotated UID token for next run
  NEW_UID=$(echo "$AKL_RESP" | jq -r '.uid_token')
  if [ -n "$NEW_UID" ] && [ "$NEW_UID" != "null" ]; then
    echo -n "$NEW_UID" > "$UID_TOKEN_FILE"
    chmod 600 "$UID_TOKEN_FILE"
    log "INFO: UID token rotated and saved"
  fi
else
  # Cloud identity auth (GCP or Azure)
  if [ "$VAULT_AUTH_METHOD" = "gcp" ]; then
    AKL_CLOUD_JWT=$(curl -sf \
      "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/identity?audience=akeyless.io&format=full" \
      -H "Metadata-Flavor: Google")
    B64_CLOUD_ID=$(echo -n "$AKL_CLOUD_JWT" | base64 -w0)
  elif [ "$VAULT_AUTH_METHOD" = "azure" ]; then
    B64_CLOUD_ID=$(echo -n "$CLOUD_JWT" | base64 -w0)
  elif [ "$VAULT_AUTH_METHOD" = "approle" ]; then
    log "ERROR: AppRole does not provide cloud identity for Akeyless. Set AKEYLESS_ACCESS_TYPE=universal_identity"; exit 1
  fi

  AKL_RESP=$(curl -sf "${AKEYLESS_API}/auth" \
    -X POST -H "Content-Type: application/json" \
    -d "$(jq -n --arg aid "$AKEYLESS_ACCESS_ID" --arg atype "$AKEYLESS_ACCESS_TYPE" --arg cid "$B64_CLOUD_ID" \
      '{"access-id":$aid,"access-type":$atype,"cloud-id":$cid}')")
  AKL_TOKEN=$(echo "$AKL_RESP" | jq -r '.token')
  [ -n "$AKL_TOKEN" ] && [ "$AKL_TOKEN" != "null" ] || { log "ERROR: Akeyless auth failed: $AKL_RESP"; exit 1; }
fi
log "INFO: Authenticated to Akeyless API (${AKEYLESS_ACCESS_TYPE})"

# --- Step 4: Update Akeyless target via REST API ---
curl -sf "${AKEYLESS_API}/update-hashi-vault-target" \
  -X POST -H "Content-Type: application/json" \
  -d "$(jq -n --arg tok "$AKL_TOKEN" --arg name "$AKEYLESS_TARGET_NAME" --arg vt "$TOKEN" --arg url "$VAULT_URL" \
    '{"token":$tok,"name":$name,"vault-token":$vt,"hashi-url":$url}')" > /dev/null
log "INFO: Akeyless target '${AKEYLESS_TARGET_NAME}' updated"

# --- Step 5: Self-schedule next run based on TTL ---
NEXT_MINUTES=$(awk "BEGIN { m=int($TTL * $REFRESH_RATIO / 60); if(m<$MIN_MINUTES) m=$MIN_MINUTES; print m }")
if [ "$SELF_SCHEDULE" = "true" ]; then
  SCRIPT_PATH="$(readlink -f "$0")"
  echo "$SCRIPT_PATH" | at now + ${NEXT_MINUTES} minutes 2>&1
  log "INFO: Next refresh in ${NEXT_MINUTES}min (TTL=${TTL}s, ratio=${REFRESH_RATIO})"
else
  log "INFO: Self-scheduling disabled. Recommended next run: ${NEXT_MINUTES}min"
fi
