#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
# run-vault.sh  — Start Vault dev server without CAP_SETFCAP errors
#
# Fixes: "unable to set CAP_SETFCAP effective capability: Operation not permitted"
#
# Root Cause:
#   Newer hashicorp/vault images run `setcap cap_ipc_lock=+ep /bin/vault`
#   to grant mlock() capability without --cap-add=IPC_LOCK.
#   This setcap call itself requires CAP_SETFCAP, which is stripped in:
#     - Rootless Docker (Docker Desktop on Mac/Windows)
#     - WSL2 environments
#     - GitHub Actions / GitLab CI runners
#     - GKE Autopilot / EKS Fargate (no privileged containers)
#
# Fix:
#   SKIP_SETCAP=true          → skips the setcap call in the entrypoint
#   disable_mlock=true (HCL)  → Vault won't call mlock() at all (dev-safe)
#   Omit --cap-add=IPC_LOCK   → no capability escalation needed
# ─────────────────────────────────────────────────────────────────────────────
set -euo pipefail

VAULT_TOKEN="${VAULT_TOKEN:-root}"
VAULT_PORT="${VAULT_PORT:-8201}"
CONTAINER_NAME="vault-dev"

echo "Starting Vault dev server (CAP_SETFCAP-safe)..."

# Remove existing container if present
docker rm -f "${CONTAINER_NAME}" 2>/dev/null || true

docker run -d \
  --name "${CONTAINER_NAME}" \
  -p "${VAULT_PORT}:8201" \
  -e VAULT_DEV_ROOT_TOKEN_ID="${VAULT_TOKEN}" \
  -e VAULT_DEV_LISTEN_ADDRESS="0.0.0.0:8201" \
  -e SKIP_SETCAP="true" \
  -e VAULT_LOCAL_CONFIG='{"disable_mlock":true,"ui":true}' \
  hashicorp/vault:latest \
  server -dev

echo ""
echo "Waiting for Vault to be ready..."
for i in $(seq 1 20); do
  if docker exec "${CONTAINER_NAME}" vault status >/dev/null 2>&1; then
    echo "✓ Vault is ready"
    break
  fi
  sleep 1
done

echo ""
echo "  VAULT_ADDR=http://127.0.0.1:${VAULT_PORT}"
echo "  VAULT_TOKEN=${VAULT_TOKEN}"
echo ""
echo "  export VAULT_ADDR=http://127.0.0.1:${VAULT_PORT}"
echo "  export VAULT_TOKEN=${VAULT_TOKEN}"
echo "  bash scripts/setup-all.sh"
