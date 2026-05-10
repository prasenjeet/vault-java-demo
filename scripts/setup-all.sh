#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
# setup-all.sh — Configure all HashiCorp Vault secret engines for the demo
#
# Usage:
#   export VAULT_ADDR=http://127.0.0.1:8201
#   export VAULT_TOKEN=root
#   bash scripts/setup-all.sh
#
# Prerequisites:
#   1. Vault running (dev mode):
#      docker run --cap-add=IPC_LOCK \
#          -e VAULT_DEV_ROOT_TOKEN_ID=root \
#          -e VAULT_DEV_LISTEN_ADDRESS=0.0.0.0:8201 \
#          -p 8201:8201 hashicorp/vault:latest server -dev
#
#   2. vault CLI installed (https://developer.hashicorp.com/vault/downloads)
#   3. PostgreSQL running (for DB dynamic secrets)
# ─────────────────────────────────────────────────────────────────────────────
set -euo pipefail

VAULT_ADDR="${VAULT_ADDR:-http://127.0.0.1:8201}"
VAULT_TOKEN="${VAULT_TOKEN:-root}"
PG_HOST="${PG_HOST:-postgres}"
PG_PORT="${PG_PORT:-5432}"
PG_DB="${PG_DB:-mydb}"
PG_ROOT_USER="${PG_ROOT_USER:-postgres}"
PG_ROOT_PASS="${PG_ROOT_PASS:-postgres}"

export VAULT_ADDR VAULT_TOKEN

# ── Colors ────────────────────────────────────────────────────────────────────
GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; NC='\033[0m'
info()    { echo -e "${CYAN}[INFO]${NC}  $*"; }
success() { echo -e "${GREEN}[OK]${NC}    $*"; }
section() { echo -e "\n${YELLOW}══════════════════════════════════════════════${NC}";
            echo -e "${YELLOW}  $*${NC}";
            echo -e "${YELLOW}══════════════════════════════════════════════${NC}"; }

# ── Verify Vault ──────────────────────────────────────────────────────────────
section "1. Verifying Vault Connectivity"
vault status
success "Vault is reachable"

# ══════════════════════════════════════════════════════════════════════════════
# SECRET ENGINE: DATABASE (Dynamic Secrets)
# ══════════════════════════════════════════════════════════════════════════════
section "2. Configuring Database Secrets Engine"

info "Enabling database secrets engine..."
vault secrets enable database 2>/dev/null || info "database already enabled"

info "Configuring PostgreSQL connection..."
vault write database/config/mypostgres \
    plugin_name=postgresql-database-plugin \
    allowed_roles="readonly,readwrite,admin" \
    connection_url="postgresql://{{username}}:{{password}}@${PG_HOST}:${PG_PORT}/${PG_DB}?sslmode=disable" \
    username="${PG_ROOT_USER}" \
    password="${PG_ROOT_PASS}"

info "Creating 'readonly' role..."
vault write database/roles/readonly \
    db_name=mypostgres \
    creation_statements="
        CREATE ROLE \"{{name}}\"
            WITH LOGIN
            PASSWORD '{{password}}'
            VALID UNTIL '{{expiration}}';
        GRANT SELECT ON ALL TABLES IN SCHEMA public TO \"{{name}}\";
        GRANT SELECT ON ALL SEQUENCES IN SCHEMA public TO \"{{name}}\";
        ALTER DEFAULT PRIVILEGES IN SCHEMA public
            GRANT SELECT ON TABLES TO \"{{name}}\";
    " \
    revocation_statements="
        REVOKE ALL PRIVILEGES ON ALL TABLES IN SCHEMA public FROM \"{{name}}\";
        DROP ROLE IF EXISTS \"{{name}}\";
    " \
    default_ttl="1h" \
    max_ttl="24h"

info "Creating 'readwrite' role..."
vault write database/roles/readwrite \
    db_name=mypostgres \
    creation_statements="
        CREATE ROLE \"{{name}}\"
            WITH LOGIN
            PASSWORD '{{password}}'
            VALID UNTIL '{{expiration}}';
        GRANT SELECT, INSERT, UPDATE, DELETE
            ON ALL TABLES IN SCHEMA public TO \"{{name}}\";
        GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO \"{{name}}\";
    " \
    revocation_statements="
        REVOKE ALL PRIVILEGES ON ALL TABLES IN SCHEMA public FROM \"{{name}}\";
        DROP ROLE IF EXISTS \"{{name}}\";
    " \
    default_ttl="1h" \
    max_ttl="24h"

success "Database secrets engine configured"
echo ""
echo "  Test: vault read database/creds/readonly"

# ══════════════════════════════════════════════════════════════════════════════
# SECRET ENGINE: PKI (Certificate Authority)
# ══════════════════════════════════════════════════════════════════════════════
section "3. Configuring PKI Secrets Engine"

# Root CA
info "Enabling PKI engine (Root CA)..."
vault secrets enable pki 2>/dev/null || info "pki already enabled"
vault secrets tune -max-lease-ttl=87600h pki

info "Generating Root CA..."
vault write -field=certificate pki/root/generate/internal \
    common_name="example.com Root CA" \
    ttl=87600h > /tmp/root_ca.crt

info "Configuring Root CA URLs..."
vault write pki/config/urls \
    issuing_certificates="${VAULT_ADDR}/v1/pki/ca" \
    crl_distribution_points="${VAULT_ADDR}/v1/pki/crl"

# Intermediate CA
info "Enabling PKI engine (Intermediate CA)..."
vault secrets enable -path=pki_int pki 2>/dev/null || info "pki_int already enabled"
vault secrets tune -max-lease-ttl=43800h pki_int

info "Generating Intermediate CA CSR..."
vault write -format=json pki_int/intermediate/generate/internal \
    common_name="example.com Intermediate CA" \
    | jq -r '.data.csr' > /tmp/pki_int.csr

info "Signing Intermediate CA with Root CA..."
vault write -format=json pki/root/sign-intermediate \
    csr=@/tmp/pki_int.csr \
    format=pem_bundle \
    ttl=43800h \
    | jq -r '.data.certificate' > /tmp/pki_int.crt

info "Setting signed Intermediate CA..."
vault write pki_int/intermediate/set-signed \
    certificate=@/tmp/pki_int.crt

info "Configuring Intermediate CA URLs..."
vault write pki_int/config/urls \
    issuing_certificates="${VAULT_ADDR}/v1/pki_int/ca" \
    crl_distribution_points="${VAULT_ADDR}/v1/pki_int/crl"

info "Creating certificate issuance role..."
vault write pki_int/roles/example-dot-com \
    allowed_domains="example.com,internal.example.com,test.example.com" \
    allow_subdomains=true \
    allow_bare_domains=true \
    allow_glob_domains=false \
    max_ttl=720h \
    key_type=rsa \
    key_bits=2048 \
    require_cn=true \
    server_flag=true \
    client_flag=true \
    code_signing_flag=false

success "PKI secrets engine configured"
echo ""
echo "  Root CA cert: /tmp/root_ca.crt"
echo "  Test:         vault write pki_int/issue/example-dot-com common_name=api.internal.example.com"

# ══════════════════════════════════════════════════════════════════════════════
# SECRET ENGINE: TRANSIT (Encryption-as-a-Service)
# ══════════════════════════════════════════════════════════════════════════════
section "4. Configuring Transit Secrets Engine"

info "Enabling transit engine..."
vault secrets enable transit 2>/dev/null || info "transit already enabled"

info "Creating AES-256-GCM encryption key..."
vault write -f transit/keys/app-encryption

info "Configuring key rotation policy..."
vault write transit/keys/app-encryption/config \
    min_decryption_version=1 \
    min_encryption_version=0 \
    deletion_allowed=false

info "Creating ECDSA P-256 signing key..."
vault write transit/keys/app-signing type=ecdsa-p256

info "Creating RSA-4096 signing key..."
vault write transit/keys/app-rsa type=rsa-4096

info "Creating HMAC key..."
vault write -f transit/keys/app-hmac

success "Transit secrets engine configured"
echo ""
echo "  Test encrypt: vault write transit/encrypt/app-encryption plaintext=\$(echo 'hello' | base64)"
echo "  Test sign:    vault write transit/sign/app-signing input=\$(echo 'data' | base64)"

# ══════════════════════════════════════════════════════════════════════════════
# SECRET ENGINE: SSH
# ══════════════════════════════════════════════════════════════════════════════
section "5. Configuring SSH Secrets Engine"

# OTP mode
info "Enabling SSH engine (OTP mode)..."
vault secrets enable ssh 2>/dev/null || info "ssh already enabled"

info "Creating OTP role..."
vault write ssh/roles/otp-role \
    key_type=otp \
    default_user=ubuntu \
    allowed_users="ubuntu,ec2-user,centos,admin" \
    cidr_list="0.0.0.0/0"

# Signed Certificate mode
info "Enabling SSH engine (Signed Certificate mode)..."
vault secrets enable -path=ssh-client-signer ssh 2>/dev/null \
    || info "ssh-client-signer already enabled"

info "Generating SSH CA key pair..."
vault write ssh-client-signer/config/ca generate_signing_key=true 2>/dev/null \
    || info "SSH client-signer CA already configured"

info "Exporting CA public key (install this on SSH servers)..."
vault read -field=public_key ssh-client-signer/config/ca \
    > /tmp/vault_ssh_ca.pub

info "Creating client certificate role..."
vault write ssh-client-signer/roles/my-role - <<'ROLE_EOF'
{
    "algorithm_signer": "rsa-sha2-256",
    "allow_user_certificates": true,
    "allowed_users": "ubuntu,ec2-user,*",
    "allowed_extensions": "permit-pty,permit-port-forwarding,permit-agent-forwarding",
    "default_extensions": {"permit-pty": ""},
    "key_type": "ca",
    "default_user": "ubuntu",
    "ttl": "30m0s",
    "max_ttl": "8h"
}
ROLE_EOF

# Host Certificate mode
info "Enabling SSH engine (Host Certificate mode)..."
vault secrets enable -path=ssh-host-signer ssh 2>/dev/null \
    || info "ssh-host-signer already enabled"

vault write ssh-host-signer/config/ca generate_signing_key=true 2>/dev/null \
    || info "SSH host-signer CA already configured"

vault write ssh-host-signer/roles/host-role \
    key_type=ca \
    allow_host_certificates=true \
    allowed_domains="*.example.com,example.com,localhost" \
    allow_subdomains=true \
    ttl=87600h

success "SSH secrets engine configured"
echo ""
echo "  CA public key (install on servers): /tmp/vault_ssh_ca.pub"
echo "  Install on server: cat /tmp/vault_ssh_ca.pub >> /etc/ssh/trusted-user-ca-keys.pem"
echo "  Add to sshd_config: TrustedUserCAKeys /etc/ssh/trusted-user-ca-keys.pem"
echo ""
echo "  Test OTP:  vault write ssh/creds/otp-role ip=10.0.0.1 username=ubuntu"
echo "  Test cert: vault write ssh-client-signer/sign/my-role public_key=@~/.ssh/id_rsa.pub"

# ══════════════════════════════════════════════════════════════════════════════
# POLICIES
# ══════════════════════════════════════════════════════════════════════════════
section "6. Creating Vault Policies"

info "Writing application policy..."
vault policy write myapp-policy - <<'EOF'
# Database dynamic credentials
path "database/creds/readonly" {
  capabilities = ["read"]
}
path "database/creds/readwrite" {
  capabilities = ["read"]
}

# PKI certificate issuance
path "pki_int/issue/example-dot-com" {
  capabilities = ["create", "update"]
}
path "pki_int/sign/example-dot-com" {
  capabilities = ["create", "update"]
}
path "pki_int/revoke" {
  capabilities = ["create", "update"]
}

# Transit encrypt/decrypt/sign/verify
path "transit/encrypt/app-encryption" {
  capabilities = ["create", "update"]
}
path "transit/decrypt/app-encryption" {
  capabilities = ["create", "update"]
}
path "transit/sign/app-signing" {
  capabilities = ["create", "update"]
}
path "transit/verify/app-signing" {
  capabilities = ["create", "update"]
}
path "transit/rewrap/app-encryption" {
  capabilities = ["create", "update"]
}
path "transit/hmac/app-hmac" {
  capabilities = ["create", "update"]
}
path "transit/datakey/plaintext/app-encryption" {
  capabilities = ["create", "update"]
}

# SSH OTP
path "ssh/creds/otp-role" {
  capabilities = ["create", "update"]
}

# SSH signed certificates
path "ssh-client-signer/sign/my-role" {
  capabilities = ["create", "update"]
}

# Lease management
path "sys/leases/renew" {
  capabilities = ["create", "update"]
}
path "sys/leases/revoke" {
  capabilities = ["create", "update"]
}
EOF

success "Policy 'myapp-policy' created"

# AppRole setup
info "Enabling AppRole auth..."
vault auth enable approle 2>/dev/null || info "approle already enabled"

vault write auth/approle/role/myapp \
    token_ttl=1h \
    token_max_ttl=4h \
    token_policies="myapp-policy" \
    bind_secret_id=true \
    secret_id_ttl=24h \
    secret_id_num_uses=100

ROLE_ID=$(vault read -field=role_id auth/approle/role/myapp/role-id)
SECRET_ID=$(vault write -field=secret_id -f auth/approle/role/myapp/secret-id)

success "AppRole configured"
echo ""
echo "  VAULT_ROLE_ID=${ROLE_ID}"
echo "  VAULT_SECRET_ID=${SECRET_ID}"

# ── Summary ───────────────────────────────────────────────────────────────────
section "✓ Setup Complete"
echo ""
echo "  Secret Engines:"
vault secrets list
echo ""
echo "  Run the demo:"
echo "    VAULT_ADDR=${VAULT_ADDR} VAULT_TOKEN=${VAULT_TOKEN} mvn exec:java"
echo ""
echo "  Or run specific engine:"
echo "    mvn exec:java -Dexec.args=transit"
echo "    mvn exec:java -Dexec.args=db"
echo "    mvn exec:java -Dexec.args=pki"
echo "    mvn exec:java -Dexec.args=ssh"
