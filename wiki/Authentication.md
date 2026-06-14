# Authentication

The project supports two Vault authentication methods:

| Method | Class | When to Use |
|--------|-------|-------------|
| Token | `VaultConfig` | Local dev, CI jobs with short-lived tokens |
| AppRole | `AppRoleVaultConfig` | Production applications |

## Token Authentication (Dev/Test)

**Class**: `com.example.vault.config.VaultConfig`

Reads from environment variables at startup:

```bash
export VAULT_ADDR=http://127.0.0.1:8201
export VAULT_TOKEN=root
```

`VaultConfig` is a singleton (`getInstance()`). The first call creates the instance; subsequent calls return the cached one. `getVaultTemplate()` is lazily initialized and synchronized.

```java
VaultConfig config = VaultConfig.getInstance();

// Optional: verify Vault is reachable and unsealed
config.verifyConnectivity();   // throws RuntimeException if sealed or unreachable

VaultTemplate vaultTemplate = config.getVaultTemplate();
```

`verifyConnectivity()` calls `GET /v1/sys/health` and throws if Vault is sealed.

**Defaults** (when env vars are not set):
- `VAULT_ADDR` → `http://127.0.0.1:8200`
- `VAULT_TOKEN` → `root`

> Note: The `docker-compose.yml` exposes Vault on port `8201`. Set `VAULT_ADDR=http://127.0.0.1:8201` when using Docker.

## AppRole Authentication (Production)

**Class**: `com.example.vault.config.AppRoleVaultConfig`

AppRole is the recommended auth method for machine-to-machine authentication:

- **Role ID**: not a secret — can be baked into the container image or config map
- **Secret ID**: secret — injected at runtime via CI/CD, init container, or secrets manager

```bash
export VAULT_ADDR=https://vault.production.example.com
export VAULT_ROLE_ID=<role-id-from-vault>
export VAULT_SECRET_ID=<secret-id-injected-at-runtime>
export VAULT_APPROLE_PATH=approle   # optional, default is "approle"
```

```java
AppRoleVaultConfig appRoleConfig = new AppRoleVaultConfig();
VaultTemplate vaultTemplate = appRoleConfig.buildVaultTemplate();
```

`buildVaultTemplate()` calls `auth/approle/login` immediately and exchanges the Role ID + Secret ID for a short-lived Vault token. Throws `IllegalStateException` if either env var is missing.

## Setting Up AppRole in Vault

The setup script (`scripts/setup-all.sh`) creates an AppRole named `myapp`:

```bash
vault auth enable approle

vault write auth/approle/role/myapp \
    token_ttl=1h \
    token_max_ttl=4h \
    token_policies="myapp-policy" \
    bind_secret_id=true \
    secret_id_ttl=24h \
    secret_id_num_uses=100

# Get the Role ID (not a secret — embed in config)
vault read -field=role_id auth/approle/role/myapp/role-id

# Generate a Secret ID (inject at runtime)
vault write -field=secret_id -f auth/approle/role/myapp/secret-id
```

The `myapp-policy` grants access to all engine paths used in the demo. See the policy in [Configuration Reference](Configuration.md#vault-policy).

## Token Refresh

AppRole returns a token with `token_ttl=1h` and `token_max_ttl=4h`. Spring Vault handles token renewal automatically when using `AppRoleAuthentication`. For long-running applications, consider:
- Configuring a longer `token_max_ttl`
- Using `SecretLeaseContainer` (already used by `DynamicDatabaseSecretService`) to manage lease lifecycles

## Environment Variable Reference

| Variable | Used By | Default | Description |
|----------|---------|---------|-------------|
| `VAULT_ADDR` | Both | `http://127.0.0.1:8200` | Vault server URL |
| `VAULT_TOKEN` | `VaultConfig` | `root` | Auth token |
| `VAULT_ROLE_ID` | `AppRoleVaultConfig` | — | AppRole Role ID (required) |
| `VAULT_SECRET_ID` | `AppRoleVaultConfig` | — | AppRole Secret ID (required) |
| `VAULT_APPROLE_PATH` | `AppRoleVaultConfig` | `approle` | AppRole mount path |
