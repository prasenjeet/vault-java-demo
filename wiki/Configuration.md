# Configuration Reference

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `VAULT_ADDR` | `http://127.0.0.1:8200` | Vault server URL |
| `VAULT_TOKEN` | `root` | Auth token (dev/test) |
| `VAULT_ROLE_ID` | — | AppRole Role ID (production) |
| `VAULT_SECRET_ID` | — | AppRole Secret ID (production) |
| `VAULT_APPROLE_PATH` | `approle` | AppRole mount path |
| `DB_HOST` | `localhost` | PostgreSQL hostname |
| `DB_PORT` | `5432` | PostgreSQL port |
| `DB_NAME` | `mydb` | PostgreSQL database name |
| `METRICS_PORT` | `8080` | Port for Prometheus `/metrics` HTTP server |

`VaultConfig` checks env vars first, then Java system properties (e.g., `-DVAULT_ADDR=...`), then falls back to the defaults above.

> The `docker-compose.yml` exposes Vault on port **8201**, not 8200. Set `VAULT_ADDR=http://127.0.0.1:8201` when using Docker.

## Vault Mount Paths

| Engine | Mount | Configured By |
|--------|-------|---------------|
| Database | `database/` | `DynamicDatabaseSecretService` (hardcoded prefix) |
| PKI Root CA | `pki/` | `scripts/setup-all.sh` |
| PKI Intermediate CA | `pki_int/` | `PkiSecretService` constructor |
| Transit | `transit/` | `TransitSecretService` (via `opsForTransit()`) |
| SSH OTP | `ssh/` | `SshSecretService` constructor |
| SSH Client Signer | `ssh-client-signer/` | `SshSecretService` constructor |
| SSH Host Signer | `ssh-host-signer/` | `SshSecretService` constructor |
| AppRole Auth | `auth/approle/` | `AppRoleVaultConfig` |

## Vault Policy

The `myapp-policy` created by `scripts/setup-all.sh` covers all demo paths:

```hcl
# Dynamic DB credentials
path "database/creds/readonly"  { capabilities = ["read"] }
path "database/creds/readwrite" { capabilities = ["read"] }

# PKI certificate issuance
path "pki_int/issue/example-dot-com" { capabilities = ["create", "update"] }
path "pki_int/sign/example-dot-com"  { capabilities = ["create", "update"] }
path "pki_int/revoke"                { capabilities = ["create", "update"] }

# Transit encrypt/decrypt
path "transit/encrypt/app-encryption"           { capabilities = ["create", "update"] }
path "transit/decrypt/app-encryption"           { capabilities = ["create", "update"] }
path "transit/sign/app-signing"                 { capabilities = ["create", "update"] }
path "transit/verify/app-signing"               { capabilities = ["create", "update"] }
path "transit/rewrap/app-encryption"            { capabilities = ["create", "update"] }
path "transit/hmac/app-hmac"                    { capabilities = ["create", "update"] }
path "transit/datakey/plaintext/app-encryption" { capabilities = ["create", "update"] }

# SSH
path "ssh/creds/otp-role"             { capabilities = ["create", "update"] }
path "ssh-client-signer/sign/my-role" { capabilities = ["create", "update"] }

# Lease management
path "sys/leases/renew"  { capabilities = ["create", "update"] }
path "sys/leases/revoke" { capabilities = ["create", "update"] }
```

## Transit Key Names (Constants in TransitSecretService)

```java
public static final String ENCRYPTION_KEY = "app-encryption";   // AES-256-GCM
public static final String SIGNING_KEY     = "app-signing";      // ECDSA P-256
public static final String RSA_KEY         = "app-rsa";          // RSA-4096
public static final String HMAC_KEY        = "app-hmac";         // HMAC-SHA256
```

## Database Roles

| Role | Permissions | default_ttl | max_ttl |
|------|-------------|-------------|---------|
| `readonly` | SELECT on all tables + sequences | 1h | 24h |
| `readwrite` | SELECT, INSERT, UPDATE, DELETE + sequences | 1h | 24h |

## PKI Role (`example-dot-com`)

| Setting | Value |
|---------|-------|
| `allowed_domains` | `example.com`, `internal.example.com`, `test.example.com` |
| `allow_subdomains` | `true` |
| `allow_bare_domains` | `true` |
| `max_ttl` | 720h (30 days) |
| `key_type` | RSA |
| `key_bits` | 2048 |

## SSH Roles

**OTP role (`otp-role`)**:

| Setting | Value |
|---------|-------|
| `key_type` | `otp` |
| `default_user` | `ubuntu` |
| `allowed_users` | `ubuntu`, `ec2-user`, `centos`, `admin` |
| `cidr_list` | `0.0.0.0/0` |

**Client certificate role (`my-role`)**:

| Setting | Value |
|---------|-------|
| `key_type` | `ca` |
| `allow_user_certificates` | `true` |
| `allowed_users` | `ubuntu`, `ec2-user`, `*` |
| `ttl` | 30m |
| `max_ttl` | 8h |
| `algorithm_signer` | `rsa-sha2-256` |
| Default extensions | `permit-pty` |

## AppRole (`myapp`)

| Setting | Value |
|---------|-------|
| `token_ttl` | 1h |
| `token_max_ttl` | 4h |
| `token_policies` | `myapp-policy` |
| `bind_secret_id` | `true` |
| `secret_id_ttl` | 24h |
| `secret_id_num_uses` | 100 |

## Dependencies (pom.xml)

| Library | Version | Purpose |
|---------|---------|---------|
| `spring-vault-core` | 2.3.4 | Vault API client + lease management |
| `hikaricp` | 5.1.0 | JDBC connection pooling |
| `postgresql` | 42.7.2 | PostgreSQL JDBC driver |
| `bcpkix-jdk18on` | 1.77 | PEM parsing / X.509 cert inspection |
| `bcprov-jdk18on` | 1.77 | BouncyCastle crypto provider |
| `okhttp` | 4.12.0 | HTTP client (used by Spring Vault) |
| `jackson-databind` | 2.16.1 | JSON serialization |
| `simpleclient` | 0.16.0 | Prometheus Java client — counters / histograms / gauges |
| `simpleclient_httpserver` | 0.16.0 | Embedded HTTP server exposing `/metrics` |
| `simpleclient_hotspot` | 0.16.0 | JVM metrics (heap, GC, threads, classloading) |
| `slf4j-api` | 2.0.12 | Logging API |
| `logback-classic` | 1.4.14 | Logging implementation |
| `commons-lang3` | 3.14.0 | Utilities |
| `testcontainers` | 1.19.6 | Real containers in tests |
| `junit-jupiter` | 5.10.2 | Test framework |
| `mockito-core` | 5.10.0 | Mocking in unit tests |
