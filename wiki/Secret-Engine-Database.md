# Secret Engine: Dynamic Database Secrets

**Class**: `com.example.vault.db.DynamicDatabaseSecretService`

## What It Does

Vault generates short-lived PostgreSQL credentials on demand. No static passwords are stored anywhere in the application. Each credential set has a TTL; when it expires, Vault automatically drops the database role.

## How It Works

```
App → vault read database/creds/readonly
    ← { username: "v-token-readonly-abc123",
        password: "A1b2-C3d4-E5f6-G7h8",
        lease_id: "database/creds/readonly/abcdef...",
        lease_duration: 3600 }
App → PostgreSQL (connect with dynamic creds)
TTL expires → Vault executes: DROP ROLE "v-token-readonly-abc123"
```

## Vault Configuration

The setup script (`scripts/setup-all.sh`) configures these resources:

**Database connection (one-time):**
```bash
vault secrets enable database

vault write database/config/mypostgres \
    plugin_name=postgresql-database-plugin \
    allowed_roles="readonly,readwrite,admin" \
    connection_url="postgresql://{{username}}:{{password}}@postgres:5432/mydb?sslmode=disable" \
    username="postgres" \
    password="postgres"
```

**`readonly` role:**
- Grants `SELECT` on all tables and sequences
- `default_ttl=1h`, `max_ttl=24h`
- Creation SQL: `CREATE ROLE "{{name}}" WITH LOGIN PASSWORD '{{password}}' VALID UNTIL '{{expiration}}'; GRANT SELECT ON ALL TABLES...`
- Revocation SQL: `REVOKE ALL PRIVILEGES...; DROP ROLE IF EXISTS "{{name}}"`

**`readwrite` role:**
- Grants `SELECT, INSERT, UPDATE, DELETE` on all tables
- `default_ttl=1h`, `max_ttl=24h`

## Java API

### Fetch credentials once
```java
DynamicDatabaseSecretService service = new DynamicDatabaseSecretService(
    vaultTemplate, "localhost", "5432", "mydb");

DatabaseCredential cred = service.getDynamicCredentials("readonly");
// cred.username()            → "v-token-readonly-abc123"
// cred.password()            → "A1b2-C3d4-..."
// cred.leaseId()             → "database/creds/readonly/..."
// cred.leaseDurationSeconds() → 3600
// cred.role()                → "readonly"
```

### Build a HikariCP connection pool
```java
HikariDataSource ds = service.buildDataSource(cred);

try (Connection conn = ds.getConnection()) {
    // Use the connection normally
}
```

Pool configuration applied automatically:
- `maximumPoolSize=5`, `minimumIdle=1`
- `maxLifetime` set to `(leaseDuration - 60) seconds` to prevent stale connections
- `connectionTestQuery=SELECT 1`

### Auto-renewal with SecretLeaseContainer
```java
AtomicReference<HikariDataSource> dsHolder = new AtomicReference<>();

service.setupAutoRenewal("readonly", dsHolder);
// SecretLeaseContainer starts in background.
// When the lease is renewed, a new DataSource is created and swapped
// atomically into dsHolder; the old pool is closed.

// Use the current DataSource:
try (Connection conn = dsHolder.get().getConnection()) { ... }
```

Uses `RequestedSecret.rotating()` — Spring Vault tracks the lease and renews it before expiry. On renewal, the listener creates a new `DatabaseCredential` and a new HikariCP pool, then atomically replaces the old one.

### Revoke a lease explicitly
```java
service.revokeLease(cred);
// Calls POST /v1/sys/leases/revoke
// Vault drops the DB user immediately (doesn't wait for TTL)
```

Call this on application shutdown for clean resource release.

## DatabaseCredential Record

```java
public record DatabaseCredential(
    String username,
    String password,
    String leaseId,
    long   leaseDurationSeconds,
    String role
) {
    // Check if near expiry for custom renewal logic
    public boolean isNearExpiry(long thresholdSeconds, long issuedAtEpochSeconds)
}
```

`toString()` truncates the lease ID and never includes the password.

## Vault Paths

| Operation | HTTP | Vault Path |
|-----------|------|------------|
| Fetch credentials | `GET` | `database/creds/{role}` |
| Revoke lease | `POST` | `sys/leases/revoke` |
| Renew lease | `POST` | `sys/leases/renew` |

## Policy Requirements

```hcl
path "database/creds/readonly"  { capabilities = ["read"] }
path "database/creds/readwrite" { capabilities = ["read"] }
path "sys/leases/renew"         { capabilities = ["create", "update"] }
path "sys/leases/revoke"        { capabilities = ["create", "update"] }
```

## Username Format

Vault-generated usernames follow the pattern: `v-{auth_method}-{role}-{random}`.

For token auth (dev): `v-token-readonly-abc123xyz`
For AppRole auth: `v-approle-readonly-abc123xyz`

The database user is dropped when Vault executes the revocation statement — either on lease expiry or explicit `revokeLease()`.
