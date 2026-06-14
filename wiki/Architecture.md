# Architecture

## Component Overview

```
┌─────────────────────────────────────────────────────────────────────┐
│                      vault-java-demo                                │
│                                                                     │
│  VaultDemoApplication                                               │
│        │                                                            │
│        ├─── VaultConfig (singleton)                                 │
│        │       └── VaultTemplate (Spring Vault)                     │
│        │                                                            │
│        ├─── DynamicDatabaseSecretService   ──► Vault database/      │
│        │       └── HikariCP DataSource     ──► PostgreSQL           │
│        │                                                            │
│        ├─── PkiSecretService               ──► Vault pki_int/       │
│        │       └── BouncyCastle (cert parsing)                      │
│        │                                                            │
│        ├─── TransitSecretService           ──► Vault transit/       │
│        │       └── VaultTransitOperations                           │
│        │                                                            │
│        └─── SshSecretService               ──► Vault ssh/           │
│                                                 ssh-client-signer/  │
│                                                 ssh-host-signer/    │
└─────────────────────────────────────────────────────────────────────┘
```

## Runtime Infrastructure (docker-compose.yml)

```
┌──────────────────────┐     ┌──────────────────────┐
│  HashiCorp Vault     │     │  PostgreSQL           │
│  Port: 8201          │     │  Port: 5432           │
│  Dev mode (unsealed) │     │  DB: mydb             │
│  Root token: root    │     │  User: postgres       │
└──────────────────────┘     └──────────────────────┘
```

## Package Structure

```
com.example.vault/
├── VaultDemoApplication.java      Main entry point; CLI arg routing
├── config/
│   ├── VaultConfig.java           Singleton; token auth; VaultTemplate factory
│   └── AppRoleVaultConfig.java    Production AppRole authentication
├── db/
│   └── DynamicDatabaseSecretService.java
├── pki/
│   └── PkiSecretService.java
├── transit/
│   └── TransitSecretService.java
├── ssh/
│   └── SshSecretService.java
└── model/
    ├── DatabaseCredential.java    Record: username, password, leaseId, ttl, role
    └── IssuedCertificate.java     Record: certPem, keyPem, caPem, leaseId, ttl
```

## Key Design Decisions

### VaultTemplate as the central client
All secret engines use `VaultTemplate` from Spring Vault (`spring-vault-core`). This is used standalone — no Spring Boot required. Configured once in `VaultConfig` and shared across services.

### Singleton VaultConfig
`VaultConfig` is a thread-safe singleton (`getInstance()`). `getVaultTemplate()` is lazily initialized and synchronized. This avoids creating multiple HTTP connection pools for the same Vault connection.

### Records for domain types
`DatabaseCredential` and `IssuedCertificate` are Java 17 records. They are immutable value objects — credentials from Vault are never mutated after creation.

### Demo mode / graceful degradation
`VaultDemoApplication.main()` catches connectivity failures and continues in "DEMO mode". Each engine's `runDemo()` method catches its own exceptions and prints informative setup hints, so the jar can be explored without a running Vault instance.

### SecretLeaseContainer for auto-renewal
`DynamicDatabaseSecretService.setupAutoRenewal()` uses Spring Vault's `SecretLeaseContainer` with `RequestedSecret.rotating()`. When the lease is renewed, a new `HikariCP` pool is created atomically via `AtomicReference<HikariDataSource>`, and the old pool is closed. This achieves zero-downtime credential rotation.

### Private keys never leave Vault (Transit)
All Transit operations send plaintext to Vault and receive ciphertext back. The private signing keys (ECDSA P-256, RSA-4096) are stored in Vault and are never returned to the application.

## Data Flow Examples

### Dynamic DB Credential Lifecycle
```
App boots
  └► VaultConfig.getVaultTemplate()
  └► DynamicDatabaseSecretService.getDynamicCredentials("readonly")
       └► GET /v1/database/creds/readonly
       ◄── { username, password, lease_id, lease_duration: 3600s }
  └► buildDataSource(cred)              → HikariCP pool
  └► executeQuery()                     → PostgreSQL
  └► revokeLease(cred) [on shutdown]
       └► POST /v1/sys/leases/revoke
       └── PostgreSQL: DROP ROLE "v-token-readonly-xyz"
```

### Transit Encrypt/Decrypt
```
encrypt("app-encryption", "sensitive data")
  └► POST /v1/transit/encrypt/app-encryption
       body: { plaintext: base64("sensitive data") }
  ◄── { ciphertext: "vault:v3:AAAA..." }

decrypt("app-encryption", "vault:v3:AAAA...")
  └► POST /v1/transit/decrypt/app-encryption
       body: { ciphertext: "vault:v3:AAAA..." }
  ◄── { plaintext: base64("sensitive data") }
```

### PKI Certificate Issuance
```
issueCertificate("api.internal.example.com", 72h, SANs, IPs)
  └► POST /v1/pki_int/issue/example-dot-com
       body: { common_name, ttl, alt_names, ip_sans }
  ◄── { certificate: PEM, private_key: PEM, issuing_ca: PEM }
```
