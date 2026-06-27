# Architecture

## Component Overview

```
┌─────────────────────────────────────────────────────────────────────┐
│                      vault-java-demo                                │
│                                                                     │
│  VaultDemoApplication                                               │
│        │                                                            │
│        ├─── MetricsService (singleton)                              │
│        │       └── Prometheus HTTP server (:8080/metrics)           │
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

┌──────────────────────┐     ┌──────────────────────┐
│  Prometheus          │     │  Grafana              │
│  Port: 9090          │────►│  Port: 3000           │
│  Scrapes :8080/metrics│    │  admin / admin        │
└──────────────────────┘     │  Vault Demo dashboard │
                             └──────────────────────┘
```

## Package Structure

```
com.example.vault/
├── VaultDemoApplication.java      Main entry point; CLI arg routing; starts MetricsService
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
├── metrics/
│   └── MetricsService.java        Singleton; Prometheus registry + embedded HTTP server
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

### MetricsService singleton
`MetricsService` mirrors the `VaultConfig` singleton pattern. All Prometheus metrics are static fields registered at class-load time. The embedded HTTP server is started once in `main()` via `startServer()`, and the non-daemon server thread keeps the JVM alive after all demos complete so Prometheus can scrape the final state.

Each service (Transit, PKI, SSH, DB) calls the static helpers `MetricsService.startTimer()`, `recordSuccess()`, and `recordError()` around every Vault operation.

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
