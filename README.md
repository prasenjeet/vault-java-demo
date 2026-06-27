# HashiCorp Vault — Java Integration Demo

Demonstrates all four major Vault secret engines with production-grade Java code.

```
┌──────────────────────────────────────────────────────────────────┐
│            Secret Engine Coverage                                │
│                                                                  │
│  ① Dynamic DB Secrets  — Auto-rotating PostgreSQL credentials   │
│  ② PKI                 — On-demand X.509 TLS certificates       │
│  ③ Transit             — Encryption / Signing / HMAC / Key Mgmt │
│  ④ SSH                 — OTP login + Signed certificate access   │
└──────────────────────────────────────────────────────────────────┘
```

---

## Project Structure

```
vault-java-demo/
├── pom.xml
├── docker-compose.yml
├── scripts/
│   ├── setup-all.sh          ← Configure all Vault engines (run once)
│   └── init-db.sql           ← PostgreSQL schema + Vault user
├── monitoring/
│   ├── prometheus/
│   │   └── prometheus.yml    ← Scrape config (targets Java app on host)
│   └── grafana/
│       ├── dashboards/
│       │   └── vault-demo.json           ← Pre-built Vault dashboard
│       └── provisioning/
│           ├── dashboards/dashboard.yml
│           └── datasources/prometheus.yml
└── src/
    ├── main/java/com/example/vault/
    │   ├── VaultDemoApplication.java     ← Main entry point
    │   ├── config/
    │   │   ├── VaultConfig.java          ← Token auth + VaultTemplate factory
    │   │   └── AppRoleVaultConfig.java   ← AppRole auth (production)
    │   ├── db/
    │   │   └── DynamicDatabaseSecretService.java
    │   ├── pki/
    │   │   └── PkiSecretService.java
    │   ├── transit/
    │   │   └── TransitSecretService.java
    │   ├── ssh/
    │   │   └── SshSecretService.java
    │   ├── metrics/
    │   │   └── MetricsService.java       ← Prometheus metrics + embedded HTTP server
    │   └── model/
    │       ├── DatabaseCredential.java
    │       └── IssuedCertificate.java
    └── test/java/com/example/vault/
        └── VaultIntegrationTest.java     ← Testcontainers integration tests
```

---

## Quick Start

### 1. Start Infrastructure

```bash
# Start Vault + PostgreSQL + Prometheus + Grafana
docker compose up -d

# Optional: also start PgAdmin (DB browser UI)
docker compose --profile tools up -d

# Verify
docker ps
curl http://localhost:8201/v1/sys/health
```

**Service URLs:**

| Service    | URL                         | Credentials       |
|------------|-----------------------------|-------------------|
| Vault UI   | http://localhost:8201/ui    | token: `root`     |
| Prometheus | http://localhost:9090       | —                 |
| Grafana    | http://localhost:3000       | admin / admin     |
| PgAdmin    | http://localhost:5050       | admin@admin.com / admin *(--profile tools)* |

### 2. Configure Vault Secret Engines

```bash
export VAULT_ADDR=http://127.0.0.1:8201
export VAULT_TOKEN=root

bash scripts/setup-all.sh
```

### 3. Run the Demo

export JAVA_HOME=/Library/Java/JavaVirtualMachines/jdk-17.jdk/Contents/Home



```bash
# All engines
mvn exec:java -Dexec.mainClass=com.example.vault.VaultDemoApplication

# Specific engine
mvn exec:java -Dexec.mainClass=com.example.vault.VaultDemoApplication -Dexec.args=transit
mvn exec:java -Dexec.mainClass=com.example.vault.VaultDemoApplication -Dexec.args=db
mvn exec:java -Dexec.mainClass=com.example.vault.VaultDemoApplication -Dexec.args=pki
mvn exec:java -Dexec.mainClass=com.example.vault.VaultDemoApplication -Dexec.args=ssh
```

### 4. Run Integration Tests

```bash
# Requires Docker (Testcontainers spins up real Vault)
mvn test
```

### 5. View Metrics

Once the app is running, Prometheus scrapes metrics from the embedded HTTP server:

```
http://localhost:8080/metrics
```

Open Grafana at http://localhost:3000 — the **Vault Demo** dashboard is pre-provisioned and shows:
- Operations per second by engine and outcome
- Latency histograms (p50 / p95 / p99)
- Transit key rotations
- Active credential / certificate TTLs
- JVM heap, GC, and thread metrics

---

## Secret Engine Details

---

### ① Dynamic Database Secrets

**How it works:**

```
App → vault read database/creds/readonly
    ← { username: "v-token-readonly-xyz", password: "A1b2-C3d4-...", lease_id: "...", ttl: 3600 }
App → PostgreSQL (connect with dynamic creds)
TTL expires → Vault executes DROP ROLE "v-token-readonly-xyz"
```

**Vault roles configured:**

| Role | Permissions | TTL |
|------|------------|-----|
| `readonly` | SELECT on all tables | 1h (max 24h) |
| `readwrite` | SELECT, INSERT, UPDATE, DELETE | 1h (max 24h) |

**Key features implemented:**
- `getDynamicCredentials(role)` — single credential fetch
- `buildDataSource(cred)` — HikariCP pool with dynamic creds
- `setupAutoRenewal(role, dsHolder)` — automatic renewal via `SecretLeaseContainer`
- `revokeLease(cred)` — explicit cleanup on shutdown

**Java usage:**

```java
DynamicDatabaseSecretService service = new DynamicDatabaseSecretService(
    vaultTemplate, "localhost", "5432", "mydb");

DatabaseCredential cred = service.getDynamicCredentials("readonly");
HikariDataSource ds = service.buildDataSource(cred);

try (Connection conn = ds.getConnection()) {
    // Use the connection normally
}

service.revokeLease(cred);  // Drop the DB user immediately
```

---

### ② PKI — Certificate Authority

**How it works:**

```
App → vault write pki_int/issue/example-dot-com \
          common_name=api.internal.example.com ttl=72h
    ← { certificate: "-----BEGIN CERTIFICATE-----...",
        private_key: "-----BEGIN RSA PRIVATE KEY-----...",
        issuing_ca:  "-----BEGIN CERTIFICATE-----..." }
```

**CA hierarchy configured:**
```
Root CA (pki/)
    └── Intermediate CA (pki_int/)
            └── Issues certs for *.example.com
```

**Key features implemented:**
- `issueCertificate(cn, ttl, altNames, ipSans)` — full cert with SANs
- `signCsr(csrPem, cn, ttl)` — sign externally-generated CSR
- `revokeCertificate(serialNumber)` — CRL-based revocation
- `saveCertificateToFiles(cert, dir)` — write PEM files to disk
- `parseCertificate(pem)` — X509Certificate object for inspection

**Java usage:**

```java
PkiSecretService pki = new PkiSecretService(vaultTemplate, "pki_int", "example-dot-com");

IssuedCertificate cert = pki.issueCertificate(
    "api.internal.example.com",
    Duration.ofHours(72),
    new String[]{"api.example.com", "localhost"},
    new String[]{"127.0.0.1", "10.0.0.5"}
);

// Use cert.certificatePem() and cert.privateKeyPem() for TLS config
pki.saveCertificateToFiles(cert, Path.of("/etc/app/tls"));
```

---

### ③ Transit — Encryption-as-a-Service

**How it works:**

```
App → vault write transit/encrypt/app-encryption plaintext=base64(data)
    ← { ciphertext: "vault:v3:8SDd3WHDOjf..." }

App → vault write transit/decrypt/app-encryption ciphertext="vault:v3:8SDd3WHDOjf..."
    ← { plaintext: base64(original_data) }
```

The private key NEVER leaves Vault. Ciphertext version (`v3`) tracks key rotation.

**Keys configured:**

| Key Name | Type | Use Case |
|----------|------|----------|
| `app-encryption` | AES-256-GCM | Symmetric encrypt/decrypt |
| `app-signing` | ECDSA P-256 | Digital signatures |
| `app-rsa` | RSA-4096 | RSA signing/encryption |
| `app-hmac` | HMAC-SHA256 | Message authentication |

**Key features implemented:**

| Method | Description |
|--------|-------------|
| `encrypt(key, plaintext)` | AES-256-GCM encryption |
| `decrypt(key, ciphertext)` | Decryption |
| `encryptWithContext(key, pt, ctx)` | Context-bound encryption |
| `batchEncrypt(key, list)` | Bulk encryption (single API call) |
| `batchDecrypt(key, list)` | Bulk decryption |
| `sign(key, data)` | ECDSA/RSA signing |
| `verify(key, data, sig)` | Signature verification |
| `hmac(key, data)` | HMAC-SHA256 |
| `rotateKey(key)` | Zero-downtime key rotation |
| `rewrap(key, ciphertext)` | Re-encrypt with latest key version |
| `generateDataKey(key, bits)` | Envelope encryption DEK |
| `hash(data, algorithm)` | SHA-256/512 |
| `generateRandomBytes(n)` | CSPRNG random bytes |

**Java usage:**

```java
TransitSecretService transit = new TransitSecretService(vaultTemplate);

// Encrypt sensitive data (PII, card numbers, etc.)
String ciphertext = transit.encrypt("app-encryption", "4111-1111-1111-1111");
String plaintext  = transit.decrypt("app-encryption", ciphertext);

// Sign a JWT payload or API request
String signature = transit.sign("app-signing", jsonPayload);
boolean valid    = transit.verify("app-signing", jsonPayload, signature);

// Rotate key — old ciphertexts still decrypt
transit.rotateKey("app-encryption");
String rewrapped = transit.rewrap("app-encryption", oldCiphertext);

// Envelope encryption for large data
Map<String, String> dek = transit.generateDataKey("app-encryption", 256);
// Use dek.get("plaintext") locally, store dek.get("ciphertext") in DB
```

---

### ④ SSH — OTP + Signed Certificates

#### Mode A: OTP (One-Time Password)

```
Developer → vault write ssh/creds/otp-role ip=10.0.1.100 username=ubuntu
          ← { key: "a86cf4b2-...", key_type: "otp" }
Developer → ssh ubuntu@10.0.1.100  (enters OTP when prompted)
Server    → vault-ssh-helper verifies OTP → grants/denies access
OTP consumed → cannot be reused
```

**Requires:** `vault-ssh-helper` installed on target SSH servers.

#### Mode B: Signed Certificates (Recommended)

```
Developer → vault write ssh-client-signer/sign/my-role \
                public_key=@~/.ssh/id_rsa.pub \
                valid_principals=ubuntu ttl=30m
          ← { signed_key: "ssh-rsa-cert-v01@openssh.com ..." }
Developer → saves to ~/.ssh/id_rsa-cert.pub
Developer → ssh ubuntu@10.0.1.100  (uses certificate, no password)
Cert TTL expires → cert unusable, request new one from Vault
```

**Requires:** Install Vault CA public key on servers:
```bash
vault read -field=public_key ssh-client-signer/config/ca >> /etc/ssh/trusted-user-ca-keys.pem
# Add to /etc/ssh/sshd_config: TrustedUserCAKeys /etc/ssh/trusted-user-ca-keys.pem
```

**Key features implemented:**
- `generateOtp(role, username, targetIp)` — OTP credential
- `verifyOtp(otp, username, ip)` — server-side OTP validation
- `signUserPublicKey(role, pubKey, principals, ttl, extensions)` — client cert
- `signHostPublicKey(role, pubKey, hostnames, ttl)` — host cert (no TOFU)
- `getCaPublicKey(mountPath)` — retrieve CA public key for server config
- `saveCertificate(cert, sshDir, keyBasename)` — write cert to ~/.ssh/

---

## Monitoring

The demo includes a full observability stack with zero extra configuration required.

### Architecture

```
Java App (MetricsService)
    │  exposes /metrics on :8080
    ▼
Prometheus (:9090)
    │  scrapes every 15s
    ▼
Grafana (:3000)
    │  pre-provisioned dashboard
    ▼
vault-demo.json dashboard
```

### Exposed Prometheus Metrics

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `vault_operations_total` | Counter | `engine`, `operation`, `status` | All Vault API calls, tagged success/error |
| `vault_operation_duration_seconds` | Histogram | `engine`, `operation` | Latency per operation (11 buckets, 1ms–5s) |
| `vault_transit_key_rotations_total` | Counter | `key` | Transit key rotation count |
| `vault_db_credential_ttl_seconds` | Gauge | `role` | TTL of most recently issued DB credential |
| `vault_pki_cert_ttl_seconds` | Gauge | `role` | TTL of most recently issued PKI certificate |
| `vault_ssh_cert_ttl_seconds` | Gauge | `principals` | TTL of most recently signed SSH certificate |
| `jvm_*` | Various | — | JVM heap, GC, threads, classloading (auto) |

### Java Usage

```java
// Time an operation and record its outcome
Histogram.Timer timer = MetricsService.startTimer("transit", "encrypt");
try {
    String ct = transit.encrypt("app-encryption", plaintext);
    MetricsService.recordSuccess("transit", "encrypt");
    return ct;
} catch (Exception e) {
    MetricsService.recordError("transit", "encrypt");
    throw e;
} finally {
    timer.observeDuration();
}
```

The `MetricsService` singleton starts an embedded HTTP server on `METRICS_PORT` (default `8080`) that Prometheus scrapes. The server thread is non-daemon so the JVM stays alive after all demos complete, giving Prometheus time to scrape before exit.

---

## Authentication Methods

### Dev/Test: Token Auth
```bash
export VAULT_ADDR=http://127.0.0.1:8201
export VAULT_TOKEN=root
```

### Production: AppRole Auth
```bash
export VAULT_ADDR=https://vault.production.example.com
export VAULT_ROLE_ID=<role-id-from-vault>
export VAULT_SECRET_ID=<secret-id-injected-at-runtime>
```

```java
// Use AppRoleVaultConfig for production
AppRoleVaultConfig appRoleConfig = new AppRoleVaultConfig();
VaultTemplate vaultTemplate = appRoleConfig.buildVaultTemplate();
```

---

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `VAULT_ADDR` | `http://127.0.0.1:8201` | Vault server URL |
| `VAULT_TOKEN` | `root` | Auth token (dev only) |
| `VAULT_ROLE_ID` | — | AppRole Role ID |
| `VAULT_SECRET_ID` | — | AppRole Secret ID |
| `VAULT_APPROLE_PATH` | `approle` | AppRole mount path |
| `DB_HOST` | `localhost` | PostgreSQL host |
| `DB_PORT` | `5432` | PostgreSQL port |
| `DB_NAME` | `mydb` | Database name |
| `METRICS_PORT` | `8080` | Prometheus `/metrics` HTTP server port |

---

## Dependencies

| Library | Version | Purpose |
|---------|---------|---------|
| `spring-vault-core` | 2.3.4 | Vault API client + lease management |
| `hikaricp` | 5.1.0 | JDBC connection pooling |
| `postgresql` | 42.7.2 | PostgreSQL JDBC driver |
| `bcpkix-jdk18on` | 1.77 | PEM parsing / X.509 cert inspection |
| `bcprov-jdk18on` | 1.77 | Bouncy Castle crypto provider |
| `okhttp` | 4.12.0 | HTTP client |
| `jackson-databind` | 2.16.1 | JSON serialization |
| `simpleclient` | 0.16.0 | Prometheus Java client — counters/histograms/gauges |
| `simpleclient_httpserver` | 0.16.0 | Embedded HTTP server for `/metrics` |
| `simpleclient_hotspot` | 0.16.0 | JVM metrics (heap, GC, threads) |
| `commons-lang3` | 3.14.0 | General utilities |
| `testcontainers-vault` | 1.19.6 | Real Vault in integration tests |
| `testcontainers-postgresql` | 1.19.6 | Real PostgreSQL in tests |
