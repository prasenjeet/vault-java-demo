# Getting Started

## Prerequisites

| Tool | Version | Purpose |
|------|---------|---------|
| Java | 17+ | Runtime (JDK required) |
| Maven | 3.8+ | Build and dependency management |
| Docker | 20+ | Vault + PostgreSQL containers |
| `vault` CLI | 1.15+ | Setup scripts |
| `jq` | any | Used in `setup-all.sh` for JSON parsing |

Set `JAVA_HOME` if needed:
```bash
export JAVA_HOME=/Library/Java/JavaVirtualMachines/jdk-17.jdk/Contents/Home
```

## Step 1 — Start Infrastructure

```bash
# Start all services: Vault, PostgreSQL, Prometheus, Grafana
docker compose up -d

# Optional: also start PgAdmin (DB browser UI on port 5050)
docker compose --profile tools up -d

# Confirm containers are running
docker ps

# Verify Vault health
curl http://localhost:8201/v1/sys/health
# Expected: {"initialized":true,"sealed":false,...}
```

The `docker-compose.yml` starts:

| Service    | Port | Details |
|------------|------|---------|
| Vault      | 8201 | Dev mode, root token `root` |
| PostgreSQL | 5432 | DB `mydb`, user `postgres` / `postgres` |
| Prometheus | 9090 | Scrapes Java app on `host.docker.internal:8080` |
| Grafana    | 3000 | admin / admin — Vault Demo dashboard pre-provisioned |
| PgAdmin    | 5050 | admin@admin.com / admin — only with `--profile tools` |

## Step 2 — Configure Vault Secret Engines

```bash
export VAULT_ADDR=http://127.0.0.1:8201
export VAULT_TOKEN=root

bash scripts/setup-all.sh
```

The setup script configures, in order:
1. **Database engine** — PostgreSQL connection + `readonly` and `readwrite` roles
2. **PKI engine** — Root CA → Intermediate CA → certificate issuance role
3. **Transit engine** — AES-256, ECDSA, RSA-4096, and HMAC keys
4. **SSH engine** — OTP role, client-signer CA, host-signer CA
5. **Vault policy** — `myapp-policy` covering all paths
6. **AppRole auth** — `myapp` role bound to the policy

On success, the script prints:
```
VAULT_ROLE_ID=<role-id>
VAULT_SECRET_ID=<secret-id>
```
Save these for AppRole authentication.

## Step 3 — Run the Demo

```bash
# All four engines
mvn exec:java -Dexec.mainClass=com.example.vault.VaultDemoApplication

# Specific engine
mvn exec:java -Dexec.mainClass=com.example.vault.VaultDemoApplication -Dexec.args=transit
mvn exec:java -Dexec.mainClass=com.example.vault.VaultDemoApplication -Dexec.args=db
mvn exec:java -Dexec.mainClass=com.example.vault.VaultDemoApplication -Dexec.args=pki
mvn exec:java -Dexec.mainClass=com.example.vault.VaultDemoApplication -Dexec.args=ssh
```

Environment variables (defaults work against `docker compose up`):

```bash
export VAULT_ADDR=http://127.0.0.1:8201
export VAULT_TOKEN=root
export DB_HOST=localhost
export DB_PORT=5432
export DB_NAME=mydb
```

## Step 4 — View Metrics

Once the Java app is running, open:

- **Raw metrics**: http://localhost:8080/metrics
- **Prometheus UI**: http://localhost:9090 — query `vault_operations_total` or `vault_operation_duration_seconds`
- **Grafana dashboard**: http://localhost:3000 — open the pre-built **Vault Demo** dashboard (admin / admin)

The app keeps the metrics server alive after all demos finish. Press **Ctrl+C** to exit.

See [Monitoring](Monitoring.md) for the full metrics reference and PromQL examples.

## Step 5 — Run Integration Tests

```bash
# Testcontainers spins up real Vault and PostgreSQL automatically
mvn test
```

Tests are in `src/test/java/com/example/vault/VaultIntegrationTest.java`. Docker must be running.

## Build Fat JAR

```bash
mvn package -DskipTests
java -jar target/vault-java-demo-1.0.0.jar [db|pki|transit|ssh|all]
```

## Verifying Individual Engines via CLI

After running `setup-all.sh`, you can test each engine independently:

```bash
# Database — fetch dynamic credentials
vault read database/creds/readonly

# PKI — issue a certificate
vault write pki_int/issue/example-dot-com common_name=api.internal.example.com ttl=1h

# Transit — encrypt/decrypt
vault write transit/encrypt/app-encryption plaintext=$(echo -n "hello" | base64)
vault write transit/decrypt/app-encryption ciphertext=<ciphertext from above>

# SSH — generate OTP
vault write ssh/creds/otp-role ip=10.0.0.1 username=ubuntu

# SSH — sign a public key
vault write ssh-client-signer/sign/my-role public_key=@~/.ssh/id_rsa.pub
```

## Troubleshooting

**`Vault is sealed`** — The Vault container was restarted. Dev mode unseals automatically on start, but a fresh container is needed if you stopped it: `docker compose restart vault`

**`No credentials returned from Vault`** — Setup script did not run or failed partway through. Re-run `bash scripts/setup-all.sh`.

**`PostgreSQL connection refused`** — PostgreSQL container is not ready yet. Wait ~5s after `docker compose up -d` and retry.

**`VAULT_ROLE_ID and VAULT_SECRET_ID must be set`** — You instantiated `AppRoleVaultConfig` without setting those env vars. Use `VaultConfig` (token auth) for local dev.

**`Could not start metrics server on port 8080`** — Port 8080 is already in use. Set `METRICS_PORT=9091` (or any free port) before running the app, and update `monitoring/prometheus/prometheus.yml` to match.

**Grafana shows "No data"** — Prometheus hasn't scraped yet (15s delay) or the Java app isn't running. Confirm `http://localhost:8080/metrics` is reachable from the host.
