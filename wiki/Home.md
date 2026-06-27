# HashiCorp Vault Java Demo — Wiki

A production-grade Java demonstration of all four major HashiCorp Vault secret engines.

## Pages

| Page | Description |
|------|-------------|
| [Architecture](Architecture.md) | Component diagram, data flows, design decisions |
| [Getting Started](Getting-Started.md) | Prerequisites, infrastructure setup, running the demo |
| [Secret Engine: Database](Secret-Engine-Database.md) | Dynamic PostgreSQL credentials, lease management, HikariCP integration |
| [Secret Engine: PKI](Secret-Engine-PKI.md) | X.509 certificate issuance, CA hierarchy, CSR signing, revocation |
| [Secret Engine: Transit](Secret-Engine-Transit.md) | Encryption-as-a-Service, signing, HMAC, key rotation, envelope encryption |
| [Secret Engine: SSH](Secret-Engine-SSH.md) | OTP authentication, signed SSH certificates, host certificates |
| [Authentication](Authentication.md) | Token auth (dev), AppRole auth (production), policy configuration |
| [Monitoring](Monitoring.md) | Prometheus metrics, Grafana dashboard, MetricsService instrumentation |
| [Configuration Reference](Configuration.md) | All environment variables, defaults, and Vault paths |
| [Java API Reference](API-Reference.md) | Method signatures and usage for all service classes |
| [Testing](Testing.md) | Integration tests with Testcontainers, test structure |

## Quick Links

- **Start infrastructure**: `docker compose up -d`
- **Configure Vault**: `bash scripts/setup-all.sh`
- **Run all engines**: `mvn exec:java -Dexec.mainClass=com.example.vault.VaultDemoApplication`
- **Run one engine**: `mvn exec:java -Dexec.mainClass=com.example.vault.VaultDemoApplication -Dexec.args=transit`
- **View metrics**: http://localhost:8080/metrics · Prometheus: http://localhost:9090 · Grafana: http://localhost:3000

## Secret Engines at a Glance

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
