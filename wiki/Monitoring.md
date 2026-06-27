# Monitoring — Prometheus & Grafana

The demo ships a full observability stack. No extra configuration is needed beyond `docker compose up -d`.

## Stack Overview

```
Java App  (:8080/metrics)
    │  Prometheus scrapes every 15s
    ▼
Prometheus (:9090)
    │  Grafana queries via datasource
    ▼
Grafana (:3000)
    │  pre-provisioned "Vault Demo" dashboard
    ▼
vault-demo.json
```

## Service URLs

| Service    | URL                      | Credentials   |
|------------|--------------------------|---------------|
| Metrics    | http://localhost:8080/metrics | —        |
| Prometheus | http://localhost:9090    | —             |
| Grafana    | http://localhost:3000    | admin / admin |

Grafana auto-provisions the Prometheus datasource and the **Vault Demo** dashboard on first start — no manual setup required.

## MetricsService

**Class**: `com.example.vault.metrics.MetricsService`

A thread-safe singleton that:
- Registers all Prometheus metrics at class-load time
- Starts an embedded HTTP server exposing `/metrics`
- Registers JVM metrics automatically (heap, GC, threads, classloading)
- Installs a shutdown hook to stop the server cleanly

`VaultDemoApplication.main()` starts it before any Vault operations:

```java
MetricsService metrics = MetricsService.getInstance();
metrics.startServer();
// ... run demos ...
// Server stays alive after demos; press Ctrl+C to exit
```

The HTTP server thread is **non-daemon**, keeping the JVM alive after `main()` returns so Prometheus can scrape the final metric values.

## Exposed Metrics

### `vault_operations_total` — Counter

Total Vault API calls, broken down by engine, operation, and outcome.

Labels:
- `engine` — `transit`, `db`, `pki`, `ssh`
- `operation` — e.g. `encrypt`, `decrypt`, `issue_certificate`, `get_credentials`
- `status` — `success` or `error`

Example queries:
```promql
# Error rate by engine
rate(vault_operations_total{status="error"}[5m])

# Success rate for Transit
rate(vault_operations_total{engine="transit",status="success"}[1m])
```

### `vault_operation_duration_seconds` — Histogram

Latency of each Vault operation. Buckets: 1ms, 5ms, 10ms, 25ms, 50ms, 100ms, 250ms, 500ms, 1s, 2.5s, 5s.

Labels: `engine`, `operation`

Example queries:
```promql
# p95 latency for PKI cert issuance
histogram_quantile(0.95,
  rate(vault_operation_duration_seconds_bucket{engine="pki"}[5m]))

# p50 latency for all engines
histogram_quantile(0.50,
  rate(vault_operation_duration_seconds_bucket[5m]))
```

### `vault_transit_key_rotations_total` — Counter

Number of Transit key rotation operations.

Labels: `key` — e.g. `app-encryption`

### `vault_db_credential_ttl_seconds` — Gauge

Lease duration (in seconds) of the most recently issued dynamic DB credential.

Labels: `role` — `readonly` or `readwrite`

### `vault_pki_cert_ttl_seconds` — Gauge

Lease duration (in seconds) of the most recently issued PKI certificate.

Labels: `role` — e.g. `example-dot-com`

### `vault_ssh_cert_ttl_seconds` — Gauge

TTL (in seconds) of the most recently signed SSH certificate.

Labels: `principals` — comma-separated principals, e.g. `ubuntu,ec2-user`

### JVM Metrics (auto-registered)

`DefaultExports.initialize()` registers:

| Metric prefix | Description |
|--------------|-------------|
| `jvm_memory_bytes_*` | Heap and non-heap memory |
| `jvm_gc_collection_seconds_*` | GC pause times |
| `jvm_threads_*` | Thread counts by state |
| `jvm_classes_*` | Loaded/unloaded class counts |
| `process_cpu_seconds_total` | CPU time |

## Instrumenting Operations

Each service uses the static helpers on `MetricsService`:

```java
// Start a timer
Histogram.Timer timer = MetricsService.startTimer("transit", "encrypt");
try {
    String result = doVaultCall();
    MetricsService.recordSuccess("transit", "encrypt");
    return result;
} catch (Exception e) {
    MetricsService.recordError("transit", "encrypt");
    throw e;
} finally {
    timer.observeDuration();   // always records latency
}
```

## Prometheus Configuration

`monitoring/prometheus/prometheus.yml` — scrapes the Java app on the host machine:

```yaml
scrape_configs:
  - job_name: vault-java-demo
    scrape_interval: 15s
    static_configs:
      - targets: ['host.docker.internal:8080']
```

`host.docker.internal` resolves to the Docker host's loopback via `extra_hosts` in `docker-compose.yml`, allowing Prometheus (inside Docker) to reach the Java app running on the host.

## Grafana Dashboard

The pre-built **Vault Demo** dashboard (`monitoring/grafana/dashboards/vault-demo.json`) includes panels for:

- Operations per second by engine and status
- Latency heatmap and p50/p95/p99 percentiles
- Transit key rotation rate
- Active credential and certificate TTLs (DB, PKI, SSH)
- JVM heap usage and GC pause time
- Error rate alerting thresholds

Grafana is provisioned automatically via:
- `monitoring/grafana/provisioning/datasources/prometheus.yml` — Prometheus datasource
- `monitoring/grafana/provisioning/dashboards/dashboard.yml` — dashboard loader

## Changing the Metrics Port

```bash
export METRICS_PORT=9091
mvn exec:java -Dexec.mainClass=com.example.vault.VaultDemoApplication
```

Update `monitoring/prometheus/prometheus.yml` to match if you change the port.

## Troubleshooting

**`/metrics` returns nothing** — The MetricsService server failed to start (port in use). Check the log for `Could not start metrics server on port`. Change `METRICS_PORT`.

**Prometheus shows `DOWN` for `vault-java-demo` target** — The Java app is not running, or `METRICS_PORT` doesn't match the scrape target in `prometheus.yml`.

**Grafana dashboard shows "No data"** — Prometheus hasn't scraped yet (up to 15s delay), or the app hasn't run any Vault operations yet. Run a demo first.
