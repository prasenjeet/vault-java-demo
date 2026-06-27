package com.example.vault.metrics;

import io.prometheus.client.CollectorRegistry;
import io.prometheus.client.Counter;
import io.prometheus.client.Gauge;
import io.prometheus.client.Histogram;
import io.prometheus.client.exporter.HTTPServer;
import io.prometheus.client.hotspot.DefaultExports;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.net.InetSocketAddress;

/**
 * Central Prometheus metrics registry and embedded HTTP server.
 *
 * Exposes /metrics on METRICS_PORT (default 8080) for Prometheus to scrape.
 * Instruments all four Vault secret engine operations.
 */
public class MetricsService {

    private static final Logger log = LoggerFactory.getLogger(MetricsService.class);
    private static volatile MetricsService instance;

    private HTTPServer httpServer;
    private final int port;

    // ── Operations counter ────────────────────────────────────────────────────
    public static final Counter VAULT_OPERATIONS = Counter.build()
            .name("vault_operations_total")
            .help("Total Vault operations by secret engine, operation type, and outcome")
            .labelNames("engine", "operation", "status")
            .register();

    // ── Latency histogram ──────────────────────────────────────────────────────
    public static final Histogram VAULT_OPERATION_DURATION = Histogram.build()
            .name("vault_operation_duration_seconds")
            .help("Vault operation latency in seconds")
            .labelNames("engine", "operation")
            .buckets(0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0)
            .register();

    // ── Transit: key rotations ────────────────────────────────────────────────
    public static final Counter TRANSIT_KEY_ROTATIONS = Counter.build()
            .name("vault_transit_key_rotations_total")
            .help("Number of Transit key rotation operations")
            .labelNames("key")
            .register();

    // ── Database: issued credential TTL ───────────────────────────────────────
    public static final Gauge DB_CREDENTIAL_TTL = Gauge.build()
            .name("vault_db_credential_ttl_seconds")
            .help("Lease duration (seconds) of the most recently issued dynamic DB credential")
            .labelNames("role")
            .register();

    // ── PKI: issued certificate TTL ───────────────────────────────────────────
    public static final Gauge PKI_CERT_TTL = Gauge.build()
            .name("vault_pki_cert_ttl_seconds")
            .help("Lease duration (seconds) of the most recently issued PKI certificate")
            .labelNames("role")
            .register();

    // ── SSH: signed certificate TTL ───────────────────────────────────────────
    public static final Gauge SSH_CERT_TTL = Gauge.build()
            .name("vault_ssh_cert_ttl_seconds")
            .help("TTL (seconds) of the most recently signed SSH certificate")
            .labelNames("principals")
            .register();

    private MetricsService(int port) {
        this.port = port;
        DefaultExports.initialize();  // registers JVM heap, GC, threads, classloading
    }

    public static MetricsService getInstance() {
        if (instance == null) {
            synchronized (MetricsService.class) {
                if (instance == null) {
                    int port = Integer.parseInt(
                            System.getenv().getOrDefault("METRICS_PORT", "8080"));
                    instance = new MetricsService(port);
                }
            }
        }
        return instance;
    }

    /**
     * Starts the HTTP server and registers a shutdown hook.
     * The server thread is non-daemon so the JVM stays alive after demos complete,
     * giving Prometheus time to scrape. Press Ctrl+C to exit.
     */
    public void startServer() {
        try {
            httpServer = new HTTPServer(
                    new InetSocketAddress("0.0.0.0", port),
                    CollectorRegistry.defaultRegistry,
                    false);  // non-daemon: keeps JVM alive after main() returns

            Runtime.getRuntime().addShutdownHook(new Thread(() -> {
                log.info("Stopping metrics HTTP server...");
                httpServer.stop();
            }, "metrics-shutdown"));

            log.info("Prometheus metrics server listening on :{}/metrics", port);
        } catch (IOException e) {
            log.warn("Could not start metrics server on port {}: {}", port, e.getMessage());
        }
    }

    public int getPort() {
        return port;
    }

    // ── Instrumentation helpers ───────────────────────────────────────────────

    public static Histogram.Timer startTimer(String engine, String operation) {
        return VAULT_OPERATION_DURATION.labels(engine, operation).startTimer();
    }

    public static void recordSuccess(String engine, String operation) {
        VAULT_OPERATIONS.labels(engine, operation, "success").inc();
    }

    public static void recordError(String engine, String operation) {
        VAULT_OPERATIONS.labels(engine, operation, "error").inc();
    }
}
