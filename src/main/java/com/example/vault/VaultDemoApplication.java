package com.example.vault;

import com.example.vault.config.VaultConfig;
import com.example.vault.db.DynamicDatabaseSecretService;
import com.example.vault.metrics.MetricsService;
import com.example.vault.pki.PkiSecretService;
import com.example.vault.ssh.SshSecretService;
import com.example.vault.transit.TransitSecretService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.vault.core.VaultTemplate;

/**
 * HashiCorp Vault Java Demo — Main Entry Point
 * ─────────────────────────────────────────────
 *
 * Demonstrates all 4 secret engine integrations:
 *   1. Dynamic DB Secrets  — Auto-rotating PostgreSQL credentials
 *   2. PKI                 — On-demand TLS certificate issuance
 *   3. Transit             — Encryption-as-a-Service
 *   4. SSH                 — OTP + Signed certificate access
 *
 * Prerequisites:
 *   1. Start Vault dev server:
 *        docker run --cap-add=IPC_LOCK \
 *            -e 'VAULT_DEV_ROOT_TOKEN_ID=root' \
 *            -e 'VAULT_DEV_LISTEN_ADDRESS=0.0.0.0:8200' \
 *            -p 8200:8200 hashicorp/vault:latest server -dev
 *
 *   2. Run setup scripts:
 *        bash scripts/setup-all.sh
 *
 *   3. Run this application:
 *        VAULT_ADDR=http://127.0.0.1:8200 VAULT_TOKEN=root mvn exec:java
 */
public class VaultDemoApplication {

    private static final Logger log = LoggerFactory.getLogger(VaultDemoApplication.class);

    public static void main(String[] args) {
        System.out.println("""
            ╔══════════════════════════════════════════════════════╗
            ║       HashiCorp Vault Java Integration Demo          ║
            ║                                                      ║
            ║  Engines: DB | PKI | Transit | SSH                   ║
            ║  Metrics: Prometheus + Grafana                       ║
            ╚══════════════════════════════════════════════════════╝
            """);

        // ── Start Prometheus metrics server ───────────────────────────────────
        MetricsService metrics = MetricsService.getInstance();
        metrics.startServer();

        // ── Initialize Vault connection ───────────────────────────────────────
        VaultConfig config = VaultConfig.getInstance();

        System.out.printf("Connecting to Vault at: %s%n", config.getVaultAddr());

        try {
            config.verifyConnectivity();
            System.out.println("✓ Vault connected and healthy\n");
        } catch (Exception e) {
            System.out.println("⚠ Vault not reachable — running in DEMO mode (no real Vault)");
            System.out.println("  Start Vault: docker run -e VAULT_DEV_ROOT_TOKEN_ID=root "
                    + "-p 8200:8200 hashicorp/vault server -dev\n");
        }

        VaultTemplate vaultTemplate = config.getVaultTemplate();

        // ── Parse CLI arguments for selective demo ────────────────────────────
        String mode = args.length > 0 ? args[0].toLowerCase() : "all";

        switch (mode) {
            case "db"      -> runDbDemo(vaultTemplate);
            case "pki"     -> runPkiDemo(vaultTemplate);
            case "transit" -> runTransitDemo(vaultTemplate);
            case "ssh"     -> runSshDemo(vaultTemplate);
            case "all"     -> {
                runDbDemo(vaultTemplate);
                runPkiDemo(vaultTemplate);
                runTransitDemo(vaultTemplate);
                runSshDemo(vaultTemplate);
            }
            default -> {
                System.out.println("Usage: java -jar vault-demo.jar [db|pki|transit|ssh|all]");
                System.exit(1);
            }
        }

        System.out.printf("""

            ✓ All demos completed.

            ┌─ Prometheus / Grafana ──────────────────────────────┐
            │  Metrics endpoint : http://localhost:%d/metrics      │
            │  Prometheus UI    : http://localhost:9090            │
            │  Grafana dashboard: http://localhost:3000            │
            │                     (admin / admin)                  │
            │                                                      │
            │  Press Ctrl+C to stop the metrics server.            │
            └─────────────────────────────────────────────────────┘
            %n""", metrics.getPort());
    }

    // ── Demo Runners ──────────────────────────────────────────────────────────

    private static void runDbDemo(VaultTemplate vaultTemplate) {
        System.out.println("\n" + "═".repeat(55));
        System.out.println("  SECRET ENGINE 1: Dynamic Database Secrets");
        System.out.println("═".repeat(55));

        try {
            DynamicDatabaseSecretService dbService = new DynamicDatabaseSecretService(
                    vaultTemplate,
                    System.getenv().getOrDefault("DB_HOST", "localhost"),
                    System.getenv().getOrDefault("DB_PORT", "5432"),
                    System.getenv().getOrDefault("DB_NAME", "mydb")
            );

            System.out.println("\nFetching credentials for 'readonly' role...");
            dbService.runDemo("readonly");

            System.out.println("\nFetching credentials for 'readwrite' role...");
            dbService.runDemo("readwrite");

        } catch (Exception e) {
            System.out.println("  [DB Demo] " + formatError(e));
            System.out.println("  → Setup: vault write database/config/mypostgres ...");
        }
    }

    private static void runPkiDemo(VaultTemplate vaultTemplate) {
        System.out.println("\n" + "═".repeat(55));
        System.out.println("  SECRET ENGINE 2: PKI Certificate Authority");
        System.out.println("═".repeat(55));

        try {
            PkiSecretService pkiService = new PkiSecretService(
                    vaultTemplate,
                    "pki_int",           // Intermediate CA mount
                    "example-dot-com"    // Role name
            );
            pkiService.runDemo();

        } catch (Exception e) {
            System.out.println("  [PKI Demo] " + formatError(e));
            System.out.println("  → Setup: vault secrets enable pki && "
                    + "vault write pki_int/roles/example-dot-com ...");
        }
    }

    private static void runTransitDemo(VaultTemplate vaultTemplate) {
        System.out.println("\n" + "═".repeat(55));
        System.out.println("  SECRET ENGINE 3: Transit (Encryption-as-a-Service)");
        System.out.println("═".repeat(55));

        try {
            TransitSecretService transitService = new TransitSecretService(vaultTemplate);
            transitService.runDemo();

        } catch (Exception e) {
            System.out.println("  [Transit Demo] " + formatError(e));
            System.out.println("  → Setup: vault secrets enable transit && "
                    + "vault write -f transit/keys/app-encryption");
        }
    }

    private static void runSshDemo(VaultTemplate vaultTemplate) {
        System.out.println("\n" + "═".repeat(55));
        System.out.println("  SECRET ENGINE 4: SSH (OTP + Signed Certificates)");
        System.out.println("═".repeat(55));

        try {
            SshSecretService sshService = new SshSecretService(vaultTemplate);
            sshService.runDemo();

        } catch (Exception e) {
            System.out.println("  [SSH Demo] " + formatError(e));
            System.out.println("  → Setup: vault secrets enable ssh && "
                    + "vault write ssh/roles/otp-role key_type=otp ...");
        }
    }

    private static String formatError(Exception e) {
        String msg = e.getMessage();
        if (msg != null && msg.length() > 120) {
            msg = msg.substring(0, 120) + "...";
        }
        return "Requires real Vault — " + msg;
    }
}
