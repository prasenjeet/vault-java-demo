package com.example.vault.db;

import com.example.vault.config.VaultConfig;
import com.example.vault.metrics.MetricsService;
import com.example.vault.model.DatabaseCredential;
import io.prometheus.client.Histogram;
import com.zaxxer.hikari.HikariConfig;
import com.zaxxer.hikari.HikariDataSource;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.vault.core.VaultTemplate;
import org.springframework.vault.core.lease.SecretLeaseContainer;
import org.springframework.vault.core.lease.domain.RequestedSecret;
import org.springframework.vault.core.lease.event.SecretLeaseCreatedEvent;
import org.springframework.vault.core.lease.event.SecretLeaseExpiredEvent;
import org.springframework.vault.support.VaultResponse;

import javax.sql.DataSource;
import java.sql.Connection;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.Map;
import java.util.concurrent.atomic.AtomicReference;

/**
 * HashiCorp Vault — Dynamic Database Secrets Engine
 * ──────────────────────────────────────────────────
 * Vault generates short-lived PostgreSQL credentials on demand.
 * No static passwords. Credentials auto-expire when lease ends.
 *
 * Flow:
 *   App → Vault (GET /database/creds/<role>)
 *       ← Vault returns { username, password, lease_id, lease_duration }
 *   App → PostgreSQL (connect with dynamic creds)
 *   TTL expires → Vault revokes the DB user automatically
 *
 * Vault Setup (run once):
 * ──────────────────────
 *   vault secrets enable database
 *
 *   vault write database/config/mypostgres \
 *       plugin_name=postgresql-database-plugin \
 *       allowed_roles="readonly,readwrite" \
 *       connection_url="postgresql://{{username}}:{{password}}@localhost:5432/mydb?sslmode=disable" \
 *       username="vault_root" \
 *       password="vault_root_password"
 *
 *   vault write database/roles/readonly \
 *       db_name=mypostgres \
 *       creation_statements="CREATE ROLE \"{{name}}\" WITH LOGIN PASSWORD '{{password}}' VALID UNTIL '{{expiration}}'; \
 *           GRANT SELECT ON ALL TABLES IN SCHEMA public TO \"{{name}}\";" \
 *       default_ttl="1h" \
 *       max_ttl="24h"
 *
 *   vault write database/roles/readwrite \
 *       db_name=mypostgres \
 *       creation_statements="CREATE ROLE \"{{name}}\" WITH LOGIN PASSWORD '{{password}}' VALID UNTIL '{{expiration}}'; \
 *           GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO \"{{name}}\";" \
 *       default_ttl="1h" \
 *       max_ttl="24h"
 */
public class DynamicDatabaseSecretService {

    private static final Logger log = LoggerFactory.getLogger(DynamicDatabaseSecretService.class);

    // Vault path for DB credentials
    private static final String DB_CREDS_PATH = "database/creds/";

    private final VaultTemplate vaultTemplate;
    private final String dbHost;
    private final String dbPort;
    private final String dbName;

    public DynamicDatabaseSecretService(VaultTemplate vaultTemplate,
                                        String dbHost, String dbPort, String dbName) {
        this.vaultTemplate = vaultTemplate;
        this.dbHost = dbHost;
        this.dbPort = dbPort;
        this.dbName = dbName;
    }

    // ── 1. Fetch Dynamic Credentials ──────────────────────────────────────────

    /**
     * Retrieves a fresh set of dynamic DB credentials from Vault.
     * Each call creates a NEW username/password pair with a lease.
     *
     * @param role Vault DB role name (e.g., "readonly", "readwrite")
     * @return DatabaseCredential with username, password, leaseId, leaseDuration
     */
    public DatabaseCredential getDynamicCredentials(String role) {
        log.info("Requesting dynamic DB credentials for role: {}", role);
        Histogram.Timer timer = MetricsService.startTimer("database", "get_credentials");
        try {
            VaultResponse response = vaultTemplate.read(DB_CREDS_PATH + role);
            if (response == null || response.getData() == null) {
                throw new RuntimeException("No credentials returned from Vault for role: " + role);
            }

            Map<String, Object> data = response.getData();
            String username    = (String) data.get("username");
            String password    = (String) data.get("password");
            String leaseId     = response.getLeaseId();
            long leaseDuration = response.getLeaseDuration();

            MetricsService.DB_CREDENTIAL_TTL.labels(role).set(leaseDuration);
            MetricsService.recordSuccess("database", "get_credentials");
            log.info("Dynamic credentials issued → user={}, lease_id={}, ttl={}s",
                    username, leaseId, leaseDuration);

            return new DatabaseCredential(username, password, leaseId, leaseDuration, role);
        } catch (Exception e) {
            MetricsService.recordError("database", "get_credentials");
            throw e;
        } finally {
            timer.observeDuration();
        }
    }

    // ── 2. Build HikariCP DataSource with Dynamic Credentials ─────────────────

    /**
     * Creates a HikariCP connection pool using Vault-issued dynamic credentials.
     * Pool should be recreated when credentials are renewed.
     */
    public HikariDataSource buildDataSource(DatabaseCredential cred) {
        log.info("Building HikariCP pool with dynamic user: {}", cred.username());

        HikariConfig config = new HikariConfig();
        config.setJdbcUrl(String.format("jdbc:postgresql://%s:%s/%s", dbHost, dbPort, dbName));
        config.setUsername(cred.username());
        config.setPassword(cred.password());
        config.setDriverClassName("org.postgresql.Driver");

        // Pool sizing — keep small since creds rotate
        config.setMaximumPoolSize(5);
        config.setMinimumIdle(1);
        config.setConnectionTimeout(30_000);
        config.setIdleTimeout(600_000);

        // Set max lifetime to slightly less than Vault lease to avoid stale connections
        long maxLifetimeMs = Math.max((cred.leaseDurationSeconds() - 60) * 1000L, 30_000L);
        config.setMaxLifetime(maxLifetimeMs);

        config.setPoolName("VaultDynamicPool-" + cred.role());

        // Validation
        config.setConnectionTestQuery("SELECT 1");

        return new HikariDataSource(config);
    }

    // ── 3. Auto-Renewal with SecretLeaseContainer ─────────────────────────────

    /**
     * Sets up automatic lease renewal using Spring Vault's SecretLeaseContainer.
     * Credentials are automatically renewed before TTL expires.
     * On expiration, a new credential set is fetched and pool is rebuilt.
     *
     * @param role       DB role to lease
     * @param dsHolder   AtomicReference holding the active DataSource (rebuilt on renewal)
     */
    public void setupAutoRenewal(String role, AtomicReference<HikariDataSource> dsHolder) {
        SecretLeaseContainer container = new SecretLeaseContainer(vaultTemplate);

        RequestedSecret secret = RequestedSecret.rotating(DB_CREDS_PATH + role);

        container.addLeaseListener(event -> {
            if (event instanceof SecretLeaseCreatedEvent created) {
                log.info("Lease created/renewed for {}: lease_id={}",
                        role, created.getLease().getLeaseId());

                Map<String, Object> data = created.getSecrets();
                DatabaseCredential newCred = new DatabaseCredential(
                        (String) data.get("username"),
                        (String) data.get("password"),
                        created.getLease().getLeaseId(),
                        created.getLease().getLeaseDuration().getSeconds(),
                        role
                );

                // Swap data source atomically
                HikariDataSource oldDs = dsHolder.getAndSet(buildDataSource(newCred));
                if (oldDs != null && !oldDs.isClosed()) {
                    log.info("Closing old DataSource for user: {}", oldDs.getUsername());
                    oldDs.close();
                }

            } else if (event instanceof SecretLeaseExpiredEvent expired) {
                log.warn("Lease EXPIRED for {}. Requesting new credentials.", role);
            }
        });

        container.addRequestedSecret(secret);

        try {
            container.start();
            log.info("SecretLeaseContainer started for role: {}", role);
        } catch (Exception e) {
            log.error("Failed to start SecretLeaseContainer", e);
            throw new RuntimeException(e);
        }
    }

    // ── 4. Revoke Lease Explicitly ────────────────────────────────────────────

    /**
     * Explicitly revoke a Vault lease (drops the DB user immediately).
     * Call this on application shutdown for clean resource release.
     */
    public void revokeLease(DatabaseCredential cred) {
        Histogram.Timer timer = MetricsService.startTimer("database", "revoke_lease");
        try {
            vaultTemplate.write("sys/leases/revoke", Map.of("lease_id", cred.leaseId()));
            MetricsService.recordSuccess("database", "revoke_lease");
            log.info("Lease revoked: {} (user: {})", cred.leaseId(), cred.username());
        } catch (Exception e) {
            MetricsService.recordError("database", "revoke_lease");
            log.warn("Failed to revoke lease {}: {}", cred.leaseId(), e.getMessage());
        } finally {
            timer.observeDuration();
        }
    }

    // ── 5. Demo: Execute Query with Dynamic Credentials ───────────────────────

    /**
     * Full end-to-end demo:
     *   1. Get dynamic creds from Vault
     *   2. Build connection pool
     *   3. Execute a sample query
     *   4. Revoke lease on completion
     */
    public void runDemo(String role) {
        DatabaseCredential cred = null;
        HikariDataSource ds = null;

        try {
            // Step 1: Get credentials
            cred = getDynamicCredentials(role);
            System.out.printf("""
                ┌─ Dynamic DB Credentials ────────────────────────┐
                │  Role     : %-34s │
                │  Username : %-34s │
                │  Password : %-34s │
                │  Lease ID : %-34s │
                │  TTL      : %-30ds │
                └─────────────────────────────────────────────────┘
                %n""",
                    role, cred.username(),
                    maskPassword(cred.password()),
                    cred.leaseId().substring(0, Math.min(36, cred.leaseId().length())),
                    cred.leaseDurationSeconds());

            // Step 2: Build pool
            ds = buildDataSource(cred);

            // Step 3: Execute query
            executeTestQuery(ds, cred.username());

        } finally {
            // Step 4: Cleanup
            if (ds != null) ds.close();
            if (cred != null) revokeLease(cred);
        }
    }

    private void executeTestQuery(DataSource ds, String username) {
        try (Connection conn = ds.getConnection();
             Statement stmt = conn.createStatement();
             ResultSet rs = stmt.executeQuery(
                     "SELECT current_user, current_database(), now()")) {
            if (rs.next()) {
                System.out.printf("  Connected as: %s | DB: %s | Time: %s%n",
                        rs.getString(1), rs.getString(2), rs.getString(3));
            }
        } catch (SQLException e) {
            log.error("Query failed for user {}: {}", username, e.getMessage());
            System.out.println("  [Simulated query — connect to real PostgreSQL to execute]");
        }
    }

    private String maskPassword(String password) {
        if (password == null || password.length() <= 4) return "****";
        return password.substring(0, 2) + "*".repeat(password.length() - 4)
                + password.substring(password.length() - 2);
    }
}
