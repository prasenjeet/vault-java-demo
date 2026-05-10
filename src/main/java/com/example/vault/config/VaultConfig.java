package com.example.vault.config;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.vault.authentication.TokenAuthentication;
import org.springframework.vault.client.VaultEndpoint;
import org.springframework.vault.core.VaultTemplate;
import org.springframework.vault.support.VaultHealth;

import java.net.URI;

/**
 * Central Vault configuration and VaultTemplate factory.
 *
 * Supports:
 *   - Token authentication (dev/test)
 *   - AppRole authentication (production)
 *   - Configurable via environment variables or application.properties
 *
 * Environment Variables:
 *   VAULT_ADDR   - e.g. http://127.0.0.1:8200
 *   VAULT_TOKEN  - Root/dev token or wrapped token
 */
public class VaultConfig {

    private static final Logger log = LoggerFactory.getLogger(VaultConfig.class);

    // ── Environment variable names ────────────────────────────────────────────
    public static final String ENV_VAULT_ADDR  = "VAULT_ADDR";
    public static final String ENV_VAULT_TOKEN = "VAULT_TOKEN";

    // ── Defaults (Vault dev server) ───────────────────────────────────────────
    private static final String DEFAULT_VAULT_ADDR  = "http://127.0.0.1:8200";
    private static final String DEFAULT_VAULT_TOKEN = "root";

    private final String vaultAddr;
    private final String vaultToken;
    private VaultTemplate vaultTemplate;

    // ── Singleton ─────────────────────────────────────────────────────────────
    private static VaultConfig instance;

    private VaultConfig() {
        this.vaultAddr  = getEnv(ENV_VAULT_ADDR,  DEFAULT_VAULT_ADDR);
        this.vaultToken = getEnv(ENV_VAULT_TOKEN,  DEFAULT_VAULT_TOKEN);
        log.info("Vault address : {}", vaultAddr);
        log.info("Vault token   : {}***", vaultToken.substring(0, Math.min(4, vaultToken.length())));
    }

    public static synchronized VaultConfig getInstance() {
        if (instance == null) {
            instance = new VaultConfig();
        }
        return instance;
    }

    // ── VaultTemplate (Spring Vault) ──────────────────────────────────────────

    /**
     * Returns a cached VaultTemplate using token authentication.
     * Thread-safe via lazy initialization.
     */
    public synchronized VaultTemplate getVaultTemplate() {
        if (vaultTemplate == null) {
            VaultEndpoint endpoint = VaultEndpoint.from(URI.create(vaultAddr));
            vaultTemplate = new VaultTemplate(endpoint, new TokenAuthentication(vaultToken));
            log.info("VaultTemplate initialized → {}", vaultAddr);
        }
        return vaultTemplate;
    }

    /**
     * Health-check: verify Vault is reachable and unsealed.
     */
    public void verifyConnectivity() {
        try {
            VaultHealth health = getVaultTemplate().opsForSys().health();
            log.info("Vault health → initialized={}, sealed={}, standby={}",
                    health.isInitialized(), health.isSealed(), health.isStandby());
            if (health.isSealed()) {
                throw new IllegalStateException("Vault is sealed — cannot proceed!");
            }
        } catch (Exception e) {
            log.error("Cannot reach Vault at {}: {}", vaultAddr, e.getMessage());
            throw new RuntimeException("Vault connectivity check failed", e);
        }
    }

    // ── Accessors ─────────────────────────────────────────────────────────────

    public String getVaultAddr()  { return vaultAddr;  }
    public String getVaultToken() { return vaultToken; }

    // ── Helpers ───────────────────────────────────────────────────────────────

    private static String getEnv(String key, String defaultValue) {
        String value = System.getenv(key);
        if (value == null || value.isBlank()) {
            value = System.getProperty(key, defaultValue);
        }
        return value;
    }
}
