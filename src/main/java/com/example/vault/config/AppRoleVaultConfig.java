package com.example.vault.config;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.vault.authentication.AppRoleAuthentication;
import org.springframework.vault.authentication.AppRoleAuthenticationOptions;
import org.springframework.vault.client.VaultEndpoint;
import org.springframework.vault.core.VaultTemplate;
import org.springframework.vault.support.VaultToken;

import java.net.URI;

/**
 * AppRole Authentication for production environments.
 *
 * Flow:
 *   1. Application has Role ID (not secret, can be baked into image)
 *   2. Secret ID is injected at runtime (from CI/CD, init container, etc.)
 *   3. Both are exchanged for a short-lived Vault token
 *
 * Environment Variables:
 *   VAULT_ADDR          - Vault server URL
 *   VAULT_ROLE_ID       - AppRole Role ID
 *   VAULT_SECRET_ID     - AppRole Secret ID (injected at runtime)
 *   VAULT_APPROLE_PATH  - Mount path (default: approle)
 */
public class AppRoleVaultConfig {

    private static final Logger log = LoggerFactory.getLogger(AppRoleVaultConfig.class);

    private final String vaultAddr;
    private final String roleId;
    private final String secretId;
    private final String appRolePath;

    public AppRoleVaultConfig() {
        this.vaultAddr   = getEnv("VAULT_ADDR",         "http://127.0.0.1:8200");
        this.roleId      = getEnv("VAULT_ROLE_ID",      "");
        this.secretId    = getEnv("VAULT_SECRET_ID",    "");
        this.appRolePath = getEnv("VAULT_APPROLE_PATH", "approle");

        if (roleId.isBlank() || secretId.isBlank()) {
            throw new IllegalStateException(
                "VAULT_ROLE_ID and VAULT_SECRET_ID must be set for AppRole auth");
        }
    }

    /**
     * Creates a VaultTemplate authenticated via AppRole.
     * The returned token has a TTL configured on the AppRole role.
     */
    public VaultTemplate buildVaultTemplate() {
        VaultEndpoint endpoint = VaultEndpoint.from(URI.create(vaultAddr));

        AppRoleAuthenticationOptions options = AppRoleAuthenticationOptions.builder()
                .roleId(AppRoleAuthenticationOptions.RoleId.provided(roleId))
                .secretId(AppRoleAuthenticationOptions.SecretId.provided(secretId))
                .path(appRolePath)
                .build();

        // RestTemplate needed internally by Spring Vault
        org.springframework.web.client.RestTemplate restTemplate =
                org.springframework.vault.client.VaultClients.createRestTemplate(
                        endpoint,
                        new org.springframework.http.client.SimpleClientHttpRequestFactory());

        AppRoleAuthentication auth = new AppRoleAuthentication(options, restTemplate);
        VaultToken token = auth.login();

        log.info("AppRole login successful. Token acquired.");

        return new VaultTemplate(endpoint, auth);
    }

    // ── Vault setup commands (run once) ───────────────────────────────────────

    /**
     * Instructions to configure AppRole in Vault (CLI reference).
     *
     * vault auth enable approle
     *
     * vault write auth/approle/role/myapp \
     *     token_ttl=1h \
     *     token_max_ttl=4h \
     *     token_policies="myapp-policy" \
     *     bind_secret_id=true \
     *     secret_id_ttl=24h \
     *     secret_id_num_uses=10
     *
     * # Get Role ID (not secret)
     * vault read auth/approle/role/myapp/role-id
     *
     * # Generate Secret ID (inject at runtime)
     * vault write -f auth/approle/role/myapp/secret-id
     */
    public static void printSetupInstructions() {
        System.out.println("""
            ── AppRole Setup (run once in Vault) ────────────────────────────
            vault auth enable approle
            
            vault write auth/approle/role/myapp \\
                token_ttl=1h \\
                token_max_ttl=4h \\
                token_policies="myapp-policy" \\
                bind_secret_id=true \\
                secret_id_ttl=24h \\
                secret_id_num_uses=10
            
            # Get Role ID (embed in app config — not a secret)
            vault read auth/approle/role/myapp/role-id
            
            # Generate Secret ID (inject at runtime via CI/CD)
            vault write -f auth/approle/role/myapp/secret-id
            ─────────────────────────────────────────────────────────────────
            """);
    }

    private static String getEnv(String key, String defaultValue) {
        String v = System.getenv(key);
        return (v != null && !v.isBlank()) ? v : defaultValue;
    }
}
