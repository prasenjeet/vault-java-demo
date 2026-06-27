package com.example.vault.transit;

import com.example.vault.metrics.MetricsService;
import io.prometheus.client.Histogram;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.vault.core.VaultTemplate;
import org.springframework.vault.core.VaultTransitOperations;
import org.springframework.vault.support.*;
import org.springframework.vault.support.Hmac;
import org.springframework.vault.support.Signature;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Map;

/**
 * HashiCorp Vault — Transit Secrets Engine (Encryption-as-a-Service)
 * ───────────────────────────────────────────────────────────────────
 * Vault handles all cryptographic operations. Plaintext is sent to Vault,
 * ciphertext comes back. Vault NEVER stores the plaintext.
 * Private keys NEVER leave Vault.
 *
 * Operations:
 *   • Encrypt / Decrypt            — Symmetric encryption (AES-256-GCM)
 *   • Sign / Verify                — Asymmetric signing (ECDSA, RSA)
 *   • HMAC                         — Message authentication codes
 *   • Hash                         — SHA-256/512
 *   • Random bytes                 — CSPRNG
 *   • Key rotation                 — Zero-downtime key rotation
 *   • Rewrap                       — Re-encrypt with latest key version
 *   • Batch Encrypt/Decrypt        — High-throughput bulk operations
 *   • Data key generation          — Derived keys for local encryption
 *
 * Vault Setup (run once):
 * ──────────────────────
 *   vault secrets enable transit
 *
 *   # Symmetric encryption key (AES-256-GCM96)
 *   vault write -f transit/keys/app-encryption
 *
 *   # Asymmetric signing key (ECDSA P-256)
 *   vault write transit/keys/app-signing type=ecdsa-p256
 *
 *   # RSA key for signing/encryption
 *   vault write transit/keys/app-rsa type=rsa-4096
 *
 *   # Enable key rotation (optional policy)
 *   vault write transit/keys/app-encryption/config \
 *       min_decryption_version=1 \
 *       min_encryption_version=0 \
 *       deletion_allowed=false
 */
public class TransitSecretService {

    private static final Logger log = LoggerFactory.getLogger(TransitSecretService.class);

    private final VaultTemplate vaultTemplate;
    private final VaultTransitOperations transitOps;

    // Key names (configured in Vault)
    public static final String ENCRYPTION_KEY = "app-encryption";   // AES-256-GCM
    public static final String SIGNING_KEY     = "app-signing";      // ECDSA P-256
    public static final String RSA_KEY         = "app-rsa";          // RSA-4096
    public static final String HMAC_KEY        = "app-hmac";         // HMAC-SHA-256

    public TransitSecretService(VaultTemplate vaultTemplate) {
        this.vaultTemplate = vaultTemplate;
        this.transitOps    = vaultTemplate.opsForTransit();
    }

    // ── 1. Encrypt / Decrypt ──────────────────────────────────────────────────

    /**
     * Encrypts plaintext using Vault Transit (AES-256-GCM).
     * Plaintext is base64-encoded before sending to Vault.
     *
     * @param keyName   Transit key name
     * @param plaintext Data to encrypt
     * @return Vault ciphertext (format: vault:v{version}:base64...)
     */
    public String encrypt(String keyName, String plaintext) {
        log.debug("Encrypting with key: {}", keyName);
        Histogram.Timer timer = MetricsService.startTimer("transit", "encrypt");
        try {
            Plaintext pt = Plaintext.of(plaintext);
            Ciphertext ciphertext = transitOps.encrypt(keyName, pt);
            MetricsService.recordSuccess("transit", "encrypt");
            log.debug("Encrypted → {}", ciphertext.getCiphertext().substring(0, 20) + "...");
            return ciphertext.getCiphertext();
        } catch (Exception e) {
            MetricsService.recordError("transit", "encrypt");
            throw e;
        } finally {
            timer.observeDuration();
        }
    }

    /**
     * Decrypts Vault ciphertext back to plaintext string.
     *
     * @param keyName    Transit key name
     * @param ciphertext Vault ciphertext (vault:v{n}:...)
     * @return Decrypted plaintext string
     */
    public String decrypt(String keyName, String ciphertext) {
        log.debug("Decrypting with key: {}", keyName);
        Histogram.Timer timer = MetricsService.startTimer("transit", "decrypt");
        try {
            Plaintext plaintext = transitOps.decrypt(keyName, Ciphertext.of(ciphertext));
            MetricsService.recordSuccess("transit", "decrypt");
            return plaintext.asString();
        } catch (Exception e) {
            MetricsService.recordError("transit", "decrypt");
            throw e;
        } finally {
            timer.observeDuration();
        }
    }

    // ── 2. Encrypt / Decrypt with Context (key derivation) ───────────────────

    /**
     * Context-derived encryption: different context → different derived key.
     * Context binds ciphertext to specific use (e.g., user ID, tenant ID).
     * Ciphertext cannot be decrypted without the same context.
     *
     * @param keyName   Transit key name (must be derived-type)
     * @param plaintext Data to encrypt
     * @param context   Binding context (e.g., userId, tenantId)
     * @return Vault ciphertext
     */
    public String encryptWithContext(String keyName, String plaintext, String context) {
        Plaintext pt = Plaintext.of(plaintext).with(
                VaultTransitContext.fromContext(context.getBytes(StandardCharsets.UTF_8)));
        Ciphertext ciphertext = transitOps.encrypt(keyName, pt);

        log.debug("Encrypted with context '{}' → key={}", context, keyName);
        return ciphertext.getCiphertext();
    }

    public String decryptWithContext(String keyName, String ciphertext, String context) {
        Plaintext plaintext = transitOps.decrypt(
                keyName,
                Ciphertext.of(ciphertext).with(
                        VaultTransitContext.fromContext(context.getBytes(StandardCharsets.UTF_8)))
        );
        return plaintext.asString();
    }

    // ── 3. Batch Encrypt / Decrypt ────────────────────────────────────────────

    /**
     * Encrypts multiple plaintexts in a single Vault API call.
     * More efficient than individual encrypt calls for bulk operations.
     *
     * @param keyName    Transit key name
     * @param plaintexts List of strings to encrypt
     * @return List of Vault ciphertexts (same order)
     */
    public List<String> batchEncrypt(String keyName, List<String> plaintexts) {
        log.info("Batch encrypting {} items with key: {}", plaintexts.size(), keyName);
        Histogram.Timer timer = MetricsService.startTimer("transit", "batch_encrypt");
        try {
            List<Plaintext> pts = plaintexts.stream()
                    .map(Plaintext::of)
                    .toList();

            List<VaultEncryptionResult> results = transitOps.encrypt(keyName, pts);

            List<String> ciphertexts = new ArrayList<>();
            for (VaultEncryptionResult result : results) {
                if (result.getCause() == null) {
                    ciphertexts.add(result.get().getCiphertext());
                } else {
                    log.error("Batch encrypt error: {}", result.getCause());
                    ciphertexts.add(null);
                }
            }
            MetricsService.recordSuccess("transit", "batch_encrypt");
            return ciphertexts;
        } catch (Exception e) {
            MetricsService.recordError("transit", "batch_encrypt");
            throw e;
        } finally {
            timer.observeDuration();
        }
    }

    /**
     * Decrypts multiple ciphertexts in a single Vault API call.
     */
    public List<String> batchDecrypt(String keyName, List<String> ciphertexts) {
        log.info("Batch decrypting {} items with key: {}", ciphertexts.size(), keyName);

        List<Ciphertext> cts = ciphertexts.stream()
                .map(Ciphertext::of)
                .toList();

        List<VaultDecryptionResult> results = transitOps.decrypt(keyName, cts);

        return results.stream()
                .map(r -> r.get() != null ? r.get().asString() : null)
                .toList();
    }

    // ── 4. Sign / Verify ──────────────────────────────────────────────────────

    /**
     * Signs data using a Vault Transit asymmetric key (ECDSA/RSA).
     * The private key NEVER leaves Vault.
     *
     * @param keyName  Transit signing key (ecdsa-p256 or rsa-*)
     * @param data     Data to sign (will be hashed internally)
     * @return Base64-encoded signature
     */
    public String sign(String keyName, String data) {
        log.debug("Signing data with key: {}", keyName);
        Histogram.Timer timer = MetricsService.startTimer("transit", "sign");
        try {
            Plaintext pt = Plaintext.of(data);
            Signature signature = transitOps.sign(keyName, pt);
            MetricsService.recordSuccess("transit", "sign");
            log.debug("Signed → {}", signature.getSignature().substring(0, 20) + "...");
            return signature.getSignature();
        } catch (Exception e) {
            MetricsService.recordError("transit", "sign");
            throw e;
        } finally {
            timer.observeDuration();
        }
    }

    /**
     * Verifies a signature using the Vault Transit key's public key.
     *
     * @param keyName   Transit key name
     * @param data      Original data
     * @param signature Base64 signature from sign()
     * @return true if signature is valid
     */
    public boolean verify(String keyName, String data, String signature) {
        log.debug("Verifying signature with key: {}", keyName);
        Histogram.Timer timer = MetricsService.startTimer("transit", "verify");
        try {
            Plaintext pt = Plaintext.of(data);
            boolean valid = transitOps.verify(keyName, pt, Signature.of(signature));
            MetricsService.recordSuccess("transit", "verify");
            log.info("Signature verification for key {}: {}", keyName, valid ? "VALID" : "INVALID");
            return valid;
        } catch (Exception e) {
            MetricsService.recordError("transit", "verify");
            throw e;
        } finally {
            timer.observeDuration();
        }
    }

    // ── 5. HMAC ───────────────────────────────────────────────────────────────

    /**
     * Generates an HMAC-SHA-256 of the given data using a Vault-managed key.
     * Useful for data integrity verification and API request signing.
     *
     * @param keyName Transit key name
     * @param data    Data to HMAC
     * @return Vault HMAC string (vault:v{n}:base64...)
     */
    public String hmac(String keyName, String data) {
        log.debug("Generating HMAC with key: {}", keyName);

        Plaintext pt = Plaintext.of(data);
        VaultHmacRequest request = VaultHmacRequest.builder()
                .plaintext(pt)
                .build();

        Hmac hmacResult = transitOps.getHmac(keyName, request);
        return hmacResult.getHmac();
    }

    /**
     * Verifies an HMAC matches the given data.
     */
    public boolean verifyHmac(String keyName, String data, String hmacValue) {
        Plaintext pt = Plaintext.of(data);
        return transitOps.verify(keyName, pt, Signature.of(hmacValue));
    }

    // ── 6. Key Rotation ───────────────────────────────────────────────────────

    /**
     * Rotates the Transit key to a new version.
     * Old versions can still decrypt existing ciphertexts.
     * New encryptions use the latest version automatically.
     * Use rewrap() to re-encrypt old ciphertexts with the new key version.
     *
     * @param keyName Transit key to rotate
     */
    public void rotateKey(String keyName) {
        log.info("Rotating Transit key: {}", keyName);
        Histogram.Timer timer = MetricsService.startTimer("transit", "rotate_key");
        try {
            transitOps.rotate(keyName);
            MetricsService.TRANSIT_KEY_ROTATIONS.labels(keyName).inc();
            MetricsService.recordSuccess("transit", "rotate_key");
            log.info("Key rotated successfully: {}", keyName);
        } catch (Exception e) {
            MetricsService.recordError("transit", "rotate_key");
            throw e;
        } finally {
            timer.observeDuration();
        }
    }

    /**
     * Re-encrypts a ciphertext with the latest key version.
     * Old ciphertexts become current without decrypting to plaintext.
     * Call after key rotation to upgrade all stored ciphertexts.
     *
     * @param keyName    Transit key name
     * @param ciphertext Existing ciphertext (older key version)
     * @return New ciphertext encrypted with latest key version
     */
    public String rewrap(String keyName, String ciphertext) {
        log.debug("Rewrapping ciphertext with latest key version: {}", keyName);

        return transitOps.rewrap(keyName, ciphertext);
    }

    // ── 7. Data Key Generation ────────────────────────────────────────────────

    /**
     * Generates a data encryption key (DEK) for local encryption.
     * Returns both:
     *   - plaintext DEK (use for local crypto, then discard)
     *   - ciphertext DEK (store alongside encrypted data)
     *
     * Pattern (Envelope Encryption):
     *   1. Generate DEK from Vault
     *   2. Use plaintext DEK to encrypt large data locally (AES)
     *   3. Store ciphertext DEK alongside encrypted data
     *   4. Discard plaintext DEK from memory
     *   5. Later: decrypt ciphertext DEK via Vault, use to decrypt data
     *
     * @param keyName Transit master key name
     * @param bits    Key size: 128, 256, or 512
     * @return Map with "plaintext" (base64) and "ciphertext" (vault:v{n}:...)
     */
    public Map<String, String> generateDataKey(String keyName, int bits) {
        log.info("Generating {}-bit data key with master key: {}", bits, keyName);

        VaultTransitKeyCreationRequest keyRequest = VaultTransitKeyCreationRequest.builder()
                .derived(false)
                .build();

        Map<String, Object> request = Map.of("bits", bits);

        var response = vaultTemplate.write(
                "transit/datakey/plaintext/" + keyName, request);

        if (response == null || response.getData() == null) {
            throw new RuntimeException("Data key generation failed");
        }

        Map<String, Object> data = response.getData();
        return Map.of(
                "plaintext",  (String) data.get("plaintext"),   // base64 raw key
                "ciphertext", (String) data.get("ciphertext")   // vault:v{n}:...
        );
    }

    // ── 8. Hash ───────────────────────────────────────────────────────────────

    /**
     * Hash data using Vault's CSPRNG-based hash function.
     *
     * @param data      Data to hash
     * @param algorithm sha2-256, sha2-512, sha3-256, sha3-512
     * @return Hex-encoded hash
     */
    public String hash(String data, String algorithm) {
        String base64Data = Base64.getEncoder()
                .encodeToString(data.getBytes(StandardCharsets.UTF_8));

        Map<String, Object> request = Map.of(
                "input",     base64Data,
                "algorithm", algorithm,
                "format",    "hex"
        );

        var response = vaultTemplate.write("transit/hash/" + algorithm, request);
        if (response == null || response.getData() == null) {
            throw new RuntimeException("Hashing failed");
        }
        return (String) response.getData().get("sum");
    }

    // ── 9. Random Bytes ───────────────────────────────────────────────────────

    /**
     * Generates cryptographically secure random bytes from Vault.
     * More secure than Java's SecureRandom for high-assurance use cases.
     *
     * @param numBytes Number of random bytes (1-65536)
     * @return Base64-encoded random bytes
     */
    public String generateRandomBytes(int numBytes) {
        Map<String, Object> request = Map.of(
                "bytes",  numBytes,
                "format", "base64"
        );

        var response = vaultTemplate.write("transit/random/" + numBytes, request);
        if (response == null || response.getData() == null) {
            throw new RuntimeException("Random byte generation failed");
        }
        return (String) response.getData().get("random_bytes");
    }

    // ── 10. Demo ───────────────────────────────────────────────────────────────

    public void runDemo() {
        System.out.println("\n══════════════ Transit Secrets Engine Demo ══════════════");

        // ─── Encrypt / Decrypt ───
        String sensitiveData  = "user:prasenjeet@example.com | card:4111111111111111 | cvv:123";
        String encrypted      = encrypt(ENCRYPTION_KEY, sensitiveData);
        String decrypted      = decrypt(ENCRYPTION_KEY, encrypted);

        System.out.printf("""
            ┌─ Encrypt / Decrypt ─────────────────────────────────┐
            │  Plaintext  : %-34s │
            │  Ciphertext : %-34s │
            │  Decrypted  : %-34s │
            │  Match      : %-34s │
            └─────────────────────────────────────────────────────┘
            %n""",
                sensitiveData.substring(0, Math.min(34, sensitiveData.length())),
                encrypted.substring(0, Math.min(34, encrypted.length())),
                decrypted.substring(0, Math.min(34, decrypted.length())),
                sensitiveData.equals(decrypted) ? "✓ YES" : "✗ NO");

        // ─── Sign / Verify ───
        String payload   = "{\"userId\":\"u-1234\",\"action\":\"transfer\",\"amount\":5000}";
        String signature = sign(SIGNING_KEY, payload);
        boolean valid    = verify(SIGNING_KEY, payload, signature);

        System.out.printf("""
            ┌─ Sign / Verify ─────────────────────────────────────┐
            │  Payload    : %-34s │
            │  Signature  : %-34s │
            │  Valid      : %-34s │
            └─────────────────────────────────────────────────────┘
            %n""",
                payload.substring(0, Math.min(34, payload.length())),
                signature.substring(0, Math.min(34, signature.length())),
                valid ? "✓ VALID" : "✗ INVALID");

        // ─── Batch Encrypt ───
        List<String> records = List.of(
                "SSN:123-45-6789",
                "SSN:987-65-4321",
                "SSN:555-12-3456"
        );
        List<String> batchCiphertexts = batchEncrypt(ENCRYPTION_KEY, records);

        System.out.println("┌─ Batch Encrypt ─────────────────────────────────────┐");
        for (int i = 0; i < records.size(); i++) {
            String ct = batchCiphertexts.get(i);
            System.out.printf("│  [%d] %-50s │%n", i,
                    ct != null ? ct.substring(0, Math.min(50, ct.length())) : "ERROR");
        }
        System.out.println("└─────────────────────────────────────────────────────┘\n");

        // ─── Key Rotation + Rewrap ───
        System.out.println("  Rotating key: " + ENCRYPTION_KEY);
        rotateKey(ENCRYPTION_KEY);
        String rewrapped = rewrap(ENCRYPTION_KEY, encrypted);
        System.out.printf("  Rewrapped: old=%s...%n  →    new=%s...%n%n",
                encrypted.substring(0, 25), rewrapped.substring(0, 25));
    }
}
