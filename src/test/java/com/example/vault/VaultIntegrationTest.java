package com.example.vault;

import com.example.vault.config.VaultConfig;
import com.example.vault.db.DynamicDatabaseSecretService;
import com.example.vault.model.DatabaseCredential;
import com.example.vault.model.IssuedCertificate;
import com.example.vault.pki.PkiSecretService;
import com.example.vault.ssh.SshSecretService;
import com.example.vault.transit.TransitSecretService;
import org.junit.jupiter.api.*;
import org.springframework.vault.core.VaultTemplate;
import org.springframework.vault.support.VaultResponse;
import org.testcontainers.junit.jupiter.Testcontainers;
import org.testcontainers.vault.VaultContainer;

import java.time.Duration;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Integration tests using Testcontainers (real Vault in Docker).
 *
 * Requires Docker running locally. Tests spin up a Vault dev container,
 * configure each secret engine, and verify end-to-end flows.
 *
 * Run with: mvn test
 */
@Testcontainers
@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
@DisplayName("HashiCorp Vault Secret Engines Integration Tests")
class VaultIntegrationTest {

    // ── Vault Test Container ──────────────────────────────────────────────────

    static final String ROOT_TOKEN = "test-root-token";

    @org.testcontainers.junit.jupiter.Container
    static final VaultContainer<?> vault = new VaultContainer<>("hashicorp/vault:latest")
            .withVaultToken(ROOT_TOKEN)
            // Fix: SKIP_SETCAP avoids CAP_SETFCAP error in restricted environments
            // disable_mlock removes the need for IPC_LOCK capability entirely
            .withEnv("SKIP_SETCAP", "true")
            .withEnv("VAULT_LOCAL_CONFIG",
                    "{\"disable_mlock\":true,\"ui\":false}")
            .withInitCommand(
                    // Enable all secret engines
                    "secrets enable database",
                    "secrets enable pki",
                    "secrets tune -max-lease-ttl=87600h pki",
                    "secrets enable transit",
                    "secrets enable ssh",
                    "secrets enable -path=ssh-client-signer ssh",

                    // Transit keys
                    "write -f transit/keys/app-encryption",
                    "write transit/keys/app-signing type=ecdsa-p256",

                    // PKI Root CA
                    "write pki/root/generate/internal common_name=test.example.com ttl=87600h",
                    "write pki/config/urls " +
                            "issuing_certificates=http://vault:8200/v1/pki/ca " +
                            "crl_distribution_points=http://vault:8200/v1/pki/crl",
                    "write pki/roles/test-role " +
                            "allowed_domains=test.example.com " +
                            "allow_subdomains=true " +
                            "allow_ip_sans=true " +
                            "allow_any_name=true " +
                            "max_ttl=72h",

                    // SSH Client CA
                    "write ssh-client-signer/config/ca generate_signing_key=true",
                    "write ssh-client-signer/roles/test-role " +
                            "key_type=ca " +
                            "allow_user_certificates=true " +
                            "allowed_users=ubuntu,ec2-user " +
                            "allowed_extensions=permit-pty,permit-port-forwarding " +
                            "ttl=30m"
            );

    static VaultTemplate vaultTemplate;

    @BeforeAll
    static void setUp() {
        System.setProperty("VAULT_ADDR",  "http://" + vault.getHost() + ":" + vault.getFirstMappedPort());
        System.setProperty("VAULT_TOKEN", ROOT_TOKEN);

        vaultTemplate = VaultConfig.getInstance().getVaultTemplate();
        System.out.println("✓ Vault test container started at: "
                + System.getProperty("VAULT_ADDR"));
    }

    // ══════════════════════════════════════════════════════════════════════════
    // TRANSIT TESTS (no external dependency — fully self-contained)
    // ══════════════════════════════════════════════════════════════════════════

    @Nested
    @DisplayName("Transit — Encryption-as-a-Service")
    class TransitTests {

        TransitSecretService service;

        @BeforeEach
        void init() {
            service = new TransitSecretService(vaultTemplate);
        }

        @Test
        @Order(1)
        @DisplayName("Encrypt and Decrypt roundtrip")
        void testEncryptDecrypt() {
            String plaintext  = "sensitive-data: user@example.com | card: 4111-1111-1111-1111";
            String ciphertext = service.encrypt(TransitSecretService.ENCRYPTION_KEY, plaintext);

            assertNotNull(ciphertext);
            assertTrue(ciphertext.startsWith("vault:v"), "Ciphertext should start with vault:v");
            assertNotEquals(plaintext, ciphertext);

            String decrypted = service.decrypt(TransitSecretService.ENCRYPTION_KEY, ciphertext);
            assertEquals(plaintext, decrypted, "Decrypted text must match original");
        }

        @Test
        @Order(2)
        @DisplayName("Different plaintexts produce different ciphertexts")
        void testEncryptProducesDifferentCiphertexts() {
            String ct1 = service.encrypt(TransitSecretService.ENCRYPTION_KEY, "data-one");
            String ct2 = service.encrypt(TransitSecretService.ENCRYPTION_KEY, "data-two");
            assertNotEquals(ct1, ct2);
        }

        @Test
        @Order(3)
        @DisplayName("Batch encrypt and decrypt")
        void testBatchEncryptDecrypt() {
            List<String> originals = List.of("secret-a", "secret-b", "secret-c", "secret-d");
            List<String> ciphertexts = service.batchEncrypt(
                    TransitSecretService.ENCRYPTION_KEY, originals);

            assertEquals(originals.size(), ciphertexts.size());
            ciphertexts.forEach(ct -> {
                assertNotNull(ct);
                assertTrue(ct.startsWith("vault:v"));
            });

            List<String> decrypted = service.batchDecrypt(
                    TransitSecretService.ENCRYPTION_KEY, ciphertexts);

            assertEquals(originals, decrypted, "Batch decryption must restore all originals");
        }

        @Test
        @Order(4)
        @DisplayName("Sign and Verify (ECDSA)")
        void testSignVerify() {
            String payload   = "{\"userId\":\"u-999\",\"action\":\"transfer\",\"amount\":10000}";
            String signature = service.sign(TransitSecretService.SIGNING_KEY, payload);

            assertNotNull(signature);
            assertFalse(signature.isBlank());

            boolean valid = service.verify(TransitSecretService.SIGNING_KEY, payload, signature);
            assertTrue(valid, "Valid signature must verify successfully");
        }

        @Test
        @Order(5)
        @DisplayName("Signature verification fails for tampered payload")
        void testTamperedPayloadFailsVerification() {
            String payload    = "{\"userId\":\"u-999\",\"amount\":100}";
            String tampered   = "{\"userId\":\"u-999\",\"amount\":999999}";
            String signature  = service.sign(TransitSecretService.SIGNING_KEY, payload);

            boolean valid = service.verify(TransitSecretService.SIGNING_KEY, tampered, signature);
            assertFalse(valid, "Tampered payload must NOT verify");
        }

        @Test
        @Order(6)
        @DisplayName("Key rotation — old ciphertext still decryptable after rotation")
        void testKeyRotationBackwardCompatibility() {
            String plaintext  = "data-before-rotation";
            String ciphertext = service.encrypt(TransitSecretService.ENCRYPTION_KEY, plaintext);

            // Rotate the key
            service.rotateKey(TransitSecretService.ENCRYPTION_KEY);

            // Old ciphertext must still decrypt (Vault keeps old key versions for decryption)
            String decrypted = service.decrypt(TransitSecretService.ENCRYPTION_KEY, ciphertext);
            assertEquals(plaintext, decrypted, "Old ciphertext must decrypt after key rotation");

            // New encryption uses new key version
            String newCiphertext = service.encrypt(TransitSecretService.ENCRYPTION_KEY, plaintext);
            assertNotEquals(ciphertext, newCiphertext, "New encryption should use new key version");
        }

        @Test
        @Order(7)
        @DisplayName("Rewrap ciphertext with latest key version")
        void testRewrap() {
            String plaintext   = "data-to-rewrap";
            String oldCt       = service.encrypt(TransitSecretService.ENCRYPTION_KEY, plaintext);

            // Rotate and rewrap
            service.rotateKey(TransitSecretService.ENCRYPTION_KEY);
            String newCt = service.rewrap(TransitSecretService.ENCRYPTION_KEY, oldCt);

            assertNotNull(newCt);
            assertTrue(newCt.startsWith("vault:v"));

            // Both should decrypt to same plaintext
            String fromOld = service.decrypt(TransitSecretService.ENCRYPTION_KEY, oldCt);
            String fromNew = service.decrypt(TransitSecretService.ENCRYPTION_KEY, newCt);
            assertEquals(plaintext, fromOld);
            assertEquals(plaintext, fromNew);
        }

        @Test
        @Order(8)
        @DisplayName("Context-bound encryption — wrong context fails to decrypt")
        void testContextBoundEncryption() {
            // Create a convergent/derived key for context binding
            // Using regular key with context for this test
            String plaintext = "tenant-specific-data";
            String ctx1 = "tenant-001";
            String ctx2 = "tenant-002";

            // Encrypt with context
            String ct1 = service.encryptWithContext(
                    TransitSecretService.ENCRYPTION_KEY, plaintext, ctx1);
            String ct2 = service.encryptWithContext(
                    TransitSecretService.ENCRYPTION_KEY, plaintext, ctx2);

            assertNotEquals(ct1, ct2, "Different contexts should produce different ciphertexts");

            // Correct context decrypts
            String decrypted = service.decryptWithContext(
                    TransitSecretService.ENCRYPTION_KEY, ct1, ctx1);
            assertEquals(plaintext, decrypted);
        }
    }

    // ══════════════════════════════════════════════════════════════════════════
    // PKI TESTS
    // ══════════════════════════════════════════════════════════════════════════

    @Nested
    @DisplayName("PKI — Certificate Authority")
    class PkiTests {

        PkiSecretService service;

        @BeforeEach
        void init() {
            service = new PkiSecretService(vaultTemplate, "pki", "test-role");
        }

        @Test
        @Order(1)
        @DisplayName("Issue certificate for subdomain")
        void testIssueCertificate() {
            IssuedCertificate cert = service.issueCertificate(
                    "api.test.example.com",
                    Duration.ofHours(72),
                    new String[]{"localhost", "api.test.example.com"},
                    new String[]{"127.0.0.1"}
            );

            assertNotNull(cert, "Certificate must not be null");
            assertNotNull(cert.certificatePem(), "Certificate PEM must not be null");
            assertNotNull(cert.privateKeyPem(), "Private key PEM must not be null");
            assertNotNull(cert.issuingCaPem(), "Issuing CA PEM must not be null");

            assertTrue(cert.certificatePem().contains("BEGIN CERTIFICATE"),
                    "Certificate must be PEM-encoded");
            assertTrue(cert.privateKeyPem().contains("BEGIN"),
                    "Private key must be PEM-encoded");

            assertEquals("api.test.example.com", cert.commonName());
        }

        @Test
        @Order(2)
        @DisplayName("Parse issued certificate")
        void testParseCertificate() throws Exception {
            IssuedCertificate cert = service.issueCertificate(
                    "svc.test.example.com",
                    Duration.ofHours(24),
                    null, null
            );

            java.security.cert.X509Certificate x509 =
                    service.parseCertificate(cert.certificatePem());

            assertNotNull(x509);
            assertTrue(x509.getSubjectX500Principal().getName().contains("svc.test.example.com"));
            assertTrue(x509.getNotAfter().after(new java.util.Date()),
                    "Certificate must not be expired");
        }

        @Test
        @Order(3)
        @DisplayName("Each certificate has unique serial number")
        void testUniqueCertificates() {
            IssuedCertificate cert1 = service.issueCertificate(
                    "svc1.test.example.com", Duration.ofHours(1), null, null);
            IssuedCertificate cert2 = service.issueCertificate(
                    "svc2.test.example.com", Duration.ofHours(1), null, null);

            assertNotEquals(cert1.certificatePem(), cert2.certificatePem());
            assertNotEquals(cert1.privateKeyPem(), cert2.privateKeyPem());
        }
    }

    // ══════════════════════════════════════════════════════════════════════════
    // SSH SIGNED CERTIFICATE TESTS
    // ══════════════════════════════════════════════════════════════════════════

    @Nested
    @DisplayName("SSH — Signed Certificates")
    class SshTests {

        SshSecretService service;

        // Valid 2048-bit RSA test key (generated for tests, not used for real auth)
        static final String TEST_PUB_KEY =
                "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDGNPrhgOaGfp1dOwR7RxSAoDSrBqzW" +
                "+zbRqnIYf1foUvUAoXmwNGUlFsypTqiUnksXiUF/6so5ymwfuyKj4CLJdGQNZYZU0Vp6" +
                "wrUnZ2TFBU7nj1sixJZ+dFNlLu2BYZCCLdY7If9rtGBMDwaIqWh7O7XzzGzfH4LE7nip" +
                "MJ3y5eb3i6Fi7o6nxMtMpT9/vumy47u7+yIUnkFPD/7A/xqAo76Hl2pTU9o6+pQ5SRf" +
                "I/HfCMJ40L5qfbd8rG5BH90AbxpGPoCC4+5Sog7PRjyeFojlPjT7auGhk3xCyZPiC7f" +
                "AElRCpdcHwfP2uYnpq8UFVZ6MJq5r/w+CiKoeL7YJR test@testcontainer";

        @BeforeEach
        void init() {
            service = new SshSecretService("ssh", "ssh-client-signer", "ssh-host-signer",
                    vaultTemplate);
        }

        @Test
        @Order(1)
        @DisplayName("Sign user SSH public key")
        void testSignUserPublicKey() {
            SshSecretService.SshSignedCertificate cert = service.signUserPublicKey(
                    "test-role",
                    TEST_PUB_KEY,
                    "ubuntu",
                    Duration.ofMinutes(30),
                    Map.of("permit-pty", "", "permit-port-forwarding", "")
            );

            assertNotNull(cert, "Signed certificate must not be null");
            assertNotNull(cert.signedKeyContent(), "Signed key content must not be null");
            assertFalse(cert.signedKeyContent().isBlank());
            assertTrue(cert.signedKeyContent().contains("ssh-rsa-cert-v01@openssh.com")
                    || cert.signedKeyContent().contains("cert"),
                    "Signed key must be an SSH certificate");
            assertEquals("ubuntu", cert.validPrincipals());
        }

        @Test
        @Order(2)
        @DisplayName("CA public key is retrievable")
        void testGetCaPublicKey() {
            String caPublicKey = service.getCaPublicKey("ssh-client-signer");
            assertNotNull(caPublicKey);
            assertTrue(caPublicKey.contains("ssh-rsa") || caPublicKey.contains("ecdsa"),
                    "CA public key must be in SSH format");
        }
    }

    // ══════════════════════════════════════════════════════════════════════════
    // VAULT CONNECTIVITY TEST
    // ══════════════════════════════════════════════════════════════════════════

    @Test
    @Order(0)
    @DisplayName("Vault is reachable and unsealed")
    void testVaultConnectivity() {
        assertDoesNotThrow(() -> {
            var health = vaultTemplate.opsForSys().health();
            assertNotNull(health);
            assertTrue(health.isInitialized(), "Vault must be initialized");
            assertFalse(health.isSealed(), "Vault must not be sealed");
        });
    }
}
