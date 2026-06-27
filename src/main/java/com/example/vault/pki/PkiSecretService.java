package com.example.vault.pki;

import com.example.vault.metrics.MetricsService;
import com.example.vault.model.IssuedCertificate;
import io.prometheus.client.Histogram;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.openssl.PEMParser;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.vault.core.VaultTemplate;
import org.springframework.vault.support.VaultCertificateRequest;
import org.springframework.vault.support.VaultCertificateResponse;

import java.io.*;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

/**
 * HashiCorp Vault — PKI (Certificate Authority) Secrets Engine
 * ─────────────────────────────────────────────────────────────
 * Vault acts as an internal CA. Issues X.509 TLS certificates
 * on demand with configurable TTLs. No manual CSR/signing process.
 *
 * Use Cases:
 *   - Internal service TLS (mTLS between microservices)
 *   - Short-lived certificates (replace with new ones vs revocation)
 *   - Automated cert lifecycle management
 *
 * Vault Setup (run once):
 * ──────────────────────
 *   # Enable PKI engine
 *   vault secrets enable pki
 *   vault secrets tune -max-lease-ttl=87600h pki
 *
 *   # Generate Root CA (self-signed)
 *   vault write -field=certificate pki/root/generate/internal \
 *       common_name="example.com" \
 *       ttl=87600h > root_ca.crt
 *
 *   # Configure CRL and Issuer URLs
 *   vault write pki/config/urls \
 *       issuing_certificates="http://vault:8200/v1/pki/ca" \
 *       crl_distribution_points="http://vault:8200/v1/pki/crl"
 *
 *   # Create an Intermediate CA (recommended for production)
 *   vault secrets enable -path=pki_int pki
 *   vault secrets tune -max-lease-ttl=43800h pki_int
 *   vault write pki_int/intermediate/generate/internal \
 *       common_name="example.com Intermediate" > int_csr.json
 *   vault write pki/root/sign-intermediate \
 *       csr=@int_csr.json format=pem_bundle ttl=43800h > int_cert.json
 *   vault write pki_int/intermediate/set-signed certificate=@int_cert.json
 *
 *   # Create Role (controls what certs can be issued)
 *   vault write pki_int/roles/example-dot-com \
 *       allowed_domains="example.com,internal.example.com" \
 *       allow_subdomains=true \
 *       allow_bare_domains=true \
 *       max_ttl=720h \
 *       key_type=rsa \
 *       key_bits=2048 \
 *       require_cn=true
 */
public class PkiSecretService {

    private static final Logger log = LoggerFactory.getLogger(PkiSecretService.class);

    private final VaultTemplate vaultTemplate;
    private final String pkiMountPath;   // e.g., "pki" or "pki_int"
    private final String roleName;       // e.g., "example-dot-com"

    public PkiSecretService(VaultTemplate vaultTemplate,
                            String pkiMountPath,
                            String roleName) {
        this.vaultTemplate = vaultTemplate;
        this.pkiMountPath  = pkiMountPath;
        this.roleName      = roleName;
    }

    // ── 1. Issue Certificate ───────────────────────────────────────────────────

    /**
     * Issues a new TLS certificate for the given common name.
     *
     * @param commonName  e.g., "myservice.internal.example.com"
     * @param ttl         Certificate lifetime (e.g., Duration.ofHours(72))
     * @param altNames    Optional Subject Alternative Names (SANs)
     * @param ipSans      Optional IP SANs
     * @return IssuedCertificate with cert PEM, private key PEM, CA chain PEM
     */
    public IssuedCertificate issueCertificate(String commonName,
                                               Duration ttl,
                                               String[] altNames,
                                               String[] ipSans) {
        log.info("Issuing certificate: CN={}, TTL={}h", commonName, ttl.toHours());
        Histogram.Timer timer = MetricsService.startTimer("pki", "issue_certificate");
        try {
            VaultCertificateRequest.VaultCertificateRequestBuilder builder =
                    VaultCertificateRequest.builder()
                            .commonName(commonName)
                            .ttl(ttl);

            if (altNames != null && altNames.length > 0) {
                builder.altNames(java.util.List.of(altNames));
            }
            if (ipSans != null && ipSans.length > 0) {
                builder.ipSubjectAltNames(java.util.List.of(ipSans));
            }

            VaultCertificateResponse response = vaultTemplate
                    .opsForPki(pkiMountPath)
                    .issueCertificate(roleName, builder.build());

            if (response == null || response.getData() == null) {
                throw new RuntimeException("No certificate returned from Vault");
            }

            var certData = response.getData();

            IssuedCertificate cert = new IssuedCertificate(
                    commonName,
                    certData.getCertificate(),
                    certData.getPrivateKey(),
                    certData.getIssuingCaCertificate(),
                    "",
                    response.getLeaseId(),
                    response.getLeaseDuration()
            );

            MetricsService.PKI_CERT_TTL.labels(roleName).set(response.getLeaseDuration());
            MetricsService.recordSuccess("pki", "issue_certificate");
            log.info("Certificate issued → serial={}, lease_id={}",
                    extractSerialNumber(cert.certificatePem()),
                    cert.leaseId());

            return cert;
        } catch (Exception e) {
            MetricsService.recordError("pki", "issue_certificate");
            throw e;
        } finally {
            timer.observeDuration();
        }
    }

    // ── 2. Sign a CSR (externally generated) ──────────────────────────────────

    /**
     * Signs an externally-provided CSR using the Vault PKI engine.
     * Useful when the private key must never leave the requesting system.
     *
     * @param csrPem  PEM-encoded Certificate Signing Request
     * @param ttl     Requested TTL (subject to role max_ttl)
     * @return Signed certificate PEM
     */
    public String signCsr(String csrPem, String commonName, Duration ttl) {
        log.info("Signing CSR for CN={}", commonName);

        Map<String, Object> request = new HashMap<>();
        request.put("csr", csrPem);
        request.put("common_name", commonName);
        request.put("ttl", ttl.toHours() + "h");
        request.put("format", "pem");

        var response = vaultTemplate.write(
                pkiMountPath + "/sign/" + roleName, request);

        if (response == null || response.getData() == null) {
            throw new RuntimeException("CSR signing failed");
        }

        String signedCert = (String) response.getData().get("certificate");
        log.info("CSR signed successfully for CN={}", commonName);
        return signedCert;
    }

    // ── 3. Revoke Certificate ─────────────────────────────────────────────────

    /**
     * Revokes a certificate by serial number.
     * Certificate will appear in the CRL within the CRL rotation interval.
     *
     * @param serialNumber Certificate serial (colon-separated hex, e.g., "1a:2b:3c:...")
     */
    public void revokeCertificate(String serialNumber) {
        log.info("Revoking certificate: {}", serialNumber);
        Histogram.Timer timer = MetricsService.startTimer("pki", "revoke_certificate");
        try {
            Map<String, Object> request = new HashMap<>();
            request.put("serial_number", serialNumber);

            var response = vaultTemplate.write(pkiMountPath + "/revoke", request);
            MetricsService.recordSuccess("pki", "revoke_certificate");
            if (response != null && response.getData() != null) {
                Object revokedAt = response.getData().get("revocation_time");
                log.info("Certificate revoked at: {}", revokedAt);
            }
        } catch (Exception e) {
            MetricsService.recordError("pki", "revoke_certificate");
            throw e;
        } finally {
            timer.observeDuration();
        }
    }

    // ── 4. Save Certificate to Files ──────────────────────────────────────────

    /**
     * Writes cert, key, and CA chain to PEM files.
     * Used for applications that load TLS certs from disk.
     *
     * @param cert      Issued certificate
     * @param directory Target directory
     */
    public void saveCertificateToFiles(IssuedCertificate cert, Path directory) throws IOException {
        Files.createDirectories(directory);

        Path certFile  = directory.resolve("tls.crt");
        Path keyFile   = directory.resolve("tls.key");
        Path caFile    = directory.resolve("ca.crt");
        Path chainFile = directory.resolve("chain.pem");

        Files.writeString(certFile,  cert.certificatePem());
        Files.writeString(keyFile,   cert.privateKeyPem());
        Files.writeString(caFile,    cert.issuingCaPem());
        if (!cert.caChainPem().isBlank()) {
            Files.writeString(chainFile, cert.caChainPem());
        }

        // Restrict private key permissions (Unix)
        try {
            Runtime.getRuntime().exec(new String[]{"chmod", "600", keyFile.toString()});
        } catch (Exception ignored) {}

        log.info("Certificate files written to: {}", directory);
        log.info("  tls.crt : {}", certFile);
        log.info("  tls.key : {} (restricted)", keyFile);
        log.info("  ca.crt  : {}", caFile);
    }

    // ── 5. Parse and Inspect Certificate ─────────────────────────────────────

    /**
     * Parses the PEM certificate and returns an X509Certificate object
     * for inspection (expiry dates, SANs, etc.).
     */
    public X509Certificate parseCertificate(String pemCert) throws Exception {
        try (PEMParser parser = new PEMParser(new StringReader(pemCert))) {
            Object obj = parser.readObject();
            if (obj instanceof X509CertificateHolder holder) {
                return new JcaX509CertificateConverter().getCertificate(holder);
            }
        }
        // Fallback: standard Java parsing
        byte[] derBytes = Base64.getDecoder().decode(
                pemCert.replace("-----BEGIN CERTIFICATE-----", "")
                       .replace("-----END CERTIFICATE-----", "")
                       .replaceAll("\\s", ""));
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        return (X509Certificate) cf.generateCertificate(
                new ByteArrayInputStream(derBytes));
    }

    // ── 6. Demo ────────────────────────────────────────────────────────────────

    public void runDemo() {
        System.out.println("\n══════════════ PKI Secrets Engine Demo ══════════════");

        // Issue a certificate for a microservice
        IssuedCertificate cert = issueCertificate(
                "api.internal.example.com",
                Duration.ofHours(72),
                new String[]{"api.example.com", "localhost"},
                new String[]{"127.0.0.1", "10.0.0.5"}
        );

        System.out.printf("""
            ┌─ Issued Certificate ────────────────────────────────┐
            │  Common Name  : %-34s │
            │  Lease ID     : %-34s │
            │  TTL          : %-30ds │
            │  Cert Preview : %-34s │
            │  Key Preview  : %-34s │
            │  Issuing CA   : %-34s │
            └─────────────────────────────────────────────────────┘
            %n""",
                cert.commonName(),
                cert.leaseId() != null
                        ? cert.leaseId().substring(0, Math.min(36, cert.leaseId().length()))
                        : "N/A",
                cert.leaseDurationSeconds(),
                cert.certificatePem().substring(0, Math.min(34, cert.certificatePem().length())),
                cert.privateKeyPem().substring(0, Math.min(34, cert.privateKeyPem().length())),
                cert.issuingCaPem().substring(0, Math.min(34, cert.issuingCaPem().length()))
        );

        // Parse and inspect
        try {
            X509Certificate x509 = parseCertificate(cert.certificatePem());
            System.out.println("  Certificate Details:");
            System.out.println("    Subject  : " + x509.getSubjectX500Principal());
            System.out.println("    Issuer   : " + x509.getIssuerX500Principal());
            System.out.println("    NotBefore: " + x509.getNotBefore());
            System.out.println("    NotAfter : " + x509.getNotAfter());
            System.out.println("    Serial   : " + x509.getSerialNumber().toString(16));
        } catch (Exception e) {
            log.debug("Certificate parsing demo (requires real Vault): {}", e.getMessage());
            System.out.println("  [Certificate parsing — connect to real Vault PKI]");
        }
    }

    // ── Helpers ────────────────────────────────────────────────────────────────

    private String extractSerialNumber(String pemCert) {
        try {
            X509Certificate cert = parseCertificate(pemCert);
            return cert.getSerialNumber().toString(16);
        } catch (Exception e) {
            return "unknown";
        }
    }
}
