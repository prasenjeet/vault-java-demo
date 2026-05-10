package com.example.vault.model;

/**
 * Represents an X.509 certificate issued by Vault's PKI engine.
 *
 * @param commonName          Certificate Common Name (CN)
 * @param certificatePem      PEM-encoded certificate (tls.crt)
 * @param privateKeyPem       PEM-encoded private key  (tls.key) — SENSITIVE
 * @param issuingCaPem        PEM-encoded issuing CA certificate (ca.crt)
 * @param caChainPem          PEM-encoded full CA chain (chain.pem)
 * @param leaseId             Vault lease ID
 * @param leaseDurationSeconds Lease TTL in seconds (matches cert validity)
 */
public record IssuedCertificate(
        String commonName,
        String certificatePem,
        String privateKeyPem,
        String issuingCaPem,
        String caChainPem,
        String leaseId,
        long   leaseDurationSeconds
) {
    /**
     * Returns a summary without exposing the private key.
     */
    public String summary() {
        return "IssuedCertificate{" +
                "cn='" + commonName + '\'' +
                ", ttlSeconds=" + leaseDurationSeconds +
                ", hasCert=" + (certificatePem != null && !certificatePem.isBlank()) +
                ", hasKey=" + (privateKeyPem != null && !privateKeyPem.isBlank()) +
                ", hasCA=" + (issuingCaPem != null && !issuingCaPem.isBlank()) +
                '}';
    }

    @Override
    public String toString() {
        // Never expose private key in toString()
        return summary();
    }
}
