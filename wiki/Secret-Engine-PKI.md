# Secret Engine: PKI (Certificate Authority)

**Class**: `com.example.vault.pki.PkiSecretService`

## What It Does

Vault acts as an internal Certificate Authority. It issues X.509 TLS certificates on demand with configurable TTLs. No manual CSR/signing workflow, no cert files to rotate by hand — the application requests a cert when it starts and renews by requesting a new one.

## CA Hierarchy

```
Root CA (mount: pki/)
    └── Intermediate CA (mount: pki_int/)
            └── Issues certs for *.example.com
                             *.internal.example.com
                             *.test.example.com
```

The intermediate CA is what applications interact with. The root CA's private key is used only to sign the intermediate CA.

## Vault Configuration

Run by `scripts/setup-all.sh`:

```bash
# Root CA
vault secrets enable pki
vault secrets tune -max-lease-ttl=87600h pki
vault write pki/root/generate/internal common_name="example.com Root CA" ttl=87600h

# Intermediate CA
vault secrets enable -path=pki_int pki
vault secrets tune -max-lease-ttl=43800h pki_int
# (CSR generated, signed by root CA, set as intermediate)

# Issuance role
vault write pki_int/roles/example-dot-com \
    allowed_domains="example.com,internal.example.com,test.example.com" \
    allow_subdomains=true \
    allow_bare_domains=true \
    max_ttl=720h \
    key_type=rsa \
    key_bits=2048 \
    server_flag=true \
    client_flag=true
```

## Java API

### Construct the service

```java
PkiSecretService pki = new PkiSecretService(
    vaultTemplate,
    "pki_int",         // mount path of the intermediate CA
    "example-dot-com"  // role name
);
```

### Issue a certificate

```java
IssuedCertificate cert = pki.issueCertificate(
    "api.internal.example.com",          // Common Name
    Duration.ofHours(72),                // TTL
    new String[]{"api.example.com", "localhost"},  // DNS SANs
    new String[]{"127.0.0.1", "10.0.0.5"}         // IP SANs
);

// cert.commonName()        → "api.internal.example.com"
// cert.certificatePem()    → "-----BEGIN CERTIFICATE-----..."
// cert.privateKeyPem()     → "-----BEGIN RSA PRIVATE KEY-----..."
// cert.issuingCaPem()      → "-----BEGIN CERTIFICATE-----..."
// cert.leaseId()           → Vault lease ID
// cert.leaseDurationSeconds() → 259200 (72h)
```

### Sign an externally-generated CSR

```java
String csrPem = Files.readString(Path.of("/path/to/request.csr"));

String signedCertPem = pki.signCsr(
    csrPem,
    "service.internal.example.com",
    Duration.ofHours(24)
);
```

Use this when the private key must never leave the requesting system (the CSR is generated locally and only the signing request is sent to Vault).

### Revoke a certificate

```java
// Serial number format: colon-separated hex (e.g., "1a:2b:3c:4d:...")
pki.revokeCertificate("1a:2b:3c:4d:5e:6f");
// Certificate appears in CRL at the next CRL rotation
```

### Save certificate to files

```java
pki.saveCertificateToFiles(cert, Path.of("/etc/app/tls"));
// Writes:
//   /etc/app/tls/tls.crt   — certificate
//   /etc/app/tls/tls.key   — private key (chmod 600)
//   /etc/app/tls/ca.crt    — issuing CA cert
//   /etc/app/tls/chain.pem — full CA chain (if present)
```

### Parse and inspect a certificate

```java
X509Certificate x509 = pki.parseCertificate(cert.certificatePem());

x509.getSubjectX500Principal()   // CN=api.internal.example.com
x509.getIssuerX500Principal()    // CN=example.com Intermediate CA
x509.getNotBefore()              // issue time
x509.getNotAfter()               // expiry time
x509.getSerialNumber()           // BigInteger serial
```

Uses BouncyCastle (`bcpkix-jdk18on`) for PEM parsing, with a JDK `CertificateFactory` fallback.

## IssuedCertificate Record

```java
public record IssuedCertificate(
    String commonName,
    String certificatePem,    // tls.crt
    String privateKeyPem,     // tls.key — SENSITIVE
    String issuingCaPem,      // ca.crt
    String caChainPem,        // chain.pem
    String leaseId,
    long   leaseDurationSeconds
) {
    public String summary()   // never exposes private key
    // toString() delegates to summary()
}
```

## Vault Paths

| Operation | HTTP | Vault Path |
|-----------|------|------------|
| Issue certificate | `POST` | `pki_int/issue/example-dot-com` |
| Sign CSR | `POST` | `pki_int/sign/example-dot-com` |
| Revoke certificate | `POST` | `pki_int/revoke` |
| Get CRL | `GET` | `pki_int/crl` (unauthenticated) |

## Policy Requirements

```hcl
path "pki_int/issue/example-dot-com" { capabilities = ["create", "update"] }
path "pki_int/sign/example-dot-com"  { capabilities = ["create", "update"] }
path "pki_int/revoke"                { capabilities = ["create", "update"] }
```

## Certificate Rotation Strategy

Short-lived certs (≤72h) make revocation less critical — you can simply let them expire. For longer TTLs, use `revokeCertificate()` and rely on CRL or OCSP.

Typical patterns:
- **Microservices**: issue 24h–72h certs at startup, restart to rotate
- **CI/CD pipelines**: issue 1h cert per job, let it expire
- **Long-running services**: set up a background thread that calls `issueCertificate()` ~1h before expiry
