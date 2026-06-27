# Java API Reference

## MetricsService

**Package**: `com.example.vault.metrics`

Thread-safe singleton. Registers all Prometheus metrics at class-load and starts an embedded HTTP server on `METRICS_PORT` (default `8080`).

```java
// Get singleton instance (initializes port from METRICS_PORT env var)
MetricsService metrics = MetricsService.getInstance();

// Start /metrics HTTP server (non-daemon; keeps JVM alive after main() returns)
metrics.startServer();

// Query the configured port
int port = metrics.getPort();   // default: 8080

// ── Static instrumentation helpers ──────────────────────────────────────────

// Start a latency timer for an operation
Histogram.Timer timer = MetricsService.startTimer(String engine, String operation);
// ... call Vault ...
timer.observeDuration();   // always call in finally block

// Increment the operations counter — call after the Vault call succeeds
MetricsService.recordSuccess(String engine, String operation);

// Increment the error counter — call in catch block
MetricsService.recordError(String engine, String operation);

// ── Metric instances (static, pre-registered) ────────────────────────────────

Counter   MetricsService.VAULT_OPERATIONS            // labels: engine, operation, status
Histogram MetricsService.VAULT_OPERATION_DURATION    // labels: engine, operation
Counter   MetricsService.TRANSIT_KEY_ROTATIONS       // labels: key
Gauge     MetricsService.DB_CREDENTIAL_TTL           // labels: role
Gauge     MetricsService.PKI_CERT_TTL                // labels: role
Gauge     MetricsService.SSH_CERT_TTL                // labels: principals
```

Typical usage pattern inside a service method:

```java
Histogram.Timer timer = MetricsService.startTimer("transit", "encrypt");
try {
    String result = transitOps.encrypt(keyName, plaintext);
    MetricsService.recordSuccess("transit", "encrypt");
    return result;
} catch (Exception e) {
    MetricsService.recordError("transit", "encrypt");
    throw e;
} finally {
    timer.observeDuration();
}
```

See [Monitoring](Monitoring.md) for PromQL examples and the full metrics reference.

---

## VaultConfig

**Package**: `com.example.vault.config`

```java
// Singleton access
VaultConfig config = VaultConfig.getInstance();

// Health check (throws RuntimeException if sealed or unreachable)
config.verifyConnectivity();

// Get the shared VaultTemplate
VaultTemplate vaultTemplate = config.getVaultTemplate();

// Accessors
String addr  = config.getVaultAddr();   // e.g. "http://127.0.0.1:8201"
String token = config.getVaultToken();  // e.g. "root"
```

## AppRoleVaultConfig

**Package**: `com.example.vault.config`

Requires `VAULT_ROLE_ID` and `VAULT_SECRET_ID` environment variables.

```java
AppRoleVaultConfig config = new AppRoleVaultConfig();
VaultTemplate vaultTemplate = config.buildVaultTemplate();

// Print Vault CLI setup instructions to stdout
AppRoleVaultConfig.printSetupInstructions();
```

## DynamicDatabaseSecretService

**Package**: `com.example.vault.db`

```java
DynamicDatabaseSecretService service = new DynamicDatabaseSecretService(
    vaultTemplate,
    "localhost",   // DB_HOST
    "5432",        // DB_PORT
    "mydb"         // DB_NAME
);

// Fetch a single credential set
DatabaseCredential cred = service.getDynamicCredentials(String role);

// Build a HikariCP connection pool from a credential
HikariDataSource ds = service.buildDataSource(DatabaseCredential cred);

// Start background auto-renewal; swaps DataSource atomically on renewal
service.setupAutoRenewal(String role, AtomicReference<HikariDataSource> dsHolder);

// Revoke a lease explicitly (drops DB user immediately)
service.revokeLease(DatabaseCredential cred);

// End-to-end demo: fetch cred → build pool → run query → revoke
service.runDemo(String role);
```

## DatabaseCredential

**Package**: `com.example.vault.model`

```java
record DatabaseCredential(
    String username,             // "v-token-readonly-abc123"
    String password,             // Vault-generated password
    String leaseId,              // "database/creds/readonly/..."
    long   leaseDurationSeconds, // e.g. 3600
    String role                  // "readonly" or "readwrite"
)

// Check if TTL is nearly exhausted
boolean nearExpiry = cred.isNearExpiry(thresholdSeconds, issuedAtEpochSeconds);
```

## PkiSecretService

**Package**: `com.example.vault.pki`

```java
PkiSecretService pki = new PkiSecretService(
    vaultTemplate,
    "pki_int",         // PKI mount path
    "example-dot-com"  // role name
);

// Issue a new certificate
IssuedCertificate cert = pki.issueCertificate(
    String commonName,
    Duration ttl,
    String[] altNames,   // DNS SANs (nullable)
    String[] ipSans      // IP SANs (nullable)
);

// Sign an externally-generated CSR
String signedCertPem = pki.signCsr(String csrPem, String commonName, Duration ttl);

// Revoke by serial number (colon-separated hex)
pki.revokeCertificate(String serialNumber);

// Write cert, key, and CA chain to PEM files
pki.saveCertificateToFiles(IssuedCertificate cert, Path directory) throws IOException;

// Parse PEM into X509Certificate
X509Certificate x509 = pki.parseCertificate(String pemCert) throws Exception;

// Run interactive demo
pki.runDemo();
```

## IssuedCertificate

**Package**: `com.example.vault.model`

```java
record IssuedCertificate(
    String commonName,
    String certificatePem,       // tls.crt
    String privateKeyPem,        // tls.key — SENSITIVE
    String issuingCaPem,         // ca.crt
    String caChainPem,           // chain.pem
    String leaseId,
    long   leaseDurationSeconds
)

String summary = cert.summary();   // never exposes private key
// toString() delegates to summary()
```

## TransitSecretService

**Package**: `com.example.vault.transit`

```java
TransitSecretService transit = new TransitSecretService(vaultTemplate);

// Constants
TransitSecretService.ENCRYPTION_KEY  // "app-encryption"
TransitSecretService.SIGNING_KEY     // "app-signing"
TransitSecretService.RSA_KEY         // "app-rsa"
TransitSecretService.HMAC_KEY        // "app-hmac"

// Encrypt / Decrypt
String ciphertext = transit.encrypt(String keyName, String plaintext);
String plaintext  = transit.decrypt(String keyName, String ciphertext);

// Context-bound encrypt / decrypt
String ct = transit.encryptWithContext(String keyName, String plaintext, String context);
String pt = transit.decryptWithContext(String keyName, String ciphertext, String context);

// Batch operations (single API call)
List<String> ciphertexts = transit.batchEncrypt(String keyName, List<String> plaintexts);
List<String> plaintexts  = transit.batchDecrypt(String keyName, List<String> ciphertexts);

// Sign / Verify
String  signature = transit.sign(String keyName, String data);
boolean valid     = transit.verify(String keyName, String data, String signature);

// HMAC
String  hmacValue = transit.hmac(String keyName, String data);
boolean ok        = transit.verifyHmac(String keyName, String data, String hmacValue);

// Key rotation
transit.rotateKey(String keyName);

// Rewrap ciphertext with latest key version
String newCiphertext = transit.rewrap(String keyName, String ciphertext);

// Envelope encryption (data key generation)
// Returns Map with "plaintext" (base64) and "ciphertext" (vault:v{n}:...)
Map<String, String> dek = transit.generateDataKey(String keyName, int bits);

// Hash (algorithm: sha2-256, sha2-512, sha3-256, sha3-512)
String hexHash = transit.hash(String data, String algorithm);

// CSPRNG random bytes
String base64Bytes = transit.generateRandomBytes(int numBytes);

// Run interactive demo
transit.runDemo();
```

## SshSecretService

**Package**: `com.example.vault.ssh`

```java
// Default mount paths: ssh, ssh-client-signer, ssh-host-signer
SshSecretService ssh = new SshSecretService(vaultTemplate);

// Custom mount paths
SshSecretService ssh = new SshSecretService(
    String otpMountPath,
    String clientSignerMountPath,
    String hostSignerMountPath,
    vaultTemplate
);

// OTP
SshOtpCredential otp = ssh.generateOtp(String roleName, String username, String targetIp);
boolean valid         = ssh.verifyOtp(String otp, String username, String ip);

// Signed client certificate
SshSignedCertificate cert = ssh.signUserPublicKey(
    String roleName,
    String sshPublicKeyPem,
    String validPrincipals,       // comma-separated: "ubuntu,ec2-user"
    Duration ttl,
    Map<String, String> extensions  // SSH extensions, e.g. {"permit-pty": ""}
);

// Signed host certificate
SshSignedCertificate hostCert = ssh.signHostPublicKey(
    String roleName,
    String hostPublicKey,
    String hostnames,             // comma-separated: "server1.example.com,server1"
    Duration ttl
);

// Get CA public key (install on SSH servers)
String caPubKey = ssh.getCaPublicKey(String mountPath);

// Save signed certificate to ~/.ssh/{keyBasename}-cert.pub
ssh.saveCertificate(SshSignedCertificate cert, Path sshDir, String keyBasename) throws IOException;

// Run interactive demo
ssh.runDemo();
```

### Inner Records in SshSecretService

```java
record SshOtpCredential(
    String otp,
    String keyType,               // "otp"
    String username,
    String targetIp,
    String port,
    String leaseId,
    long   leaseDurationSeconds
) {}

record SshSignedCertificate(
    String   signedKeyContent,    // full cert content for ~/.ssh/id_rsa-cert.pub
    String   serialNumber,
    String   validPrincipals,
    Duration ttl,
    String   leaseId
) {}
```
