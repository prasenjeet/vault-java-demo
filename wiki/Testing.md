# Testing

## Overview

Integration tests in `src/test/java/com/example/vault/VaultIntegrationTest.java` use **Testcontainers** to spin up a real HashiCorp Vault container. No mocking — every test hits an actual Vault instance. Docker must be running.

```bash
mvn test
```

## Test Setup

`VaultIntegrationTest` uses JUnit 5 with `@Testcontainers`. A static `VaultContainer` field is annotated with `@Container`, so Testcontainers manages the full lifecycle (start before all tests, stop after all tests).

```java
static final VaultContainer<?> vault = new VaultContainer<>("hashicorp/vault:latest")
    .withVaultToken(ROOT_TOKEN)
    .withEnv("SKIP_SETCAP", "true")
    .withEnv("VAULT_LOCAL_CONFIG", "{\"disable_mlock\":true,\"ui\":false}")
    .withInitCommand(
        "secrets enable database",
        "secrets enable pki",
        // ... all engine setup commands
    );
```

`SKIP_SETCAP=true` and `disable_mlock=true` allow the container to run in restricted Docker environments (no `CAP_IPC_LOCK` capability required).

`@BeforeAll` wires the container URL into `VaultConfig`:
```java
System.setProperty("VAULT_ADDR", "http://" + vault.getHost() + ":" + vault.getFirstMappedPort());
System.setProperty("VAULT_TOKEN", ROOT_TOKEN);
vaultTemplate = VaultConfig.getInstance().getVaultTemplate();
```

## Test Classes

Tests are organized as `@Nested` inner classes, ordered with `@TestMethodOrder(MethodOrderer.OrderAnnotation.class)`.

### Vault connectivity test (order 0)
```java
@Test void testVaultConnectivity()
```
Verifies the container started correctly: `health.isInitialized()` and `!health.isSealed()`.

### TransitTests (nested)

| Test | What It Verifies |
|------|-----------------|
| `testEncryptDecrypt` | Roundtrip: encrypt → decrypt equals original |
| `testEncryptProducesDifferentCiphertexts` | Distinct plaintexts → distinct ciphertexts |
| `testBatchEncryptDecrypt` | Single API call encrypts and decrypts 4 items |
| `testSignVerify` | ECDSA signature verifies against original payload |
| `testTamperedPayloadFailsVerification` | Modified payload does NOT verify |
| `testKeyRotationBackwardCompatibility` | Old ciphertext still decrypts after key rotation |
| `testRewrap` | Rewrapped ciphertext decrypts to same plaintext |
| `testContextBoundEncryption` | Different contexts produce different ciphertexts |

### PkiTests (nested)

| Test | What It Verifies |
|------|-----------------|
| `testIssueCertificate` | PEM fields non-null, correct CN, PEM headers present |
| `testParseCertificate` | X509Certificate subject matches CN, not expired |
| `testUniqueCertificates` | Two issuances produce different cert+key PEMs |

Uses the `pki/` mount (Root CA directly) with role `test-role`. In the demo application, `pki_int/` is used.

### SshTests (nested)

| Test | What It Verifies |
|------|-----------------|
| `testSignUserPublicKey` | Signed cert content is non-null, is an SSH cert |
| `testGetCaPublicKey` | CA pub key contains `ssh-rsa` or `ecdsa` |

Note: OTP tests are not included because OTP mode requires `vault-ssh-helper` on the server, which is not testable in unit isolation.

## What Is Not Tested

- **Database engine** — Requires a live PostgreSQL instance with a `vault_root` user that has `CREATE ROLE` privileges. Testcontainers could add a PostgreSQL container, but it is not yet wired in.
- **SSH OTP verification** — Server-side; requires `vault-ssh-helper` running on the target host.
- **AppRole auth** — `VaultConfig` uses token auth; `AppRoleVaultConfig` is used in production but not in the test suite.
- **Lease auto-renewal** — `setupAutoRenewal()` in `DynamicDatabaseSecretService` requires a background thread and a real DB; not tested here.

## Running Specific Tests

```bash
# Run only Transit tests
mvn test -Dtest="VaultIntegrationTest\$TransitTests"

# Run only PKI tests
mvn test -Dtest="VaultIntegrationTest\$PkiTests"

# Run only SSH tests
mvn test -Dtest="VaultIntegrationTest\$SshTests"

# Run connectivity check only
mvn test -Dtest="VaultIntegrationTest#testVaultConnectivity"
```

## Test Dependencies

| Library | Purpose |
|---------|---------|
| `testcontainers:vault` | Manages `hashicorp/vault` Docker container lifecycle |
| `testcontainers:junit-jupiter` | `@Testcontainers` and `@Container` annotations |
| `testcontainers:postgresql` | Available for future DB tests |
| `junit-jupiter` | Test framework |
| `mockito-core` | Available for unit test mocking (not used in integration tests) |
