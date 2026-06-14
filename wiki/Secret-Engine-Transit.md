# Secret Engine: Transit (Encryption-as-a-Service)

**Class**: `com.example.vault.transit.TransitSecretService`

## What It Does

Vault handles all cryptographic operations. The application sends plaintext to Vault and receives ciphertext back. Private keys **never leave Vault**. Ciphertext carries a version tag (`v3`) so old ciphertexts remain decryptable after key rotation.

## Keys Configured

| Constant | Key Name | Algorithm | Use Case |
|----------|----------|-----------|----------|
| `ENCRYPTION_KEY` | `app-encryption` | AES-256-GCM96 | Symmetric encrypt/decrypt |
| `SIGNING_KEY` | `app-signing` | ECDSA P-256 | Digital signatures |
| `RSA_KEY` | `app-rsa` | RSA-4096 | RSA signing |
| `HMAC_KEY` | `app-hmac` | HMAC-SHA256 | Message authentication |

## Vault Configuration

```bash
vault secrets enable transit

vault write -f transit/keys/app-encryption           # AES-256-GCM
vault write transit/keys/app-signing type=ecdsa-p256 # ECDSA
vault write transit/keys/app-rsa     type=rsa-4096   # RSA
vault write -f transit/keys/app-hmac                 # HMAC

# Rotation policy (optional)
vault write transit/keys/app-encryption/config \
    min_decryption_version=1 \
    min_encryption_version=0 \
    deletion_allowed=false
```

## Java API

### Construct the service

```java
TransitSecretService transit = new TransitSecretService(vaultTemplate);
// Internally creates VaultTransitOperations via vaultTemplate.opsForTransit()
```

### Encrypt / Decrypt

```java
String ciphertext = transit.encrypt("app-encryption", "4111-1111-1111-1111");
// → "vault:v1:8SDd3WHDOjf7mq69CkisfDy6ec2..."

String plaintext = transit.decrypt("app-encryption", ciphertext);
// → "4111-1111-1111-1111"
```

Plaintext is automatically base64-encoded by `Plaintext.of(string)` before the API call.

### Context-bound encryption

```java
// Bind ciphertext to a specific tenant or user — cannot decrypt without the same context
String ciphertext = transit.encryptWithContext("app-encryption", "secret", "tenant-id-42");
String plaintext  = transit.decryptWithContext("app-encryption", ciphertext, "tenant-id-42");
```

The key must be configured with `derived=true` in Vault for context-based derivation.

### Batch encrypt / decrypt

```java
List<String> records = List.of("SSN:123-45-6789", "SSN:987-65-4321", "SSN:555-12-3456");

List<String> ciphertexts = transit.batchEncrypt("app-encryption", records);
// Single API call to Vault regardless of list size

List<String> plaintexts = transit.batchDecrypt("app-encryption", ciphertexts);
```

Use batch operations for bulk processing (e.g., migrating a database column). Null entries in the result indicate per-item errors.

### Sign / Verify

```java
String payload   = "{\"userId\":\"u-1234\",\"action\":\"transfer\",\"amount\":5000}";
String signature = transit.sign("app-signing", payload);
// → "vault:v1:MEQCIHKr..."

boolean valid = transit.verify("app-signing", payload, signature);
// → true
```

Works with ECDSA P-256 and RSA keys. The private key never leaves Vault.

### HMAC

```java
String hmacValue = transit.hmac("app-hmac", "message body");
// → "vault:v1:base64encodedhmac..."

boolean ok = transit.verifyHmac("app-hmac", "message body", hmacValue);
// → true
```

Useful for webhook signature verification and API request authentication.

### Key rotation

```java
transit.rotateKey("app-encryption");
// Vault creates key version N+1
// New encryptions use v(N+1)
// Old ciphertexts (v1, v2, ...) still decrypt normally
```

### Rewrap (upgrade ciphertext to latest key version)

```java
// After rotation, rewrap old ciphertexts to use the latest key version
String newCiphertext = transit.rewrap("app-encryption", oldCiphertext);
// oldCiphertext: "vault:v1:..." → newCiphertext: "vault:v3:..."
// No plaintext is exposed during rewrap
```

Run rewrap as a background job after rotation to upgrade all stored ciphertexts. Once all ciphertexts are on the latest version, you can raise `min_decryption_version` to prevent decryption with old key versions.

### Envelope encryption (data keys)

```java
Map<String, String> dek = transit.generateDataKey("app-encryption", 256);

String plaintextKey  = dek.get("plaintext");   // base64 raw AES-256 key — use then discard
String ciphertextKey = dek.get("ciphertext");  // vault:v1:... — store this in your DB

// Later, to decrypt data:
// 1. Retrieve ciphertextKey from DB
// 2. Decrypt it via Vault: transit.decrypt("app-encryption", ciphertextKey)
// 3. Use the resulting plaintextKey to decrypt large data locally
```

Use envelope encryption when the data being encrypted is large (files, blobs). Vault only handles the small DEK; the bulk data is encrypted locally with AES.

### Hash

```java
String hexHash = transit.hash("my data", "sha2-256");
// Supported algorithms: sha2-256, sha2-512, sha3-256, sha3-512
```

### Random bytes

```java
String base64Bytes = transit.generateRandomBytes(32);
// 32 cryptographically secure random bytes from Vault's entropy source
```

## Ciphertext Format

```
vault:v{version}:{base64-encoded-ciphertext}

Examples:
  vault:v1:8SDd3WHDOjf7mq69Ck...    ← encrypted with key version 1
  vault:v3:KSDd3WHDOjf7mq69Ck...    ← encrypted with key version 3 (after 2 rotations)
```

The version prefix lets Vault know which key version to use for decryption.

## Vault Paths

| Operation | HTTP | Vault Path |
|-----------|------|------------|
| Encrypt | `POST` | `transit/encrypt/{key}` |
| Decrypt | `POST` | `transit/decrypt/{key}` |
| Sign | `POST` | `transit/sign/{key}` |
| Verify | `POST` | `transit/verify/{key}` |
| HMAC | `POST` | `transit/hmac/{key}` |
| Rotate key | `POST` | `transit/keys/{key}/rotate` |
| Rewrap | `POST` | `transit/rewrap/{key}` |
| Generate data key | `POST` | `transit/datakey/plaintext/{key}` |
| Hash | `POST` | `transit/hash/{algorithm}` |
| Random bytes | `POST` | `transit/random/{n}` |

## Policy Requirements

```hcl
path "transit/encrypt/app-encryption"             { capabilities = ["create", "update"] }
path "transit/decrypt/app-encryption"             { capabilities = ["create", "update"] }
path "transit/sign/app-signing"                   { capabilities = ["create", "update"] }
path "transit/verify/app-signing"                 { capabilities = ["create", "update"] }
path "transit/rewrap/app-encryption"              { capabilities = ["create", "update"] }
path "transit/hmac/app-hmac"                      { capabilities = ["create", "update"] }
path "transit/datakey/plaintext/app-encryption"   { capabilities = ["create", "update"] }
```
