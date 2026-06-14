# Secret Engine: SSH

**Class**: `com.example.vault.ssh.SshSecretService`

## What It Does

Vault provides two complementary modes for SSH access control:

- **OTP mode**: Vault issues a single-use password tied to a specific host and user. The password cannot be reused. Requires `vault-ssh-helper` on the target server.
- **Signed certificate mode**: Vault acts as an SSH CA. It signs a user's public key with a short TTL. Servers trust the Vault CA, not individual keys. No agent needed on servers.

## Vault Configuration

Three separate SSH mounts are configured by `scripts/setup-all.sh`:

| Mount | Mode | Purpose |
|-------|------|---------|
| `ssh` | OTP | Issues one-time passwords |
| `ssh-client-signer` | Signed cert | Signs user SSH public keys |
| `ssh-host-signer` | Signed cert | Signs server SSH host keys |

```bash
# OTP mode
vault secrets enable ssh
vault write ssh/roles/otp-role \
    key_type=otp \
    default_user=ubuntu \
    allowed_users="ubuntu,ec2-user,centos,admin" \
    cidr_list="0.0.0.0/0"

# Client certificate signing
vault secrets enable -path=ssh-client-signer ssh
vault write ssh-client-signer/config/ca generate_signing_key=true
vault write ssh-client-signer/roles/my-role \
    key_type=ca \
    allow_user_certificates=true \
    allowed_users="ubuntu,ec2-user,*" \
    ttl=30m0s \
    max_ttl=8h

# Host certificate signing
vault secrets enable -path=ssh-host-signer ssh
vault write ssh-host-signer/config/ca generate_signing_key=true
vault write ssh-host-signer/roles/host-role \
    key_type=ca \
    allow_host_certificates=true \
    allowed_domains="*.example.com,example.com" \
    ttl=87600h
```

## Java API

### Construct the service

```java
// Default mount paths: ssh, ssh-client-signer, ssh-host-signer
SshSecretService ssh = new SshSecretService(vaultTemplate);

// Custom mount paths
SshSecretService ssh = new SshSecretService(
    "ssh",                 // OTP mount
    "ssh-client-signer",  // client cert mount
    "ssh-host-signer",    // host cert mount
    vaultTemplate
);
```

## Mode 1: OTP

### Generate an OTP

```java
SshOtpCredential otp = ssh.generateOtp("otp-role", "ubuntu", "10.0.1.100");

otp.otp()                  // the one-time password (masked in logs)
otp.keyType()              // "otp"
otp.username()             // "ubuntu"
otp.targetIp()             // "10.0.1.100"
otp.port()                 // "22" (from role config)
otp.leaseId()              // Vault lease ID
otp.leaseDurationSeconds() // TTL in seconds
```

Then use it:
```bash
ssh -o PasswordAuthentication=yes ubuntu@10.0.1.100
# Enter the OTP when prompted
```

The OTP is consumed on first use. It cannot be used again.

### Verify an OTP (server-side)

```java
boolean valid = ssh.verifyOtp(otp.otp(), "ubuntu", "10.0.1.100");
```

This is the call `vault-ssh-helper` makes on the SSH server. It is exposed here for testing. Returns `false` if the OTP has already been used.

### Server Setup for OTP

Install `vault-ssh-helper` on target SSH servers and configure `/etc/vault-ssh-helper.d/config.hcl`:
```hcl
vault_addr  = "http://vault.example.com:8200"
ssh_mount_point = "ssh"
allowed_cidr_list = "0.0.0.0/0"
allowed_roles = "*"
```

Configure PAM to call `vault-ssh-helper` for authentication.

## Mode 2: Signed Certificates

### Sign a user's public key

```java
Map<String, String> extensions = new LinkedHashMap<>();
extensions.put("permit-pty",              "");
extensions.put("permit-port-forwarding",  "");
extensions.put("permit-agent-forwarding", "");

String publicKey = Files.readString(Path.of(System.getProperty("user.home") + "/.ssh/id_rsa.pub"));

SshSignedCertificate cert = ssh.signUserPublicKey(
    "my-role",
    publicKey,
    "ubuntu,ec2-user",      // valid principals (OS usernames)
    Duration.ofMinutes(30), // certificate TTL
    extensions
);

cert.signedKeyContent()   // "ssh-rsa-cert-v01@openssh.com ..." — save as id_rsa-cert.pub
cert.serialNumber()       // certificate serial number
cert.validPrincipals()    // "ubuntu,ec2-user"
cert.ttl()                // Duration.ofMinutes(30)
cert.leaseId()            // Vault lease ID
```

### Save the certificate

```java
ssh.saveCertificate(
    cert,
    Path.of(System.getProperty("user.home") + "/.ssh"),
    "id_rsa"   // key basename — cert saved as id_rsa-cert.pub
);
```

File is created with `chmod 600` (owner read/write only).

Then use it:
```bash
ssh ubuntu@10.0.1.100
# SSH automatically presents id_rsa + id_rsa-cert.pub
# No password required; certificate proves identity
# After 30 minutes, request a new certificate
```

### Sign a server's host key

```java
String hostPubKey = Files.readString(Path.of("/etc/ssh/ssh_host_rsa_key.pub"));

SshSignedCertificate hostCert = ssh.signHostPublicKey(
    "host-role",
    hostPubKey,
    "server1.example.com,server1",
    Duration.ofHours(87600)  // 10 years — host certs are long-lived
);
```

Install the signed cert on the server as `/etc/ssh/ssh_host_rsa_key-cert.pub` and add `HostCertificate /etc/ssh/ssh_host_rsa_key-cert.pub` to `sshd_config`. This eliminates the "Are you sure you want to continue connecting?" prompt for clients that trust the Vault CA.

### Get the CA public key (for server installation)

```java
String caPubKey = ssh.getCaPublicKey("ssh-client-signer");
// Install on each SSH server:
// echo caPubKey >> /etc/ssh/trusted-user-ca-keys.pem
// And in sshd_config: TrustedUserCAKeys /etc/ssh/trusted-user-ca-keys.pem
```

## Inner Record Types

```java
// OTP credential
record SshOtpCredential(
    String otp,
    String keyType,
    String username,
    String targetIp,
    String port,
    String leaseId,
    long   leaseDurationSeconds
) {}

// Signed certificate (client or host)
record SshSignedCertificate(
    String   signedKeyContent,   // full cert to write to ~.ssh/id_rsa-cert.pub
    String   serialNumber,
    String   validPrincipals,
    Duration ttl,
    String   leaseId
) {}
```

## Vault Paths

| Operation | HTTP | Vault Path |
|-----------|------|------------|
| Generate OTP | `POST` | `ssh/creds/{role}` |
| Verify OTP | `POST` | `ssh/verify` |
| Sign user public key | `POST` | `ssh-client-signer/sign/{role}` |
| Sign host public key | `POST` | `ssh-host-signer/sign/{role}` |
| Get client CA key | `GET` | `ssh-client-signer/config/ca` |
| Get host CA key | `GET` | `ssh-host-signer/config/ca` |

## Policy Requirements

```hcl
path "ssh/creds/otp-role"              { capabilities = ["create", "update"] }
path "ssh-client-signer/sign/my-role"  { capabilities = ["create", "update"] }
```

## OTP vs Signed Certificates

| | OTP | Signed Certificates |
|-|-----|---------------------|
| Server requirement | `vault-ssh-helper` on every server | Install CA public key in `sshd_config` |
| Client requirement | None (uses standard SSH password auth) | Standard SSH key pair |
| Traceability | Full audit log in Vault | Serial number in Vault audit log |
| Revocation | Not needed (single use) | Let short-TTL certs expire |
| Principals | Tied to specific IP at issuance | Principals in the cert |
| Recommended for | Legacy servers where key management is hard | New infrastructure |
