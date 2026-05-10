package com.example.vault.ssh;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.vault.core.VaultTemplate;
import org.springframework.vault.support.VaultResponse;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermission;
import java.time.Duration;
import java.util.*;

/**
 * HashiCorp Vault — SSH Secrets Engine
 * ──────────────────────────────────────
 * Two modes for securing SSH access:
 *
 * Mode 1: OTP (One-Time Password)
 *   - Vault issues a single-use password for a specific target host+user
 *   - sshd verifies the OTP against Vault via vault-ssh-helper
 *   - OTP is consumed on first use
 *   - No persistent credentials on the server
 *
 * Mode 2: Signed SSH Certificates (Recommended)
 *   - Vault acts as an SSH CA
 *   - Signs user's SSH public key with a short TTL
 *   - sshd trusts Vault's CA public key
 *   - No vault-ssh-helper required
 *   - Supports certificate principals, extensions, critical options
 *
 * Vault Setup — OTP Mode:
 * ───────────────────────
 *   vault secrets enable ssh
 *
 *   vault write ssh/roles/otp-role \
 *       key_type=otp \
 *       default_user=ubuntu \
 *       allowed_users="ubuntu,ec2-user,centos" \
 *       cidr_list="10.0.0.0/8,172.16.0.0/12"
 *
 *   # On the target SSH server, install vault-ssh-helper:
 *   # https://github.com/hashicorp/vault-ssh-helper
 *
 * Vault Setup — Signed Certificate Mode:
 * ───────────────────────────────────────
 *   vault secrets enable -path=ssh-client-signer ssh
 *
 *   # Generate CA key pair (Vault manages the private key)
 *   vault write ssh-client-signer/config/ca generate_signing_key=true
 *
 *   # Get public key to install on servers
 *   vault read -field=public_key ssh-client-signer/config/ca > trusted-user-ca-keys.pem
 *
 *   # On each SSH server, add to /etc/ssh/sshd_config:
 *   #   TrustedUserCAKeys /etc/ssh/trusted-user-ca-keys.pem
 *
 *   vault write ssh-client-signer/roles/my-role \
 *       algorithm_signer=rsa-sha2-256 \
 *       allow_user_certificates=true \
 *       allowed_users="ubuntu,ec2-user,*" \
 *       allowed_extensions="permit-pty,permit-port-forwarding" \
 *       default_extensions='{"permit-pty":""}' \
 *       key_type=ca \
 *       ttl=30m0s
 *
 *   # For host certificate signing (servers prove their identity to clients):
 *   vault secrets enable -path=ssh-host-signer ssh
 *   vault write ssh-host-signer/config/ca generate_signing_key=true
 *   vault write ssh-host-signer/roles/hostrole \
 *       key_type=ca \
 *       allow_host_certificates=true \
 *       allowed_domains="*.example.com,example.com" \
 *       allow_subdomains=true \
 *       ttl=87600h
 */
public class SshSecretService {

    private static final Logger log = LoggerFactory.getLogger(SshSecretService.class);

    private final VaultTemplate vaultTemplate;

    // Mount paths
    private final String otpMountPath;            // e.g., "ssh"
    private final String clientSignerMountPath;   // e.g., "ssh-client-signer"
    private final String hostSignerMountPath;     // e.g., "ssh-host-signer"

    public SshSecretService(VaultTemplate vaultTemplate) {
        this("ssh", "ssh-client-signer", "ssh-host-signer", vaultTemplate);
    }

    public SshSecretService(String otpMountPath,
                            String clientSignerMountPath,
                            String hostSignerMountPath,
                            VaultTemplate vaultTemplate) {
        this.vaultTemplate           = vaultTemplate;
        this.otpMountPath            = otpMountPath;
        this.clientSignerMountPath   = clientSignerMountPath;
        this.hostSignerMountPath     = hostSignerMountPath;
    }

    // ══════════════════════════════════════════════════════════════════════════
    // MODE 1: OTP (One-Time Password)
    // ══════════════════════════════════════════════════════════════════════════

    /**
     * Generates a one-time SSH password for a specific target host and user.
     * The password is valid for ONE login attempt only.
     *
     * @param roleName   Vault SSH OTP role (e.g., "otp-role")
     * @param username   Target OS user on the SSH server (e.g., "ubuntu")
     * @param targetIp   IP address of the target SSH server
     * @return OTP credential with password and metadata
     */
    public SshOtpCredential generateOtp(String roleName, String username, String targetIp) {
        log.info("Generating OTP for {}@{} via role: {}", username, targetIp, roleName);

        Map<String, Object> request = new HashMap<>();
        request.put("ip",       targetIp);
        request.put("username", username);

        VaultResponse response = vaultTemplate.write(
                otpMountPath + "/creds/" + roleName, request);

        if (response == null || response.getData() == null) {
            throw new RuntimeException("OTP generation failed — check role configuration");
        }

        Map<String, Object> data = response.getData();

        SshOtpCredential cred = new SshOtpCredential(
                (String) data.get("key"),           // The OTP
                (String) data.get("key_type"),       // "otp"
                username,
                targetIp,
                (String) data.get("port"),
                response.getLeaseId(),
                response.getLeaseDuration()
        );

        log.info("OTP issued → lease_id={}, user={}, host={}, ttl={}s",
                cred.leaseId(), cred.username(), cred.targetIp(), cred.leaseDurationSeconds());

        return cred;
    }

    /**
     * Verifies that a given OTP is valid against Vault.
     * This is called by vault-ssh-helper on the SSH server.
     * (Normally invoked server-side; exposed here for testing.)
     *
     * @param otp      The OTP to verify
     * @param username Username the OTP was issued for
     * @param ip       Client IP address
     * @return true if OTP is valid and not yet consumed
     */
    public boolean verifyOtp(String otp, String username, String ip) {
        log.info("Verifying OTP for {}@{}", username, ip);

        Map<String, Object> request = new HashMap<>();
        request.put("otp",      otp);

        VaultResponse response = vaultTemplate.write(
                otpMountPath + "/verify", request);

        if (response == null || response.getData() == null) {
            log.warn("OTP verification returned no data — invalid OTP");
            return false;
        }

        String message = (String) response.getData().get("message");
        boolean valid = "Verified".equalsIgnoreCase(message);
        log.info("OTP verification result: {}", valid ? "VALID" : "INVALID");
        return valid;
    }

    // ══════════════════════════════════════════════════════════════════════════
    // MODE 2: Signed SSH Certificates (Client)
    // ══════════════════════════════════════════════════════════════════════════

    /**
     * Signs a user's SSH public key using Vault's SSH CA.
     * The resulting certificate is used for passwordless SSH authentication.
     *
     * Flow:
     *   1. User generates SSH key pair locally (ssh-keygen)
     *   2. User submits public key to Vault
     *   3. Vault signs it with its CA private key (sets TTL, principals, extensions)
     *   4. User uses the signed certificate to SSH into servers
     *   5. Certificate expires after TTL — no revocation needed
     *
     * @param roleName        Vault SSH role (e.g., "my-role")
     * @param sshPublicKeyPem User's SSH public key (contents of ~/.ssh/id_rsa.pub)
     * @param validPrincipals Comma-separated list of usernames cert is valid for
     * @param ttl             Certificate lifetime (e.g., Duration.ofMinutes(30))
     * @param extensions      SSH extensions to grant (e.g., permit-pty)
     * @return Signed certificate (write to ~/.ssh/id_rsa-cert.pub)
     */
    public SshSignedCertificate signUserPublicKey(String roleName,
                                                   String sshPublicKeyPem,
                                                   String validPrincipals,
                                                   Duration ttl,
                                                   Map<String, String> extensions) {
        log.info("Signing SSH public key for principals='{}', ttl={}m",
                validPrincipals, ttl.toMinutes());

        Map<String, Object> request = new HashMap<>();
        request.put("public_key",        sshPublicKeyPem.trim());
        request.put("valid_principals",  validPrincipals);
        request.put("ttl",               ttl.toSeconds() + "s");

        if (extensions != null && !extensions.isEmpty()) {
            request.put("extensions", extensions);
        }

        // Optional: restrict to specific key IDs for audit
        request.put("key_id", "user-" + System.getProperty("user.name", "unknown")
                + "-" + System.currentTimeMillis());

        VaultResponse response = vaultTemplate.write(
                clientSignerMountPath + "/sign/" + roleName, request);

        if (response == null || response.getData() == null) {
            throw new RuntimeException("Certificate signing failed");
        }

        Map<String, Object> data = response.getData();

        SshSignedCertificate cert = new SshSignedCertificate(
                (String) data.get("signed_key"),        // Signed certificate content
                (String) data.get("serial_number"),     // Certificate serial
                validPrincipals,
                ttl,
                response.getLeaseId()
        );

        log.info("Certificate signed → serial={}, principals={}, ttl={}m",
                cert.serialNumber(), cert.validPrincipals(), ttl.toMinutes());

        return cert;
    }

    /**
     * Signs a host's SSH public key using Vault's SSH Host CA.
     * Servers present this certificate to clients to prove their identity.
     * Prevents TOFU (Trust On First Use) SSH host-key warnings.
     *
     * @param roleName       Host signing role
     * @param hostPublicKey  Server's public key (from /etc/ssh/ssh_host_rsa_key.pub)
     * @param hostnames      Comma-separated hostnames (e.g., "server1.example.com,server1")
     * @param ttl            Certificate lifetime
     * @return Signed host certificate
     */
    public SshSignedCertificate signHostPublicKey(String roleName,
                                                   String hostPublicKey,
                                                   String hostnames,
                                                   Duration ttl) {
        log.info("Signing host SSH key for hostnames='{}', ttl={}h",
                hostnames, ttl.toHours());

        Map<String, Object> request = new HashMap<>();
        request.put("public_key",        hostPublicKey.trim());
        request.put("cert_type",         "host");
        request.put("valid_principals",  hostnames);
        request.put("ttl",               ttl.toSeconds() + "s");

        VaultResponse response = vaultTemplate.write(
                hostSignerMountPath + "/sign/" + roleName, request);

        if (response == null || response.getData() == null) {
            throw new RuntimeException("Host certificate signing failed");
        }

        Map<String, Object> data = response.getData();

        return new SshSignedCertificate(
                (String) data.get("signed_key"),
                (String) data.get("serial_number"),
                hostnames, ttl,
                response.getLeaseId()
        );
    }

    /**
     * Retrieves the Vault SSH CA's public key.
     * This must be installed on all SSH servers as TrustedUserCAKeys.
     *
     * @return CA public key in OpenSSH format
     */
    public String getCaPublicKey(String mountPath) {
        VaultResponse response = vaultTemplate.read(mountPath + "/config/ca");
        if (response == null || response.getData() == null) {
            throw new RuntimeException("Cannot retrieve CA public key from " + mountPath);
        }
        return (String) response.getData().get("public_key");
    }

    // ── Certificate File Management ───────────────────────────────────────────

    /**
     * Saves signed certificate to the user's .ssh directory.
     * The certificate file must be named {key_basename}-cert.pub
     * (e.g., id_rsa-cert.pub for id_rsa / id_rsa.pub)
     *
     * @param cert           Signed certificate
     * @param sshDir         Target directory (typically ~/.ssh)
     * @param keyBasename    Base name without extension (e.g., "id_rsa")
     */
    public void saveCertificate(SshSignedCertificate cert,
                                 Path sshDir,
                                 String keyBasename) throws IOException {
        Files.createDirectories(sshDir);

        Path certFile = sshDir.resolve(keyBasename + "-cert.pub");
        Files.writeString(certFile, cert.signedKeyContent());

        // SSH certificates must be readable only by owner
        try {
            Files.setPosixFilePermissions(certFile, Set.of(
                    PosixFilePermission.OWNER_READ,
                    PosixFilePermission.OWNER_WRITE
            ));
        } catch (UnsupportedOperationException ignored) {
            // Windows — permissions not supported
        }

        log.info("SSH certificate saved to: {}", certFile);
        log.info("  Serial:     {}", cert.serialNumber());
        log.info("  Principals: {}", cert.validPrincipals());
        log.info("  Expires in: {}m", cert.ttl().toMinutes());
    }

    // ── Demo ──────────────────────────────────────────────────────────────────

    public void runDemo() {
        System.out.println("\n══════════════ SSH Secrets Engine Demo ══════════════");

        // ─── OTP Demo ───
        System.out.println("\n── Mode 1: OTP (One-Time Password) ──────────────────");

        SshOtpCredential otp = generateOtp("otp-role", "ubuntu", "10.0.1.100");
        System.out.printf("""
            ┌─ SSH OTP Credential ────────────────────────────────┐
            │  Username   : %-34s │
            │  Target IP  : %-34s │
            │  OTP        : %-34s │
            │  Key Type   : %-34s │
            │  Lease ID   : %-34s │
            │  TTL        : %-30ds │
            └─────────────────────────────────────────────────────┘
            %n""",
                otp.username(), otp.targetIp(),
                maskOtp(otp.otp()), otp.keyType(),
                otp.leaseId() != null
                        ? otp.leaseId().substring(0, Math.min(36, otp.leaseId().length()))
                        : "N/A",
                otp.leaseDurationSeconds());

        System.out.printf("  SSH Command: ssh -o 'PasswordAuthentication=yes' %s@%s%n%n",
                otp.username(), otp.targetIp());

        // ─── Signed Certificate Demo ───
        System.out.println("── Mode 2: Signed SSH Certificates ────────────────────");

        // Simulate a real user public key
        String simulatedPublicKey = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC1234... user@laptop";

        Map<String, String> extensions = new LinkedHashMap<>();
        extensions.put("permit-pty",              "");
        extensions.put("permit-port-forwarding",  "");
        extensions.put("permit-agent-forwarding", "");

        SshSignedCertificate cert = signUserPublicKey(
                "my-role",
                simulatedPublicKey,
                "ubuntu,ec2-user",
                Duration.ofMinutes(30),
                extensions
        );

        System.out.printf("""
            ┌─ Signed SSH Certificate ────────────────────────────┐
            │  Serial No  : %-34s │
            │  Principals : %-34s │
            │  TTL        : %-34s │
            │  Cert       : %-34s │
            └─────────────────────────────────────────────────────┘
            %n""",
                cert.serialNumber() != null ? cert.serialNumber() : "vault-issued-serial",
                cert.validPrincipals(),
                cert.ttl().toMinutes() + " minutes",
                cert.signedKeyContent() != null
                        ? cert.signedKeyContent().substring(0, Math.min(34, cert.signedKeyContent().length()))
                        : "ssh-rsa-cert-v01@openssh.com...");

        System.out.println("  Steps to use the signed certificate:");
        System.out.println("  1. Save to ~/.ssh/id_rsa-cert.pub");
        System.out.println("  2. ssh ubuntu@10.0.1.100  (no password required)");
        System.out.println("  3. Certificate auto-expires after 30 minutes");
        System.out.println("  4. Request new cert — no manual key rotation needed");
    }

    private String maskOtp(String otp) {
        if (otp == null || otp.length() <= 4) return "****";
        return otp.substring(0, 2) + "*".repeat(otp.length() - 4) + otp.substring(otp.length() - 2);
    }

    // ══════════════════════════════════════════════════════════════════════════
    // Inner Record Types
    // ══════════════════════════════════════════════════════════════════════════

    public record SshOtpCredential(
            String otp,
            String keyType,
            String username,
            String targetIp,
            String port,
            String leaseId,
            long leaseDurationSeconds
    ) {}

    public record SshSignedCertificate(
            String signedKeyContent,
            String serialNumber,
            String validPrincipals,
            Duration ttl,
            String leaseId
    ) {}
}
