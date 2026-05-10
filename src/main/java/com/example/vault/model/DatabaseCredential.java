package com.example.vault.model;

/**
 * Represents dynamic database credentials issued by Vault.
 *
 * @param username            Vault-generated database username (e.g., v-token-readonly-xyz)
 * @param password            Vault-generated password
 * @param leaseId             Vault lease ID (used for renewal and revocation)
 * @param leaseDurationSeconds Lease TTL in seconds
 * @param role                Vault DB role this credential was issued for
 */
public record DatabaseCredential(
        String username,
        String password,
        String leaseId,
        long   leaseDurationSeconds,
        String role
) {
    /**
     * Returns true if the credential's lease has less than {@code thresholdSeconds}
     * remaining. Useful for proactive renewal logic.
     */
    public boolean isNearExpiry(long thresholdSeconds, long issuedAtEpochSeconds) {
        long elapsedSeconds  = System.currentTimeMillis() / 1000 - issuedAtEpochSeconds;
        long remainingSeconds = leaseDurationSeconds - elapsedSeconds;
        return remainingSeconds < thresholdSeconds;
    }

    @Override
    public String toString() {
        return "DatabaseCredential{" +
                "username='" + username + '\'' +
                ", role='" + role + '\'' +
                ", leaseId='" + (leaseId != null ? leaseId.substring(0, Math.min(20, leaseId.length())) + "..." : "null") + '\'' +
                ", leaseDurationSeconds=" + leaseDurationSeconds +
                '}';
    }
}
