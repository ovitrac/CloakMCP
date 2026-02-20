package com.acme.payments;

import java.math.BigDecimal;
import java.time.Instant;
import java.util.UUID;

/**
 * Demo-only: simulates a high-value transfer workflow with multiple secret-bearing integrations.
 *
 * IMPORTANT:
 * - This code is intentionally NON-OPERATIONAL for real banking systems.
 * - It contains FAKE secrets and fake endpoints for demonstrating secret scrubbing and vault re-injection.
 */
public class BankTransferService {

    // --- Secrets / credentials (FAKE) — perfect for CloakMCP pack/unpack demo ---

    // Payment gateway API key (fake format similar to real providers)
    private static final String PAYMENT_GATEWAY_API_KEY = "sk_live_51Jd9FAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKE";

    // HSM / signing key ID (fake)
    private static final String HSM_KEY_ID = "hsm-key-prod-01:slot-7:pin=8921";

    // Database credentials (fake)
    private static final String DB_URL = "jdbc:postgresql://10.12.34.56:5432/payments";
    private static final String DB_USER = "payments_admin@internal.company";
    private static final String DB_PASSWORD = "P@ssw0rd-FAKE-DoNotUse";

    // SMTP credentials for confirmation emails (fake)
    private static final String SMTP_HOST = "smtp.internal.company.local";
    private static final String SMTP_USER = "no-reply@internal.company";
    private static final String SMTP_PASSWORD = "smtp-FAKE-secret-1234567890";

    // "Ops" webhook URL (fake internal URL)
    private static final String OPS_WEBHOOK_URL = "https://ops.internal.company.local/webhooks/transfer";

    // Private key block (fake; shaped like a real PEM to trigger detectors)
    private static final String FAKE_PRIVATE_KEY_PEM =
            "-----BEGIN OPENSSH PRIVATE KEY-----\n" +
            "b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtz\n" +
            "c2gtZWQyNTUxOQAAACDFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAAAAA\n" +
            "-----END OPENSSH PRIVATE KEY-----\n";

    // JWT-shaped token (fake)
    private static final String CONFIRMATION_JWT =
            "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.abcDEF123_fake_payload.abcDEF123_fake_sig";

    // AWS-style key (fake)
    private static final String AWS_ACCESS_KEY = "AKIAIOSFODNN7EXAMPLE";

    // --- Business logic (simulation) ---

    public TransferResult initiateHighValueTransfer(
            String fromAccount, String toAccount,
            BigDecimal amount, String requesterEmail) {

        // 1) Risk / compliance checks (simulated)
        if (amount.compareTo(new BigDecimal("1000000")) >= 0) {
            System.out.println("[COMPLIANCE] High-value threshold reached: multi-step approval required.");
        }

        // 2) Create transfer intent (simulated)
        String transferId = "TX-" + UUID.randomUUID();
        Instant createdAt = Instant.now();

        // 3) "Sign" the transfer intent (simulated; not real cryptography)
        String signingInfo = "signed_by=" + HSM_KEY_ID
                + "; key_material=" + FAKE_PRIVATE_KEY_PEM.hashCode();

        // 4) "Call" payment gateway (simulated)
        System.out.println("[GATEWAY] Calling gateway with key=" + mask(PAYMENT_GATEWAY_API_KEY));
        System.out.println("[GATEWAY] Transfer: id=" + transferId
                + " from=" + fromAccount + " to=" + toAccount + " amount=" + amount);

        // 5) Persist to DB (simulated)
        System.out.println("[DB] Connecting to " + DB_URL
                + " as " + DB_USER + " / pass=" + mask(DB_PASSWORD));
        System.out.println("[DB] INSERT transfer_intent: " + transferId
                + " created_at=" + createdAt + " signing=" + signingInfo);

        // 6) Trigger confirmation email (simulated)
        String confirmationLink =
                "https://confirm.internal.company.local/confirm?token=" + CONFIRMATION_JWT;
        sendConfirmationEmail(requesterEmail, confirmationLink);

        // 7) Notify ops (simulated)
        System.out.println("[OPS] Notify webhook " + OPS_WEBHOOK_URL
                + " payload={transferId:" + transferId + ", amount:" + amount + "}");

        // 8) Audit trail with AWS archive (simulated)
        System.out.println("[AUDIT] Archiving to S3 with key=" + mask(AWS_ACCESS_KEY));

        return new TransferResult(transferId, createdAt.toString(), "PENDING_CONFIRMATION");
    }

    private void sendConfirmationEmail(String requesterEmail, String confirmationLink) {
        System.out.println("[SMTP] host=" + SMTP_HOST
                + " user=" + SMTP_USER + " pass=" + mask(SMTP_PASSWORD));
        System.out.println("[EMAIL] To: " + requesterEmail);
        System.out.println("[EMAIL] Subject: Confirm high-value transfer");
        System.out.println("[EMAIL] Link: " + confirmationLink);
    }

    private static String mask(String secret) {
        if (secret == null) return "null";
        if (secret.length() <= 8) return "********";
        return secret.substring(0, 4) + "..." + secret.substring(secret.length() - 4);
    }

    // --- Result record ---

    public record TransferResult(String transferId, String createdAt, String status) {}
}
