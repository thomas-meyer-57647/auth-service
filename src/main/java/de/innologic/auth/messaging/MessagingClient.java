package de.innologic.auth.messaging;

import de.innologic.auth.domain.enums.RecoveryChannel;

public interface MessagingClient {
    void sendPasswordReset(String recipient, RecoveryChannel channel, String token);

    void sendMfaRecovery(String recipient, RecoveryChannel channel, String token);

    void sendRegistrationVerification(String recipient, String registrationId, String token);
}
