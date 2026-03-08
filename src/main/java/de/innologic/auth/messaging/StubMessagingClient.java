package de.innologic.auth.messaging;

import de.innologic.auth.domain.enums.RecoveryChannel;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

@Component
public class StubMessagingClient implements MessagingClient {

    private static final Logger log = LoggerFactory.getLogger(StubMessagingClient.class);

    @Override
    public void sendPasswordReset(String recipient, RecoveryChannel channel, String token) {
        // TODO Integrate with real e-mail/SMS provider.
        log.info("[MessagingStub] Password reset token for {} via {}: {}", recipient, channel, token);
    }

    @Override
    public void sendMfaRecovery(String recipient, RecoveryChannel channel, String token) {
        // TODO Integrate with real e-mail/SMS provider.
        log.info("[MessagingStub] MFA recovery token for {} via {}: {}", recipient, channel, token);
    }

    @Override
    public void sendRegistrationVerification(String recipient, String registrationId, String token) {
        log.info("[MessagingStub] Registration verification token for {} registrationId={}: {}", recipient, registrationId, token);
    }
}
