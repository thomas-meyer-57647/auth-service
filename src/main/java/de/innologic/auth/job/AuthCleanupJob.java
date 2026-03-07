package de.innologic.auth.job;

import de.innologic.auth.domain.enums.UserStatus;
import de.innologic.auth.domain.repository.CredentialRepository;
import de.innologic.auth.domain.repository.VerificationTokenRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

import java.time.Duration;
import java.time.Instant;
import java.util.List;

@Component
public class AuthCleanupJob {

    private static final Logger log = LoggerFactory.getLogger(AuthCleanupJob.class);

    private final CredentialRepository credentialRepository;
    private final VerificationTokenRepository verificationTokenRepository;
    private final Duration pendingRegistrationTtl;

    public AuthCleanupJob(
            CredentialRepository credentialRepository,
            VerificationTokenRepository verificationTokenRepository,
            @Value("${auth.cleanup.pending-registration-ttl:PT24H}") Duration pendingRegistrationTtl
    ) {
        this.credentialRepository = credentialRepository;
        this.verificationTokenRepository = verificationTokenRepository;
        this.pendingRegistrationTtl = pendingRegistrationTtl;
    }

    @Scheduled(fixedDelayString = "${auth.cleanup.interval-ms:900000}")
    public void cleanupExpiredAuthData() {
        Instant now = Instant.now();
        Instant pendingCutoff = now.minus(pendingRegistrationTtl);

        long deletedPending = credentialRepository.deleteByStatusInAndCreatedAtBefore(
                List.of(UserStatus.PENDING_EMAIL_VERIFICATION, UserStatus.ACTIVATION_IN_PROGRESS),
                pendingCutoff
        );

        long deletedVerificationTokens = verificationTokenRepository.deleteByExpiresAtBefore(now);

        if (deletedPending > 0 || deletedVerificationTokens > 0) {
            log.info("Auth cleanup: removed {} pending registrations and {} expired verification tokens", deletedPending, deletedVerificationTokens);
        }
    }
}
