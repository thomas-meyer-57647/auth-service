package de.innologic.auth.service;

import de.innologic.auth.domain.entity.AuthCredential;
import de.innologic.auth.domain.entity.MfaConfig;
import de.innologic.auth.domain.entity.MfaRecoveryToken;
import de.innologic.auth.domain.entity.PasswordResetToken;
import de.innologic.auth.domain.enums.RecoveryChannel;
import de.innologic.auth.domain.enums.UserStatus;
import de.innologic.auth.domain.repository.CredentialRepository;
import de.innologic.auth.domain.repository.MfaRecoveryTokenRepository;
import de.innologic.auth.domain.repository.MfaConfigRepository;
import de.innologic.auth.domain.repository.PasswordResetTokenRepository;
import de.innologic.auth.messaging.MessagingClient;
import de.innologic.auth.web.error.AppException;
import de.innologic.auth.web.error.ErrorCode;
import de.innologic.auth.web.filter.CorrelationIdFilter;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.slf4j.MDC;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.http.HttpStatus;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.Optional;

import static org.springframework.http.HttpStatus.BAD_REQUEST;

@Service
public class CredentialRecoveryService {

    private static final Logger log = LoggerFactory.getLogger(CredentialRecoveryService.class);

    private final CredentialRepository credentialRepository;
    private final MfaConfigRepository mfaRepository;
    private final PasswordResetTokenRepository passwordResetTokenRepository;
    private final MfaRecoveryTokenRepository mfaRecoveryTokenRepository;
    private final MessagingClient messagingClient;
    private final SessionService sessionService;
    private final PasswordEncoder passwordEncoder = new BCryptPasswordEncoder();
    private final Duration passwordResetTtl;
    private final Duration mfaRecoveryTtl;
    private final boolean smsPasswordResetEnabled;
    private final boolean mfaRecoverySmsEnabled;

    public CredentialRecoveryService(
            CredentialRepository credentialRepository,
            MfaConfigRepository mfaRepository,
            PasswordResetTokenRepository passwordResetTokenRepository,
            MfaRecoveryTokenRepository mfaRecoveryTokenRepository,
            MessagingClient messagingClient,
            SessionService sessionService,
            @Value("${auth.password-reset.ttl:PT15M}") Duration passwordResetTtl,
            @Value("${auth.mfa-recovery.ttl:PT15M}") Duration mfaRecoveryTtl,
            @Value("${auth.password-reset.sms-enabled:false}") boolean smsPasswordResetEnabled,
            @Value("${auth.mfa-recovery.sms-enabled:false}") boolean mfaRecoverySmsEnabled
    ) {
        this.credentialRepository = credentialRepository;
        this.mfaRepository = mfaRepository;
        this.passwordResetTokenRepository = passwordResetTokenRepository;
        this.mfaRecoveryTokenRepository = mfaRecoveryTokenRepository;
        this.messagingClient = messagingClient;
        this.sessionService = sessionService;
        this.passwordResetTtl = passwordResetTtl;
        this.mfaRecoveryTtl = mfaRecoveryTtl;
        this.smsPasswordResetEnabled = smsPasswordResetEnabled;
        this.mfaRecoverySmsEnabled = mfaRecoverySmsEnabled;
    }

    public void initiatePasswordForgot(String email, RecoveryChannel requestedChannel) {
        log.info("Initiating password forgot for email={} correlationId={}", email, correlationId());
        Optional<AuthCredential> credentialOpt = credentialRepository.findByLoginEmail(email);
        if (credentialOpt.isEmpty()) {
            log.info("No credential found for email={} correlationId={}", email, correlationId());
            return;
        }

        AuthCredential credential = credentialOpt.get();
        String rawToken = "prt_" + generateOpaqueToken();

        PasswordResetToken token = new PasswordResetToken();
        token.setCredential(credential);
        token.setTokenHash(hash(rawToken));
        token.setCreatedAt(Instant.now());
        token.setExpiresAt(Instant.now().plus(passwordResetTtl));
        passwordResetTokenRepository.save(token);

        RecoveryChannel channel = resolvePasswordResetChannel(requestedChannel);
        messagingClient.sendPasswordReset(credential.getLoginEmail(), channel, rawToken);
        log.info("Password reset token dispatched for email={} channel={} correlationId={}",
                email, channel, correlationId());
    }

    public void resetPassword(String rawToken, String newPassword) {
        log.info("Resetting password via token correlationId={}", correlationId());
        PasswordResetToken token = passwordResetTokenRepository.findByTokenHash(hash(rawToken))
                .orElseThrow(() -> new AppException(BAD_REQUEST, ErrorCode.TOKEN_INVALID, "Invalid reset token"));

        if (token.getUsedAt() != null || token.getExpiresAt().isBefore(Instant.now())) {
            throw new AppException(HttpStatus.GONE, ErrorCode.TOKEN_EXPIRED, "Reset token is expired or already used");
        }

        AuthCredential credential = token.getCredential();
        credential.setPasswordHash(passwordEncoder.encode(newPassword));
        credential.setModifiedAt(Instant.now());
        credentialRepository.save(credential);
        sessionService.revokeAllSessionsForCredential(credential.getId());

        token.setUsedAt(Instant.now());
        passwordResetTokenRepository.save(token);
        log.info("Password reset completed for credentialId={} correlationId={}",
                credential.getId(), correlationId());
    }

    public void changePassword(Long credentialId, String currentPassword, String newPassword) {
        log.info("Changing password for credentialId={} correlationId={}", credentialId, correlationId());
        AuthCredential credential = credentialRepository.findById(credentialId)
                .orElseThrow(() -> new AppException(HttpStatus.UNAUTHORIZED, ErrorCode.INVALID_CREDENTIALS, "Credential not found"));
        if (credential.getPasswordHash() == null || !passwordEncoder.matches(currentPassword, credential.getPasswordHash())) {
            throw new AppException(HttpStatus.UNAUTHORIZED, ErrorCode.INVALID_CREDENTIALS, "Current password is invalid");
        }
        credential.setPasswordHash(passwordEncoder.encode(newPassword));
        credential.setModifiedAt(Instant.now());
        credentialRepository.save(credential);
        sessionService.revokeAllSessionsForCredential(credential.getId());
        log.info("Password change applied and sessions revoked for credentialId={} correlationId={}",
                credentialId, correlationId());
    }

    private RecoveryChannel resolvePasswordResetChannel(RecoveryChannel requested) {
        if (requested == null) {
            return RecoveryChannel.EMAIL;
        }
        if (requested == RecoveryChannel.SMS && !smsPasswordResetEnabled) {
            return RecoveryChannel.EMAIL;
        }
        return requested;
    }

    public void startMfaRecovery(String email, RecoveryChannel channel) {
        log.info("Starting MFA recovery for email={} correlationId={}", email, correlationId());
        Optional<AuthCredential> credentialOpt = credentialRepository.findByLoginEmail(email);
        if (credentialOpt.isEmpty()) {
            log.info("No credential for MFA recovery email={} correlationId={}", email, correlationId());
            return;
        }

        AuthCredential credential = credentialOpt.get();
        Optional<MfaConfig> mfaOpt = mfaRepository.findByCredentialId(credential.getId());
        if (mfaOpt.isEmpty() || !mfaOpt.get().isEnabled()) {
            return;
        }

        String rawToken = "mrt_" + generateOpaqueToken();
        MfaRecoveryToken token = new MfaRecoveryToken();
        token.setCredential(credential);
        token.setTokenHash(hash(rawToken));
        token.setCreatedAt(Instant.now());
        token.setExpiresAt(Instant.now().plus(mfaRecoveryTtl));
        mfaRecoveryTokenRepository.save(token);

        RecoveryChannel deliveryChannel = resolveMfaRecoveryChannel(channel);
        messagingClient.sendMfaRecovery(credential.getLoginEmail(), deliveryChannel, rawToken);
        log.info("MFA recovery token sent for email={} channel={} correlationId={}",
                email, deliveryChannel, correlationId());
    }

    public void confirmMfaRecovery(String rawToken) {
        log.info("Confirming MFA recovery token correlationId={}", correlationId());
        MfaRecoveryToken token = mfaRecoveryTokenRepository.findByTokenHash(hash(rawToken))
                .orElseThrow(() -> new AppException(BAD_REQUEST, ErrorCode.TOKEN_INVALID, "Invalid recovery token"));

        if (token.getConsumedAt() != null || token.getExpiresAt().isBefore(Instant.now())) {
            throw new AppException(BAD_REQUEST, ErrorCode.TOKEN_EXPIRED, "Recovery token is expired or already consumed");
        }

        AuthCredential credential = token.getCredential();
        MfaConfig mfa = mfaRepository.findByCredentialId(credential.getId())
                .orElseThrow(() -> new AppException(BAD_REQUEST, ErrorCode.TOKEN_INVALID, "MFA record not found"));

        mfa.setEnabled(false);
        mfa.setTotpSecretEncrypted(null);
        mfa.setUpdatedAt(Instant.now());
        mfaRepository.save(mfa);
        credential.setStatus(UserStatus.PENDING_MFA_ENROLLMENT);
        credential.setModifiedAt(Instant.now());
        credentialRepository.save(credential);
        sessionService.revokeAllSessionsForCredential(credential.getId());

        token.setConsumedAt(Instant.now());
        mfaRecoveryTokenRepository.save(token);
        log.info("MFA recovery confirmed for credentialId={} correlationId={}",
                credential.getId(), correlationId());
    }

    private String generateOpaqueToken() {
        byte[] bytes = new byte[32];
        java.security.SecureRandom random = new java.security.SecureRandom();
        random.nextBytes(bytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }

    private String hash(String input) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hashed = digest.digest(input.getBytes(StandardCharsets.UTF_8));
            StringBuilder sb = new StringBuilder();
            for (byte b : hashed) {
                sb.append(String.format("%02x", b));
            }
            return sb.toString();
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 not available", e);
        }
    }

    private String correlationId() {
        String value = MDC.get(CorrelationIdFilter.MDC_KEY);
        return value == null ? "n/a" : value;
    }

    private RecoveryChannel resolveMfaRecoveryChannel(RecoveryChannel requested) {
        if (requested == null) {
            return RecoveryChannel.EMAIL;
        }
        if (requested == RecoveryChannel.SMS && !mfaRecoverySmsEnabled) {
            return RecoveryChannel.EMAIL;
        }
        return requested;
    }
}
