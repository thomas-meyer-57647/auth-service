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

    private final CredentialRepository credentialRepository;
    private final MfaConfigRepository mfaRepository;
    private final PasswordResetTokenRepository passwordResetTokenRepository;
    private final MfaRecoveryTokenRepository mfaRecoveryTokenRepository;
    private final MessagingClient messagingClient;
    private final SessionService sessionService;
    private final PasswordEncoder passwordEncoder = new BCryptPasswordEncoder();
    private final Duration passwordResetTtl;
    private final Duration mfaRecoveryTtl;

    public CredentialRecoveryService(
            CredentialRepository credentialRepository,
            MfaConfigRepository mfaRepository,
            PasswordResetTokenRepository passwordResetTokenRepository,
            MfaRecoveryTokenRepository mfaRecoveryTokenRepository,
            MessagingClient messagingClient,
            SessionService sessionService,
            @Value("${auth.password-reset.ttl:PT15M}") Duration passwordResetTtl,
            @Value("${auth.mfa-recovery.ttl:PT15M}") Duration mfaRecoveryTtl
    ) {
        this.credentialRepository = credentialRepository;
        this.mfaRepository = mfaRepository;
        this.passwordResetTokenRepository = passwordResetTokenRepository;
        this.mfaRecoveryTokenRepository = mfaRecoveryTokenRepository;
        this.messagingClient = messagingClient;
        this.sessionService = sessionService;
        this.passwordResetTtl = passwordResetTtl;
        this.mfaRecoveryTtl = mfaRecoveryTtl;
    }

    public void initiatePasswordForgot(String email) {
        Optional<AuthCredential> credentialOpt = credentialRepository.findByLoginEmail(email);
        if (credentialOpt.isEmpty()) {
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

        messagingClient.sendPasswordReset(credential.getLoginEmail(), rawToken);
    }

    public void resetPassword(String rawToken, String newPassword) {
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
    }

    public void startMfaRecovery(String email, RecoveryChannel channel) {
        Optional<AuthCredential> credentialOpt = credentialRepository.findByLoginEmail(email);
        if (credentialOpt.isEmpty()) {
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

        messagingClient.sendMfaRecovery(credential.getLoginEmail(), channel, rawToken);
    }

    public void confirmMfaRecovery(String rawToken) {
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
}
