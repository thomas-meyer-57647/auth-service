package de.innologic.auth.service;

import de.innologic.auth.domain.entity.AuthCredential;
import de.innologic.auth.domain.entity.RefreshSession;
import de.innologic.auth.domain.enums.SessionPolicy;
import de.innologic.auth.domain.enums.UserStatus;
import de.innologic.auth.domain.repository.CredentialRepository;
import de.innologic.auth.domain.repository.RefreshSessionRepository;
import de.innologic.auth.web.error.AppException;
import de.innologic.auth.web.error.ErrorCode;
import de.innologic.auth.web.filter.CorrelationIdFilter;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.slf4j.MDC;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Base64;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;

@Service
public class SessionService {

    private static final Logger log = LoggerFactory.getLogger(SessionService.class);

    private final RefreshSessionRepository sessionRepository;
    private final CredentialRepository credentialRepository;
    private final Map<String, Long> rotatedRefreshHashes = new ConcurrentHashMap<>();

    public SessionService(RefreshSessionRepository sessionRepository, CredentialRepository credentialRepository) {
        this.sessionRepository = sessionRepository;
        this.credentialRepository = credentialRepository;
    }

    public SessionWithToken createSession(AuthCredential credential, SessionPolicy policy, String tenantId, String ipAddress, String userAgent) {
        log.info("Creating refresh session for credentialId={} policy={} correlationId={}",
                credential.getId(), policy, correlationId());
        String refreshToken = generateOpaqueToken();
        Instant now = Instant.now();

        RefreshSession session = new RefreshSession();
        session.setCredential(credential);
        session.setSid(generateSid());
        session.setUserId(credential.getUserId());
        session.setTenantId(tenantId);
        session.setSessionPolicy(policy);
        session.setRefreshTokenHash(hash(refreshToken));
        session.setIpAddress(ipAddress);
        session.setUserAgent(userAgent);
        session.setCreatedAt(now);
        session.setUpdatedAt(now);
        session.setLastUsedAt(now);
        session.setExpiresAt(calculateSessionExpiry(policy, now));
        sessionRepository.save(session);

        return new SessionWithToken(session, refreshToken);
    }

    public RotationResult rotateRefreshToken(String rawRefreshToken) {
        log.info("Rotating refresh token correlationId={}", correlationId());
        Instant now = Instant.now();
        String presentedHash = hash(rawRefreshToken);
        RefreshSession session = sessionRepository.findByRefreshTokenHash(presentedHash).orElse(null);

        if (session == null) {
            Long compromisedSessionId = rotatedRefreshHashes.get(presentedHash);
            if (compromisedSessionId != null) {
                sessionRepository.findById(compromisedSessionId).ifPresent(found -> {
                    found.setRevokedAt(now);
                    found.setUpdatedAt(now);
                    sessionRepository.save(found);
                });
                throw new AppException(HttpStatus.UNAUTHORIZED, ErrorCode.SESSION_REVOKED, "Refresh token reuse detected; session revoked");
            }
            throw new AppException(HttpStatus.UNAUTHORIZED, ErrorCode.REFRESH_INVALID, "Refresh token is invalid");
        }

        if (session.getRevokedAt() != null) {
            throw new AppException(HttpStatus.UNAUTHORIZED, ErrorCode.SESSION_REVOKED, "Session is revoked");
        }
        if (session.getExpiresAt().isBefore(now)) {
            throw new AppException(HttpStatus.UNAUTHORIZED, ErrorCode.SESSION_EXPIRED, "Session is expired");
        }

        AuthCredential credential = credentialRepository.findById(session.getCredential().getId())
                .orElseThrow(() -> new AppException(HttpStatus.UNAUTHORIZED, ErrorCode.INVALID_CREDENTIALS, "Credential not found"));
        session.setCredential(credential);

        if (credential.getStatus() != UserStatus.ACTIVE) {
            session.setRevokedAt(now);
            session.setUpdatedAt(now);
            sessionRepository.save(session);
            throw new AppException(HttpStatus.UNAUTHORIZED, ErrorCode.SESSION_REVOKED, "Credential status does not allow refresh");
        }

        String newRefreshToken = generateOpaqueToken();
        String newHash = hash(newRefreshToken);
        rotatedRefreshHashes.put(presentedHash, session.getId());

        session.setRefreshTokenHash(newHash);
        session.setUpdatedAt(now);
        session.setLastUsedAt(now);
        session.setExpiresAt(calculateSessionExpiry(session.getSessionPolicy(), now));
        sessionRepository.save(session);
        log.info("Refresh token rotated for sessionId={} correlationId={}", session.getId(), correlationId());

        return new RotationResult(session, newRefreshToken);
    }

    public void revokeSessionByRefreshToken(String rawRefreshToken) {
        String tokenHash = hash(rawRefreshToken);
        sessionRepository.findByRefreshTokenHash(tokenHash).ifPresent(session -> {
            session.setRevokedAt(Instant.now());
            session.setUpdatedAt(Instant.now());
            sessionRepository.save(session);
        });
    }

    public void revokeAllSessionsForCredential(Long credentialId) {
        for (RefreshSession session : sessionRepository.findAllByCredentialIdAndRevokedAtIsNull(credentialId)) {
            session.setRevokedAt(Instant.now());
            session.setUpdatedAt(Instant.now());
            sessionRepository.save(session);
        }
    }

    private Instant calculateSessionExpiry(SessionPolicy policy, Instant reference) {
        if (policy == SessionPolicy.MONTHS_3) {
            return reference.plus(90, ChronoUnit.DAYS);
        }
        return reference.plus(24, ChronoUnit.HOURS);
    }

    private String generateOpaqueToken() {
        byte[] bytes = new byte[32];
        java.security.SecureRandom random = new java.security.SecureRandom();
        random.nextBytes(bytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }

    private String generateSid() {
        return UUID.randomUUID().toString();
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

    public record SessionWithToken(RefreshSession session, String refreshToken) {
    }

    public record RotationResult(RefreshSession session, String newRefreshToken) {
    }
}
