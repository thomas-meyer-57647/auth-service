package de.innologic.auth.service;

import de.innologic.auth.domain.entity.AuthCredential;
import de.innologic.auth.domain.entity.RefreshSession;
import de.innologic.auth.domain.enums.SessionPolicy;
import de.innologic.auth.domain.repository.RefreshSessionRepository;
import de.innologic.auth.web.error.AppException;
import de.innologic.auth.web.error.ErrorCode;
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

    private final RefreshSessionRepository sessionRepository;
    private final Map<String, Long> rotatedRefreshHashes = new ConcurrentHashMap<>();

    public SessionService(RefreshSessionRepository sessionRepository) {
        this.sessionRepository = sessionRepository;
    }

    public SessionWithToken createSession(AuthCredential credential, SessionPolicy policy, String ipAddress, String userAgent) {
        String refreshToken = generateOpaqueToken();
        RefreshSession session = new RefreshSession();
        session.setCredential(credential);
        session.setSid(generateSid());
        session.setUserId(credential.getUserId());
        session.setTenantId(null);
        session.setSessionPolicy(policy);
        session.setRefreshTokenHash(hash(refreshToken));
        session.setIpAddress(ipAddress);
        session.setUserAgent(userAgent);
        session.setCreatedAt(Instant.now());
        session.setUpdatedAt(Instant.now());
        session.setExpiresAt(calculateSessionExpiry(policy, Instant.now()));
        sessionRepository.save(session);

        return new SessionWithToken(session, refreshToken);
    }

    public RotationResult rotateRefreshToken(String rawRefreshToken) {
        String presentedHash = hash(rawRefreshToken);
        RefreshSession session = sessionRepository.findByRefreshTokenHash(presentedHash).orElse(null);

        if (session == null) {
            Long compromisedSessionId = rotatedRefreshHashes.get(presentedHash);
            if (compromisedSessionId != null) {
                sessionRepository.findById(compromisedSessionId).ifPresent(found -> {
                    found.setRevokedAt(Instant.now());
                    found.setUpdatedAt(Instant.now());
                    sessionRepository.save(found);
                });
                throw new AppException(HttpStatus.UNAUTHORIZED, ErrorCode.SESSION_REVOKED, "Refresh token reuse detected; session revoked");
            }
            throw new AppException(HttpStatus.UNAUTHORIZED, ErrorCode.REFRESH_INVALID, "Refresh token is invalid");
        }

        if (session.getRevokedAt() != null) {
            throw new AppException(HttpStatus.UNAUTHORIZED, ErrorCode.SESSION_REVOKED, "Session is revoked");
        }
        if (session.getExpiresAt().isBefore(Instant.now())) {
            throw new AppException(HttpStatus.UNAUTHORIZED, ErrorCode.SESSION_EXPIRED, "Session is expired");
        }

        String newRefreshToken = generateOpaqueToken();
        String newHash = hash(newRefreshToken);
        rotatedRefreshHashes.put(presentedHash, session.getId());

        session.setRefreshTokenHash(newHash);
        session.setUpdatedAt(Instant.now());
        sessionRepository.save(session);

        session.setLastUsedAt(Instant.now());
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

    private Instant calculateSessionExpiry(SessionPolicy policy, Instant now) {
        if (policy == SessionPolicy.MONTHS_3) {
            return now.plus(90, ChronoUnit.DAYS);
        }
        return now.plus(24, ChronoUnit.HOURS);
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

    public record SessionWithToken(RefreshSession session, String refreshToken) {
    }

    public record RotationResult(RefreshSession session, String newRefreshToken) {
    }
}
