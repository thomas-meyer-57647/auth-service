package de.innologic.auth.security.jwt;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import de.innologic.auth.web.error.AppException;
import de.innologic.auth.web.error.ErrorCode;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;

import java.security.interfaces.RSAPublicKey;
import java.text.ParseException;
import java.time.Duration;
import java.time.Instant;
import java.util.Date;
import java.util.List;
import java.util.Objects;
import java.util.UUID;

@Service
public class JwtTokenService {

    private final JwtKeyService jwtKeyService;
    private final String issuer;
    private final Duration accessTokenTtl;
    private final Duration serviceTokenDefaultTtl;
    private final Duration serviceTokenMaxTtl;

    public JwtTokenService(
            JwtKeyService jwtKeyService,
            @Value("${auth.jwt.issuer:http://localhost:8080/api/v1/auth}") String issuer,
            @Value("${auth.jwt.access-token-ttl:PT15M}") Duration accessTokenTtl,
            @Value("${auth.jwt.service-token-ttl:PT5M}") Duration serviceTokenDefaultTtl,
            @Value("${auth.jwt.service-token-max-ttl:PT5M}") Duration serviceTokenMaxTtl
    ) {
        this.jwtKeyService = jwtKeyService;
        this.issuer = issuer;
        this.accessTokenTtl = accessTokenTtl;
        this.serviceTokenDefaultTtl = serviceTokenDefaultTtl;
        this.serviceTokenMaxTtl = serviceTokenMaxTtl;
    }

    public String issueAccessToken(
            Long userId,
            String tenantId,
            String sid,
            List<String> audList,
            List<String> scopes,
            List<String> amrList
    ) {
        validateRequired(userId, tenantId, audList, scopes);

        Instant now = Instant.now();
        Instant expiresAt = now.plus(accessTokenTtl);

        JWTClaimsSet.Builder claimsBuilder = new JWTClaimsSet.Builder()
                .issuer(issuer)
                .subject(String.valueOf(userId))
                .audience(audList)
                .issueTime(Date.from(now))
                .expirationTime(Date.from(expiresAt))
                .jwtID(UUID.randomUUID().toString())
                .claim("tenant_id", tenantId)
                .claim("scp", scopes)
                .claim("auth_time", Date.from(now))
                .claim("subject_type", "USER");

        if (sid != null && !sid.isBlank()) {
            claimsBuilder.claim("sid", sid);
        }
        if (amrList != null && !amrList.isEmpty()) {
            claimsBuilder.claim("amr", amrList);
        }

        return sign(claimsBuilder.build());
    }

    private void validateRequired(Long userId, String tenantId, List<String> audList, List<String> scopes) {
        Objects.requireNonNull(userId, "userId must not be null");
        validateTenantAndLists(tenantId, audList, scopes);
    }

    public String issueServiceToken(String serviceName, String tenantId, List<String> audList, List<String> scopes, Duration ttl) {
        validateNonBlank(serviceName, "serviceName");
        validateTenantAndLists(tenantId, audList, scopes);

        Objects.requireNonNull(ttl, "Service token TTL must not be null");
        Instant now = Instant.now();
        Instant expiresAt = now.plus(ttl);

        JWTClaimsSet claims = new JWTClaimsSet.Builder()
                .issuer(issuer)
                .subject(serviceName)
                .audience(audList)
                .issueTime(Date.from(now))
                .expirationTime(Date.from(expiresAt))
                .jwtID(UUID.randomUUID().toString())
                .claim("tenant_id", tenantId)
                .claim("scp", scopes)
                .claim("subject_type", "SERVICE")
                .build();

        return sign(claims);
    }

    public Duration resolveServiceTokenTtl(Duration requestedTtl) {
        Duration ttl = requestedTtl == null ? serviceTokenDefaultTtl : requestedTtl;
        if (ttl.isZero() || ttl.isNegative()) {
            throw new AppException(HttpStatus.BAD_REQUEST, ErrorCode.VALIDATION_ERROR, "Service token TTL must be positive");
        }
        if (ttl.compareTo(serviceTokenMaxTtl) > 0) {
            throw new AppException(HttpStatus.BAD_REQUEST, ErrorCode.VALIDATION_ERROR, "Service token TTL exceeds maximum allowed");
        }
        return ttl;
    }

    public JWTClaimsSet validateAccessToken(String token) {
        try {
            SignedJWT signedJWT = SignedJWT.parse(token);
            RSAPublicKey publicKey = jwtKeyService.getPublicKey();
            JWSVerifier verifier = new RSASSAVerifier(publicKey);
            if (!signedJWT.verify(verifier)) {
                throw new AppException(HttpStatus.UNAUTHORIZED, ErrorCode.TOKEN_INVALID, "Access token is invalid");
            }

            JWTClaimsSet claims = signedJWT.getJWTClaimsSet();
            Date expiration = claims.getExpirationTime();
            if (expiration == null || expiration.before(Date.from(Instant.now()))) {
                throw new AppException(HttpStatus.UNAUTHORIZED, ErrorCode.TOKEN_EXPIRED, "Access token is expired");
            }

            return claims;
        } catch (ParseException | JOSEException e) {
            throw new AppException(HttpStatus.UNAUTHORIZED, ErrorCode.TOKEN_INVALID, "Access token is invalid");
        }
    }

    private void validateTenantAndLists(String tenantId, List<String> audList, List<String> scopes) {
        Objects.requireNonNull(tenantId, "tenantId must not be null");
        if (tenantId.isBlank()) {
            throw new IllegalArgumentException("tenantId must not be blank");
        }

        Objects.requireNonNull(audList, "audList must not be null");
        if (audList.isEmpty()) {
            throw new IllegalArgumentException("audList must not be empty");
        }

        Objects.requireNonNull(scopes, "scopes must not be null");
        if (scopes.isEmpty()) {
            throw new IllegalArgumentException("scopes must not be empty");
        }
    }

    private void validateNonBlank(String value, String fieldName) {
        Objects.requireNonNull(value, fieldName + " must not be null");
        if (value.isBlank()) {
            throw new IllegalArgumentException(fieldName + " must not be blank");
        }
    }

    private String sign(JWTClaimsSet claims) {
        SignedJWT signedJWT = new SignedJWT(
                new JWSHeader.Builder(JWSAlgorithm.RS256)
                        .keyID(jwtKeyService.getKeyId())
                        .build(),
                claims
        );

        try {
            signedJWT.sign(new RSASSASigner(jwtKeyService.getPrivateKey()));
            return signedJWT.serialize();
        } catch (JOSEException e) {
            throw new IllegalStateException("Failed to sign token", e);
        }
    }
}
