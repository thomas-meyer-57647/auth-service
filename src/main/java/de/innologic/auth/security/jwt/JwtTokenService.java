package de.innologic.auth.security.jwt;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

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

    public JwtTokenService(
            JwtKeyService jwtKeyService,
            @Value("${auth.jwt.issuer:http://localhost:8080/api/v1/auth}") String issuer,
            @Value("${auth.jwt.access-token-ttl:PT15M}") Duration accessTokenTtl
    ) {
        this.jwtKeyService = jwtKeyService;
        this.issuer = issuer;
        this.accessTokenTtl = accessTokenTtl;
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
                .claim("subject_type", "user");

        if (sid != null && !sid.isBlank()) {
            claimsBuilder.claim("sid", sid);
        }
        if (amrList != null && !amrList.isEmpty()) {
            claimsBuilder.claim("amr", amrList);
        }

        SignedJWT signedJWT = new SignedJWT(
                new JWSHeader.Builder(JWSAlgorithm.RS256)
                        .keyID(jwtKeyService.getKeyId())
                        .build(),
                claimsBuilder.build()
        );

        try {
            signedJWT.sign(new RSASSASigner(jwtKeyService.getPrivateKey()));
            return signedJWT.serialize();
        } catch (JOSEException e) {
            throw new IllegalStateException("Failed to sign access token", e);
        }
    }

    private void validateRequired(Long userId, String tenantId, List<String> audList, List<String> scopes) {
        Objects.requireNonNull(userId, "userId must not be null");
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
}
