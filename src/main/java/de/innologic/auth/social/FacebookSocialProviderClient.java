package de.innologic.auth.social;

import de.innologic.auth.config.SocialAuthProperties;
import de.innologic.auth.domain.enums.Provider;
import de.innologic.auth.web.error.AppException;
import de.innologic.auth.web.error.ErrorCode;
import de.innologic.auth.web.filter.CorrelationIdFilter;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.slf4j.MDC;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.RestClientException;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.util.UriComponentsBuilder;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Map;

@Component
public class FacebookSocialProviderClient implements SocialProviderClient {

    private static final Logger log = LoggerFactory.getLogger(FacebookSocialProviderClient.class);
    private static final String HMAC_ALGORITHM = "HmacSHA256";

    private final RestTemplate restTemplate;
    private final SocialAuthProperties.Facebook config;

    public FacebookSocialProviderClient(RestTemplate restTemplate, SocialAuthProperties socialAuthProperties) {
        this.restTemplate = restTemplate;
        this.config = socialAuthProperties.facebook();
    }

    @Override
    public Provider getProvider() {
        return Provider.FACEBOOK;
    }

    @Override
    public SocialUserInfo fetchUserInfo(String token) {
        ensureProviderEnabled();
        log.info("Verifying Facebook social token correlationId={}", correlationId());
        try {
            String proof = buildAppSecretProof(token);
            String url = UriComponentsBuilder.fromHttpUrl(config.getUserInfoUrl())
                    .queryParam("fields", "id,email")
                    .queryParam("access_token", token)
                    .queryParam("appsecret_proof", proof)
                    .queryParam("v", config.getApiVersion())
                    .toUriString();
            Map<?, ?> response = restTemplate.getForObject(url, Map.class);
            if (response == null) {
                throw new AppException(HttpStatus.UNAUTHORIZED, ErrorCode.SOCIAL_AUTH_FAILED, "Facebook authentication failed");
            }

            String id = asString(response.get("id"));
            String email = asString(response.get("email"));
            if (!StringUtils.hasText(id) || !StringUtils.hasText(email)) {
                throw new AppException(HttpStatus.UNAUTHORIZED, ErrorCode.SOCIAL_AUTH_FAILED, "Facebook authentication failed");
            }

            log.info("Facebook social token verified for subject={} correlationId={}", id, correlationId());
            return new SocialUserInfo(id, email);
        } catch (HttpClientErrorException e) {
            log.warn("Facebook token invalid correlationId={} message={}", correlationId(), e.getMessage());
            throw new AppException(HttpStatus.UNAUTHORIZED, ErrorCode.SOCIAL_AUTH_FAILED, "Facebook authentication failed");
        } catch (RestClientException e) {
            log.warn("Facebook provider unavailable correlationId={} message={}", correlationId(), e.getMessage());
            throw new AppException(HttpStatus.SERVICE_UNAVAILABLE, ErrorCode.SOCIAL_PROVIDER_UNAVAILABLE, "Facebook provider unavailable");
        }
    }

    private void ensureProviderEnabled() {
        if (!config.isLoginEnabled() || !StringUtils.hasText(config.getAppSecret())) {
            throw new AppException(HttpStatus.SERVICE_UNAVAILABLE, ErrorCode.SOCIAL_PROVIDER_UNAVAILABLE, "Facebook login is disabled");
        }
    }

    private String buildAppSecretProof(String token) {
        try {
            Mac mac = Mac.getInstance(HMAC_ALGORITHM);
            mac.init(new SecretKeySpec(config.getAppSecret().getBytes(StandardCharsets.UTF_8), HMAC_ALGORITHM));
            byte[] digest = mac.doFinal(token.getBytes(StandardCharsets.UTF_8));
            StringBuilder builder = new StringBuilder(digest.length * 2);
            for (byte b : digest) {
                builder.append(String.format("%02x", b));
            }
            return builder.toString();
        } catch (NoSuchAlgorithmException | InvalidKeyException e) {
            throw new AppException(HttpStatus.SERVICE_UNAVAILABLE, ErrorCode.SOCIAL_PROVIDER_UNAVAILABLE, "Facebook provider unavailable");
        }
    }

    private String asString(Object value) {
        return value == null ? null : String.valueOf(value);
    }

    private String correlationId() {
        String value = MDC.get(CorrelationIdFilter.MDC_KEY);
        return value == null ? "n/a" : value;
    }
}
