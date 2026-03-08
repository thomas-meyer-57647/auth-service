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

import java.util.Map;

@Component
public class GoogleSocialProviderClient implements SocialProviderClient {

    private static final Logger log = LoggerFactory.getLogger(GoogleSocialProviderClient.class);

    private final RestTemplate restTemplate;
    private final SocialAuthProperties.Google config;

    public GoogleSocialProviderClient(RestTemplate restTemplate, SocialAuthProperties socialAuthProperties) {
        this.restTemplate = restTemplate;
        this.config = socialAuthProperties.google();
    }

    @Override
    public Provider getProvider() {
        return Provider.GOOGLE;
    }

    @Override
    public SocialUserInfo fetchUserInfo(String token) {
        ensureProviderEnabled();
        log.info("Verifying Google social token correlationId={}", correlationId());
        try {
            Map<?, ?> response = restTemplate.getForObject(config.getTokenInfoUrl() + "?id_token={token}", Map.class, token);
            if (response == null) {
                throw new AppException(HttpStatus.UNAUTHORIZED, ErrorCode.SOCIAL_AUTH_FAILED, "Google authentication failed");
            }

            String audience = asString(response.get("aud"));
            String subject = asString(response.get("sub"));
            String email = asString(response.get("email"));
            String emailVerifiedValue = asString(response.get("email_verified"));
            boolean emailVerified = Boolean.parseBoolean(emailVerifiedValue);
            if (!StringUtils.hasText(subject) || !StringUtils.hasText(email) || !emailVerified) {
                throw new AppException(HttpStatus.UNAUTHORIZED, ErrorCode.SOCIAL_AUTH_FAILED, "Google authentication failed");
            }

            if (!config.getClientId().equals(audience)) {
                throw new AppException(HttpStatus.UNAUTHORIZED, ErrorCode.SOCIAL_AUTH_FAILED, "Google authentication failed");
            }

            log.info("Google social token verified for subject={} correlationId={}", subject, correlationId());
            return new SocialUserInfo(subject, email);
        } catch (HttpClientErrorException e) {
            log.warn("Google token invalid correlationId={} message={}", correlationId(), e.getMessage());
            throw new AppException(HttpStatus.UNAUTHORIZED, ErrorCode.SOCIAL_AUTH_FAILED, "Google authentication failed");
        } catch (RestClientException e) {
            log.warn("Google provider unavailable correlationId={} message={}", correlationId(), e.getMessage());
            throw new AppException(HttpStatus.SERVICE_UNAVAILABLE, ErrorCode.SOCIAL_PROVIDER_UNAVAILABLE, "Google provider unavailable");
        }
    }

    private void ensureProviderEnabled() {
        if (!config.isLoginEnabled() || !StringUtils.hasText(config.getClientId())) {
            throw new AppException(HttpStatus.SERVICE_UNAVAILABLE, ErrorCode.SOCIAL_PROVIDER_UNAVAILABLE, "Google login is disabled");
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

