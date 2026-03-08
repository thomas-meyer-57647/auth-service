package de.innologic.auth.service;

import de.innologic.auth.domain.entity.AuthCredential;
import de.innologic.auth.domain.entity.AuthIdentity;
import de.innologic.auth.domain.enums.Provider;
import de.innologic.auth.domain.repository.AuthIdentityRepository;
import de.innologic.auth.domain.repository.CredentialRepository;
import de.innologic.auth.social.SocialProviderClient;
import de.innologic.auth.social.SocialUserInfo;
import de.innologic.auth.web.dto.RegistrationStartResponseDto;
import de.innologic.auth.web.dto.SocialRegistrationRequestDto;
import de.innologic.auth.web.error.AppException;
import de.innologic.auth.web.error.ErrorCode;
import de.innologic.auth.web.filter.CorrelationIdFilter;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.slf4j.MDC;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.util.StringUtils;

import java.time.Instant;
import java.util.List;

@Service
public class SocialAuthService {

    private static final Logger log = LoggerFactory.getLogger(SocialAuthService.class);

    private final RegistrationService registrationService;
    private final CredentialRepository credentialRepository;
    private final AuthIdentityRepository identityRepository;
    private final List<SocialProviderClient> providerClients;

    public SocialAuthService(RegistrationService registrationService,
                             CredentialRepository credentialRepository,
                             AuthIdentityRepository identityRepository,
            List<SocialProviderClient> providerClients) {
        this.registrationService = registrationService;
        this.credentialRepository = credentialRepository;
        this.identityRepository = identityRepository;
        this.providerClients = providerClients;
    }

    public RegistrationStartResponseDto registerWithProvider(Provider provider, SocialRegistrationRequestDto request) {
        SocialUserInfo userInfo = resolveUserInfo(provider, request.getSocialToken());
        log.info("Starting social registration for provider={} subject={} correlationId={}", provider, userInfo.getProviderSubject(), correlationId());
        ensureIdentityNotLinked(provider, userInfo.getProviderSubject());
        ensureEmailAvailable(userInfo.getEmail());

        RegistrationService.RegistrationStartResult result = registrationService.startSocialRegistration(
                request.getTenantId(),
                request.getCompanyPayload(),
                request.getLocationPayload(),
                request.getUserPayload(),
                userInfo.getEmail()
        );

        linkIdentity(result.getCredential(), provider, userInfo);

        RegistrationStartResponseDto response = new RegistrationStartResponseDto(
                result.getProcess().getRegistrationId(),
                result.getProcess().getStatus(),
                result.getProcess().getExpiresAt(),
                "Registration initiated; verification email has been queued."
        );
        log.info("Social registration enqueued for provider={} subject={} credentialId={} correlationId={}",
                provider, userInfo.getProviderSubject(), result.getCredential().getId(), correlationId());
        return response;
    }

    public AuthCredential resolveCredentialForLogin(Provider provider, String token) {
        SocialUserInfo userInfo = resolveUserInfo(provider, token);
        log.info("Resolving credential for social login provider={} subject={} correlationId={}",
                provider, userInfo.getProviderSubject(), correlationId());
        AuthIdentity identity = identityRepository.findByProviderAndProviderSubject(provider, userInfo.getProviderSubject())
                .orElseThrow(() -> new AppException(HttpStatus.UNAUTHORIZED, ErrorCode.SOCIAL_AUTH_FAILED, "Social identity not linked"));
        return identity.getCredential();
    }

    private SocialUserInfo resolveUserInfo(Provider provider, String token) {
        return findProviderClient(provider).fetchUserInfo(token);
    }

    private SocialProviderClient findProviderClient(Provider provider) {
        return providerClients.stream()
                .filter(client -> provider.equals(client.getProvider()))
                .findFirst()
                .orElseThrow(() -> new AppException(HttpStatus.SERVICE_UNAVAILABLE, ErrorCode.SOCIAL_PROVIDER_UNAVAILABLE, "Social provider not configured"));
    }

    private void ensureIdentityNotLinked(Provider provider, String subject) {
        if (identityRepository.findByProviderAndProviderSubject(provider, subject).isPresent()) {
            throw new AppException(HttpStatus.CONFLICT, ErrorCode.SOCIAL_IDENTITY_ALREADY_LINKED, "Social identity already linked");
        }
    }

    private void ensureEmailAvailable(String email) {
        if (!StringUtils.hasText(email)) {
            throw new AppException(HttpStatus.UNAUTHORIZED, ErrorCode.SOCIAL_AUTH_FAILED, "Social identity missing email");
        }
        if (credentialRepository.findByLoginEmail(email).isPresent()) {
            throw new AppException(HttpStatus.CONFLICT, ErrorCode.EMAIL_ALREADY_USED_BY_OTHER_PROVIDER, "E-mail already used");
        }
    }

    private void linkIdentity(AuthCredential credential, Provider provider, SocialUserInfo userInfo) {
        AuthIdentity identity = new AuthIdentity();
        identity.setCredential(credential);
        identity.setProvider(provider);
        identity.setProviderSubject(userInfo.getProviderSubject());
        identity.setProviderEmail(userInfo.getEmail());
        identity.setCreatedAt(Instant.now());
        try {
            identityRepository.save(identity);
        } catch (DataIntegrityViolationException e) {
            throw new AppException(HttpStatus.CONFLICT, ErrorCode.SOCIAL_IDENTITY_ALREADY_LINKED, "Social identity already linked");
        }
    }

    private String correlationId() {
        String value = MDC.get(CorrelationIdFilter.MDC_KEY);
        return value == null ? "n/a" : value;
    }
}
