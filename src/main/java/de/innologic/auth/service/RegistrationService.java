package de.innologic.auth.service;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import de.innologic.auth.config.MFAConfig;
import de.innologic.auth.domain.entity.AuthCredential;
import de.innologic.auth.domain.entity.MfaConfig;
import de.innologic.auth.domain.entity.RegistrationProcess;
import de.innologic.auth.domain.entity.VerificationToken;
import de.innologic.auth.domain.enums.UserStatus;
import de.innologic.auth.domain.repository.CredentialRepository;
import de.innologic.auth.domain.repository.MfaConfigRepository;
import de.innologic.auth.domain.repository.RegistrationProcessRepository;
import de.innologic.auth.domain.repository.VerificationTokenRepository;
import de.innologic.auth.messaging.MessagingClient;
import de.innologic.auth.outbound.ActivationOrchestrator;
import de.innologic.auth.web.dto.RegistrationStartRequestDto;
import de.innologic.auth.web.dto.RegistrationVerifyRequestDto;
import de.innologic.auth.web.error.AppException;
import de.innologic.auth.web.error.ErrorCode;
import de.innologic.auth.web.filter.CorrelationIdFilter;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.slf4j.MDC;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.Objects;
import java.util.UUID;

@Service
public class RegistrationService {

    private static final Logger log = LoggerFactory.getLogger(RegistrationService.class);
    private static final String STATUS_PENDING = "PENDING_EMAIL_VERIFICATION";
    private static final String STATUS_EMAIL_VERIFIED = "EMAIL_VERIFIED";
    private static final String STATUS_ACTIVE = "ACTIVE";
    private static final String DEFAULT_SECOND_FACTOR = "TOTP";
    private static final String BASE32_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

    private final CredentialRepository credentialRepository;
    private final RegistrationProcessRepository registrationProcessRepository;
    private final VerificationTokenRepository verificationTokenRepository;
    private final MfaConfigRepository mfaConfigRepository;
    private final MessagingClient messagingClient;
    private final ObjectMapper objectMapper;
    private final PasswordEncoder passwordEncoder = new BCryptPasswordEncoder();
    private final Duration registrationTtl;
    private final Duration verificationTokenTtl;
    private final MFAConfig mfaConfigProperties;
    private final boolean mfaEnabled;
    private final String requiredSecondFactor;
    private final String issuer;
    private final ActivationOrchestrator activationOrchestrator;
    private final SecureRandom secureRandom = new SecureRandom();

    public RegistrationService(
            CredentialRepository credentialRepository,
            RegistrationProcessRepository registrationProcessRepository,
            VerificationTokenRepository verificationTokenRepository,
            MfaConfigRepository mfaConfigRepository,
            MessagingClient messagingClient,
            ObjectMapper objectMapper,
            MFAConfig mfaConfigProperties,
            @Value("${AUTH_MFA_ENABLED:true}") boolean mfaEnabled,
            @Value("${AUTH_MFA_SECOND_FACTOR:TOTP}") String requiredSecondFactor,
            @Value("${AUTH_ISSUER:auth-service}") String issuer,
            @Value("${auth.cleanup.pending-registration-ttl:PT24H}") Duration registrationTtl,
            @Value("${auth.verification.token.ttl:PT15M}") Duration verificationTokenTtl,
            ActivationOrchestrator activationOrchestrator
    ) {
        this.credentialRepository = credentialRepository;
        this.registrationProcessRepository = registrationProcessRepository;
        this.verificationTokenRepository = verificationTokenRepository;
        this.mfaConfigRepository = mfaConfigRepository;
        this.messagingClient = messagingClient;
        this.objectMapper = objectMapper;
        this.mfaConfigProperties = mfaConfigProperties;
        this.mfaEnabled = mfaEnabled;
        this.requiredSecondFactor = requiredSecondFactor;
        this.issuer = issuer;
        this.registrationTtl = registrationTtl;
        this.verificationTokenTtl = verificationTokenTtl;
        this.activationOrchestrator = activationOrchestrator;
    }

    public RegistrationStartResult startRegistration(RegistrationStartRequestDto request) {
        log.info("Starting registration start for email={} correlationId={}", request.getUserEmail(), correlationId());
        credentialRepository.findByLoginEmail(request.getUserEmail()).ifPresent(existing ->
                handleDuplicateEmail(request.getUserEmail()));
        String hashedPassword = passwordEncoder.encode(request.getUserPassword());
        return createRegistration(
                request.getTenantId(),
                request.getUserEmail(),
                hashedPassword,
                request.getCompanyPayload(),
                request.getLocationPayload(),
                request.getUserPayload()
        );
    }

    public RegistrationStartResult startSocialRegistration(String tenantId,
                                                         JsonNode companyPayload,
                                                         JsonNode locationPayload,
                                                         JsonNode userPayload,
                                                         String userEmail) {
        log.info("Starting social registration start for email={} correlationId={}", userEmail, correlationId());
        return createRegistration(tenantId, userEmail, null, companyPayload, locationPayload, userPayload);
    }

    private RegistrationStartResult createRegistration(String tenantId,
                                                       String userEmail,
                                                       String passwordHash,
                                                       JsonNode companyPayload,
                                                       JsonNode locationPayload,
                                                       JsonNode userPayload) {
        Instant now = Instant.now();

        AuthCredential credential = new AuthCredential();
        credential.setUserId(generateUserId());
        credential.setLoginEmail(userEmail);
        credential.setPasswordHash(passwordHash);
        credential.setStatus(UserStatus.PENDING_EMAIL_VERIFICATION);
        credential.setEmailVerified(false);
        credential.setFailedAttempts(0);
        credential.setLockedUntil(null);
        credential.setLastLoginAt(null);
        credential.setCreatedAt(now);
        credential.setModifiedAt(now);
        credentialRepository.save(credential);

        RegistrationProcess process = new RegistrationProcess();
        process.setRegistrationId("reg_" + UUID.randomUUID());
        process.setTenantId(tenantId);
        process.setUserId(credential.getUserId());
        process.setStatus(STATUS_PENDING);
        process.setCompanyPayload(serializePayload(companyPayload));
        process.setLocationPayload(serializePayload(locationPayload));
        process.setUserPayload(serializePayload(userPayload));
        process.setExpiresAt(now.plus(registrationTtl));
        process.setCreatedAt(now);
        process.setModifiedAt(now);
        registrationProcessRepository.save(process);

        String rawToken = "vt_" + generateOpaqueToken();
        VerificationToken token = new VerificationToken();
        token.setCredential(credential);
        token.setTokenHash(hash(rawToken));
        token.setExpiresAt(now.plus(verificationTokenTtl));
        token.setCreatedAt(now);
        verificationTokenRepository.save(token);

        try {
            messagingClient.sendRegistrationVerification(credential.getLoginEmail(), process.getRegistrationId(), rawToken);
        } catch (Exception e) {
            log.warn("Failed to trigger messaging for registrationId={} correlationId={}", process.getRegistrationId(), correlationId(), e);
        }

        log.info("Registration started for registrationId={} email={} correlationId={}", process.getRegistrationId(), userEmail, correlationId());
        return new RegistrationStartResult(process, rawToken, credential);
    }

    public RegistrationProcess verifyEmail(RegistrationVerifyRequestDto request) {
        log.info("Starting email verification for registrationId={} correlationId={}", request.getRegistrationId(), correlationId());
        Instant now = Instant.now();

        RegistrationProcess process = registrationProcessRepository.findByRegistrationId(request.getRegistrationId())
                .orElseThrow(() -> new AppException(HttpStatus.NOT_FOUND, ErrorCode.REGISTRATION_NOT_FOUND, "Registration not found"));

        if (process.getExpiresAt().isBefore(now)) {
            throw new AppException(HttpStatus.GONE, ErrorCode.REGISTRATION_EXPIRED, "Registration expired");
        }

        String hashedToken = hash(request.getVerificationToken());
        VerificationToken token = verificationTokenRepository.findByTokenHash(hashedToken)
                .orElseThrow(() -> new AppException(HttpStatus.BAD_REQUEST, ErrorCode.TOKEN_INVALID, "Invalid verification token"));

        if (token.getUsedAt() != null) {
            throw new AppException(HttpStatus.BAD_REQUEST, ErrorCode.TOKEN_INVALID, "Verification token already used");
        }

        if (token.getExpiresAt().isBefore(now)) {
            throw new AppException(HttpStatus.UNAUTHORIZED, ErrorCode.TOKEN_EXPIRED, "Verification token expired");
        }

        AuthCredential credential = credentialRepository.findByUserId(process.getUserId())
                .orElseThrow(() -> new AppException(HttpStatus.NOT_FOUND, ErrorCode.REGISTRATION_NOT_FOUND, "Associated credential not found"));

        if (!Objects.equals(token.getCredential().getId(), credential.getId())) {
            throw new AppException(HttpStatus.BAD_REQUEST, ErrorCode.TOKEN_INVALID, "Token does not match registration");
        }

        credential.setEmailVerified(true);
        credential.setModifiedAt(now);
        if (mfaEnabled) {
            credential.setStatus(UserStatus.ACTIVATION_IN_PROGRESS);
            process.setStatus(STATUS_EMAIL_VERIFIED);
        } else {
            activationOrchestrator.activate(process, credential);
            credential.setStatus(UserStatus.ACTIVE);
            process.setStatus(STATUS_ACTIVE);
        }
        credentialRepository.save(credential);

        process.setModifiedAt(now);
        registrationProcessRepository.save(process);

        token.setUsedAt(now);
        verificationTokenRepository.save(token);

        if (!mfaEnabled) {
            log.info("Email verified and activation completed for registrationId={} correlationId={}", process.getRegistrationId(), correlationId());
        } else {
            log.info("Email verified for registrationId={} correlationId={}", process.getRegistrationId(), correlationId());
        }
        return process;
    }

    public MfaEnrollmentResult enrollTotp(String registrationId) {
        ensureMfaEnabled();
        if (!DEFAULT_SECOND_FACTOR.equalsIgnoreCase(requiredSecondFactor) && !requiredSecondFactor.equalsIgnoreCase("TOTP")) {
            throw new AppException(HttpStatus.BAD_REQUEST, ErrorCode.MFA_NOT_ENROLLED, "Unsupported second factor");
        }

        RegistrationProcess process = registrationProcessRepository.findByRegistrationId(registrationId)
                .orElseThrow(() -> new AppException(HttpStatus.NOT_FOUND, ErrorCode.REGISTRATION_NOT_FOUND, "Registration not found"));
        if (!STATUS_EMAIL_VERIFIED.equals(process.getStatus())) {
            throw new AppException(HttpStatus.BAD_REQUEST, ErrorCode.EMAIL_NOT_VERIFIED, "Registration must have a verified e-mail");
        }

        AuthCredential credential = credentialRepository.findByUserId(process.getUserId())
                .orElseThrow(() -> new AppException(HttpStatus.NOT_FOUND, ErrorCode.REGISTRATION_NOT_FOUND, "Associated credential not found"));

        if (!credential.isEmailVerified()) {
            throw new AppException(HttpStatus.BAD_REQUEST, ErrorCode.EMAIL_NOT_VERIFIED, "E-mail is not verified");
        }

        String secret = generateTotpSecret();
        Instant now = Instant.now();
        MfaConfig config = mfaConfigRepository.findByCredentialId(credential.getId()).orElseGet(MfaConfig::new);
        boolean isNew = config.getId() == null;
        config.setCredential(credential);
        config.setEnabled(false);
        config.setSecondFactorType(requiredSecondFactor);
        config.setTotpSecretEncrypted(secret);
        config.setEmailChannelEnabled(true);
        config.setSmsChannelEnabled(true);
        config.setEnrolledAt(null);
        if (isNew) {
            config.setCreatedAt(now);
        }
        config.setUpdatedAt(now);
        mfaConfigRepository.save(config);

        String otpauthUri = buildOtpAuthUri(secret, issuer, credential.getLoginEmail());
        log.info("MFA enrollment prepared for registrationId={} correlationId={}", process.getRegistrationId(), correlationId());
        return new MfaEnrollmentResult(secret, otpauthUri);
    }

    public RegistrationProcess confirmTotp(String registrationId, String totpCode) {
        ensureMfaEnabled();
        Instant now = Instant.now();
        RegistrationProcess process = registrationProcessRepository.findByRegistrationId(registrationId)
                .orElseThrow(() -> new AppException(HttpStatus.NOT_FOUND, ErrorCode.REGISTRATION_NOT_FOUND, "Registration not found"));

        AuthCredential credential = credentialRepository.findByUserId(process.getUserId())
                .orElseThrow(() -> new AppException(HttpStatus.NOT_FOUND, ErrorCode.REGISTRATION_NOT_FOUND, "Associated credential not found"));

        if (!credential.isEmailVerified()) {
            throw new AppException(HttpStatus.BAD_REQUEST, ErrorCode.EMAIL_NOT_VERIFIED, "E-mail is not verified");
        }

        MfaConfig config = mfaConfigRepository.findByCredentialId(credential.getId())
                .orElseThrow(() -> new AppException(HttpStatus.BAD_REQUEST, ErrorCode.MFA_NOT_ENROLLED, "MFA enrollment missing"));

        String secret = config.getTotpSecretEncrypted();
        if (secret == null || secret.isBlank()) {
            throw new AppException(HttpStatus.BAD_REQUEST, ErrorCode.MFA_NOT_ENROLLED, "MFA re-enrollment required");
        }

        if (!isValidTotp(totpCode, secret)) {
            throw new AppException(HttpStatus.BAD_REQUEST, ErrorCode.TOTP_INVALID, "Invalid TOTP code");
        }

        config.setEnabled(true);
        config.setEnrolledAt(now);
        config.setUpdatedAt(now);
        mfaConfigRepository.save(config);

        activationOrchestrator.activate(process, credential);

        credential.setStatus(UserStatus.ACTIVE);
        credential.setModifiedAt(now);
        credentialRepository.save(credential);

        process.setStatus(STATUS_ACTIVE);
        process.setModifiedAt(now);
        registrationProcessRepository.save(process);

        log.info("MFA confirmed for registrationId={} correlationId={}", process.getRegistrationId(), correlationId());
        return process;
    }

    private void ensureMfaEnabled() {
        if (!mfaEnabled) {
            throw new AppException(HttpStatus.BAD_REQUEST, ErrorCode.MFA_NOT_ENROLLED, "MFA is disabled");
        }
    }

    private void handleDuplicateEmail(String email) {
        throw new AppException(HttpStatus.CONFLICT, ErrorCode.DUPLICATE_EMAIL, "E-mail is already in use");
    }

    private String serializePayload(JsonNode payload) {
        if (payload == null) {
            return null;
        }
        try {
            return objectMapper.writeValueAsString(payload);
        } catch (JsonProcessingException e) {
            throw new AppException(HttpStatus.BAD_REQUEST, ErrorCode.VALIDATION_ERROR, "Unable to serialize registration payload");
        }
    }

    public static class RegistrationStartResult {
        private final RegistrationProcess process;
        private final String verificationToken;
        private final AuthCredential credential;

        public RegistrationStartResult(RegistrationProcess process, String verificationToken, AuthCredential credential) {
            this.process = process;
            this.verificationToken = verificationToken;
            this.credential = credential;
        }

        public RegistrationProcess getProcess() {
            return process;
        }

        public String getVerificationToken() {
            return verificationToken;
        }

        public AuthCredential getCredential() {
            return credential;
        }
    }

    public static class MfaEnrollmentResult {
        private final String secret;
        private final String otpauthUri;

        public MfaEnrollmentResult(String secret, String otpauthUri) {
            this.secret = secret;
            this.otpauthUri = otpauthUri;
        }

        public String getSecret() {
            return secret;
        }

        public String getOtpauthUri() {
            return otpauthUri;
        }
    }

    private String generateTotpSecret() {
        byte[] bytes = new byte[20];
        secureRandom.nextBytes(bytes);
        return encodeBase32(bytes);
    }

    private String encodeBase32(byte[] data) {
        StringBuilder builder = new StringBuilder();
        int index = 0;
        int digit = 0;
        int currByte, nextByte;
        for (int i = 0; i < data.length; ) {
            currByte = data[i] < 0 ? data[i] + 256 : data[i];
            if (index > 3) {
                if ((i + 1) < data.length) {
                    nextByte = data[i + 1] < 0 ? data[i + 1] + 256 : data[i + 1];
                } else {
                    nextByte = 0;
                }
                digit = currByte & (0xFF >> index);
                index = (index + 5) % 8;
                digit <<= index;
                digit |= nextByte >> (8 - index);
                i++;
            } else {
                digit = (currByte >> (8 - (index + 5))) & 0x1F;
                index = (index + 5) % 8;
                if (index == 0) {
                    i++;
                }
            }
            builder.append(BASE32_ALPHABET.charAt(digit));
        }
        return builder.toString();
    }

    private String buildOtpAuthUri(String secret, String issuer, String email) {
        try {
            String label = URLEncoder.encode(issuer + ":" + email, StandardCharsets.UTF_8);
            String encodedIssuer = URLEncoder.encode(issuer, StandardCharsets.UTF_8);
            return String.format("otpauth://totp/%s?secret=%s&issuer=%s&digits=%d&period=%d",
                    label,
                    secret,
                    encodedIssuer,
                    mfaConfigProperties.getTotpDigits(),
                    mfaConfigProperties.getTotpPeriodSeconds());
        } catch (Exception e) {
            throw new AppException(HttpStatus.INTERNAL_SERVER_ERROR, ErrorCode.INTERNAL_ERROR, "Unable to build OTP auth URI");
        }
    }

    private boolean isValidTotp(String code, String secret) {
        if (code == null || code.length() != mfaConfigProperties.getTotpDigits()) {
            return false;
        }

        byte[] key = decodeBase32(secret.replace(" ", "").toUpperCase());
        long currentStep = Instant.now().getEpochSecond() / mfaConfigProperties.getTotpPeriodSeconds();
        for (int delta = -mfaConfigProperties.getTotpAllowedDriftSteps(); delta <= mfaConfigProperties.getTotpAllowedDriftSteps(); delta++) {
            if (generateTotp(key, currentStep + delta, mfaConfigProperties.getTotpDigits()).equals(code)) {
                return true;
            }
        }
        return false;
    }

    private String generateTotp(byte[] key, long counter, int digits) {
        try {
            byte[] data = new byte[8];
            long value = counter;
            for (int i = 7; i >= 0; i--) {
                data[i] = (byte) (value & 0xFF);
                value >>= 8;
            }

            var mac = javax.crypto.Mac.getInstance("HmacSHA1");
            mac.init(new javax.crypto.spec.SecretKeySpec(key, "HmacSHA1"));
            byte[] hash = mac.doFinal(data);
            int offset = hash[hash.length - 1] & 0x0F;
            int binary = ((hash[offset] & 0x7F) << 24)
                    | ((hash[offset + 1] & 0xFF) << 16)
                    | ((hash[offset + 2] & 0xFF) << 8)
                    | (hash[offset + 3] & 0xFF);
            int otp = binary % (int) Math.pow(10, digits);
            return String.format("%0" + digits + "d", otp);
        } catch (Exception e) {
            throw new IllegalStateException("Unable to compute TOTP", e);
        }
    }

    private byte[] decodeBase32(String value) {
        value = value.toUpperCase().replace("=", "");
        int buffer = 0;
        int bitsLeft = 0;
        java.util.ArrayList<Byte> out = new java.util.ArrayList<>();
        for (char c : value.toCharArray()) {
            int val = BASE32_ALPHABET.indexOf(c);
            if (val < 0) {
                continue;
            }
            buffer = (buffer << 5) | val;
            bitsLeft += 5;
            if (bitsLeft >= 8) {
                out.add((byte) ((buffer >> (bitsLeft - 8)) & 0xFF));
                bitsLeft -= 8;
            }
        }
        byte[] result = new byte[out.size()];
        for (int i = 0; i < out.size(); i++) {
            result[i] = out.get(i);
        }
        return result;
    }

    private String generateUserId() {
        return "usr_" + UUID.randomUUID();
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

    private String generateOpaqueToken() {
        byte[] bytes = new byte[32];
        secureRandom.nextBytes(bytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }

    private String correlationId() {
        String correlationId = MDC.get(CorrelationIdFilter.MDC_KEY);
        return correlationId == null ? "n/a" : correlationId;
    }
}
