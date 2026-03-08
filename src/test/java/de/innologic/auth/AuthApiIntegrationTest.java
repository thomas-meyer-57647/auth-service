package de.innologic.auth;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import de.innologic.auth.domain.entity.AuthCredential;
import de.innologic.auth.domain.entity.MfaConfig;
import de.innologic.auth.domain.entity.PasswordResetToken;
import de.innologic.auth.domain.entity.RegistrationProcess;
import de.innologic.auth.domain.entity.VerificationToken;
import de.innologic.auth.domain.enums.Provider;
import de.innologic.auth.domain.enums.RecoveryChannel;
import de.innologic.auth.domain.enums.UserStatus;
import de.innologic.auth.domain.repository.CredentialRepository;
import de.innologic.auth.domain.repository.IdempotencyRepository;
import de.innologic.auth.domain.repository.MfaConfigRepository;
import de.innologic.auth.domain.repository.MfaRecoveryTokenRepository;
import de.innologic.auth.domain.repository.PasswordResetTokenRepository;
import de.innologic.auth.domain.repository.RefreshSessionRepository;
import de.innologic.auth.domain.repository.RegistrationProcessRepository;
import de.innologic.auth.domain.repository.VerificationTokenRepository;
import de.innologic.auth.domain.repository.AuthIdentityRepository;
import de.innologic.auth.messaging.MessagingClient;
import de.innologic.auth.outbound.CompanyServiceClient;
import de.innologic.auth.outbound.IamServiceClient;
import de.innologic.auth.outbound.UserServiceClient;
import de.innologic.auth.security.jwt.JwtTokenService;
import de.innologic.auth.service.RateLimiterService;
import de.innologic.auth.social.FacebookSocialProviderClient;
import de.innologic.auth.social.GoogleSocialProviderClient;
import de.innologic.auth.social.SocialUserInfo;
import de.innologic.auth.web.error.AppException;
import de.innologic.auth.web.error.ErrorCode;
import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
import de.innologic.auth.web.AuthController;
import de.innologic.auth.web.RegistrationController;
import de.innologic.auth.web.filter.CorrelationIdFilter;
import jakarta.servlet.http.Cookie;
import org.slf4j.LoggerFactory;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.ResultActions;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.Instant;
import java.util.UUID;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
@AutoConfigureMockMvc(addFilters = false)
@ActiveProfiles("test")
class AuthApiIntegrationTest {

    private static final String BASE = "/auth";
    private static final String MFA_RECOVERY_BASE = "/mfa/recovery";
    private static final BCryptPasswordEncoder ENCODER = new BCryptPasswordEncoder();
    private static final String INTERNAL_API_KEY_HEADER = "X-Internal-Api-Key";
    private static final String INTERNAL_API_KEY_VALUE = "internal-test-key";
    private static final String INTERNAL_TOKENS_SERVICE = "/internal/tokens/service";

    @Autowired
    private MockMvc mockMvc;

    private ListAppender<ILoggingEvent> authLogAppender;

    @Autowired
    private ObjectMapper objectMapper;

    @Autowired
    private JwtTokenService jwtTokenService;

    @Autowired
    private CredentialRepository credentialRepository;

    @Autowired
    private AuthIdentityRepository identityRepository;

    @Autowired
    private MfaConfigRepository mfaRepository;

    @Autowired
    private RefreshSessionRepository sessionRepository;

    @Autowired
    private IdempotencyRepository idempotencyRepository;

    @Autowired
    private PasswordResetTokenRepository passwordResetTokenRepository;

    @Autowired
    private MfaRecoveryTokenRepository mfaRecoveryTokenRepository;

    @Autowired
    private RegistrationProcessRepository registrationProcessRepository;

    @Autowired
    private VerificationTokenRepository verificationTokenRepository;

    @Autowired
    private RateLimiterService rateLimiterService;

    @MockitoBean
    private MessagingClient messagingClient;

    @MockBean
    private UserServiceClient userServiceClient;

    @MockBean
    private CompanyServiceClient companyServiceClient;

    @MockBean
    private IamServiceClient iamServiceClient;

    @MockBean
    private GoogleSocialProviderClient googleSocialProviderClient;

    @MockBean
    private FacebookSocialProviderClient facebookSocialProviderClient;

    @BeforeEach
    void clean() {
        verificationTokenRepository.deleteAll();
        registrationProcessRepository.deleteAll();
        sessionRepository.deleteAll();
        mfaRecoveryTokenRepository.deleteAll();
        passwordResetTokenRepository.deleteAll();
        mfaRepository.deleteAll();
        idempotencyRepository.deleteAll();
        identityRepository.deleteAll();
        credentialRepository.deleteAll();
        rateLimiterService.reset();
        when(googleSocialProviderClient.getProvider()).thenReturn(Provider.GOOGLE);
        when(facebookSocialProviderClient.getProvider()).thenReturn(Provider.FACEBOOK);
        configureAuthLogging();
    }

    @Test
    void loginMfaRefreshLogout_happyPath() throws Exception {
        AuthCredential credential = createCredential("user@example.com", "P@ssw0rd!");
        createMfa(credential, "JBSWY3DPEHPK3PXP");
        String tenantId = "tenant-42";

        MvcResult loginResult = mockMvc.perform(post(BASE + "/login")
                        .header("Idempotency-Key", "idem-login-1")
                        .header("X-Tenant-Id", tenantId)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"email\":\"user@example.com\",\"password\":\"P@ssw0rd!\"}"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.loginTransactionId").exists())
                .andReturn();

        String loginTransactionId = json(loginResult).get("loginTransactionId").asText();
        String totp = generateTotpNow("JBSWY3DPEHPK3PXP");

        MvcResult mfaResult = mockMvc.perform(post(BASE + "/mfa/verify")
                        .header("Idempotency-Key", "idem-mfa-1")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"loginTransactionId\":\"" + loginTransactionId + "\",\"totpCode\":\"" + totp + "\",\"sessionPolicy\":\"HOURS_24\"}"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.accessToken").exists())
                .andExpect(jsonPath("$.tokenType").value("Bearer"))
                .andReturn();

        String accessToken = json(mfaResult).get("accessToken").asText();
        SignedJWT accessJwt = SignedJWT.parse(accessToken);
        JWTClaimsSet accessClaims = accessJwt.getJWTClaimsSet();
        assertThat(accessClaims.getStringClaim("subject_type")).isEqualTo("USER");
        assertThat(accessClaims.getStringListClaim("scp")).contains("openid", "profile");
        assertThat(accessClaims.getStringClaim("tenant_id")).isEqualTo(tenantId);
        assertThat(accessClaims.getAudience()).contains("auth-api");
        assertThat(accessClaims.getIssuer()).isNotBlank();
        assertThat(accessClaims.getSubject()).isNotBlank();
        assertThat(accessClaims.getJWTID()).isNotBlank();
        assertThat(accessClaims.getIssueTime()).isNotNull();
        assertThat(accessClaims.getExpirationTime()).isNotNull();

        String refreshCookie = extractCookieValue(mfaResult.getResponse().getHeader(HttpHeaders.SET_COOKIE), "AUTH_REFRESH");
        assertThat(refreshCookie).isNotBlank();

        MvcResult refreshResult = mockMvc.perform(post(BASE + "/refresh")
                        .header("X-Tenant-Id", tenantId)
                        .cookie(new Cookie("AUTH_REFRESH", refreshCookie)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.accessToken").exists())
                .andReturn();

        String rotatedRefresh = extractCookieValue(refreshResult.getResponse().getHeader(HttpHeaders.SET_COOKIE), "AUTH_REFRESH");
        assertThat(rotatedRefresh).isNotBlank();
        assertThat(rotatedRefresh).isNotEqualTo(refreshCookie);

        String rotatedAccessToken = json(refreshResult).get("accessToken").asText();
        SignedJWT rotatedJwt = SignedJWT.parse(rotatedAccessToken);
        assertThat(rotatedJwt.getJWTClaimsSet().getStringClaim("tenant_id")).isEqualTo(tenantId);

        mockMvc.perform(post(BASE + "/logout")
                        .cookie(new Cookie("AUTH_REFRESH", rotatedRefresh)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.message").value("Logged out"));

        assertThat(sessionRepository.findAll()).allMatch(s -> s.getRevokedAt() != null);
    }

    @Test
    void rateLimitLoginWithinLimitAllowsMultipleRequests() throws Exception {
        AuthCredential credential = createCredential("rl-login@example.com", "Pass12345!");
        createMfa(credential, "JBSWY3DPEHPK3PXP");
        String tenantId = "tenant-rate-limit";

        loginRequest(tenantId, "rl-login-1", credential.getLoginEmail(), "Pass12345!")
                .andExpect(status().isOk());
        loginRequest(tenantId, "rl-login-2", credential.getLoginEmail(), "Pass12345!")
                .andExpect(status().isOk());
    }

    @Test
    void rateLimitLoginExceedLimitReturns429() throws Exception {
        AuthCredential credential = createCredential("rl-login-exceed@example.com", "Pass12345!");
        createMfa(credential, "JBSWY3DPEHPK3PXP");
        String tenantId = "tenant-rate-limit";

        loginRequest(tenantId, "rl-login-exceed-1", credential.getLoginEmail(), "Pass12345!")
                .andExpect(status().isOk());
        loginRequest(tenantId, "rl-login-exceed-2", credential.getLoginEmail(), "Pass12345!")
                .andExpect(status().isOk());
        loginRequest(tenantId, "rl-login-exceed-3", credential.getLoginEmail(), "Pass12345!")
                .andExpect(status().isTooManyRequests())
                .andExpect(jsonPath("$.errorCode").value("RATE_LIMITED"));
    }

    @Test
    void rateLimitPasswordForgotUsesIndependentBucket() throws Exception {
        MockHttpServletRequestBuilder forgot1 = post(BASE + "/password/forgot")
                .header("Idempotency-Key", "rl-forgot-1")
                .contentType(MediaType.APPLICATION_JSON)
                .content("{\"email\":\"rate-limit-forgot@example.com\"}")
                .with(request -> {
                    request.setRemoteAddr("127.0.0.1");
                    return request;
                });
        mockMvc.perform(forgot1)
                .andExpect(status().isAccepted());

        MockHttpServletRequestBuilder forgot2 = post(BASE + "/password/forgot")
                .header("Idempotency-Key", "rl-forgot-2")
                .contentType(MediaType.APPLICATION_JSON)
                .content("{\"email\":\"rate-limit-forgot@example.com\"}")
                .with(request -> {
                    request.setRemoteAddr("127.0.0.1");
                    return request;
                });
        mockMvc.perform(forgot2)
                .andExpect(status().isAccepted());

        MockHttpServletRequestBuilder forgot3 = post(BASE + "/password/forgot")
                .header("Idempotency-Key", "rl-forgot-3")
                .contentType(MediaType.APPLICATION_JSON)
                .content("{\"email\":\"rate-limit-forgot@example.com\"}")
                .with(request -> {
                    request.setRemoteAddr("127.0.0.1");
                    return request;
                });
        mockMvc.perform(forgot3)
                .andExpect(status().isTooManyRequests())
                .andExpect(jsonPath("$.errorCode").value("RATE_LIMITED"));
    }

    @Test
    void rateLimitSocialGoogleAppliesSeparateThreshold() throws Exception {
        SocialUserInfo googleUser = new SocialUserInfo("rl-google", "limittest@example.com");
        when(googleSocialProviderClient.fetchUserInfo("rl-google-token")).thenReturn(googleUser);

        MockHttpServletRequestBuilder socialGoogle1 = post("/registration/social/google")
                .header("Idempotency-Key", "rl-social-google-1")
                .contentType(MediaType.APPLICATION_JSON)
                .content(socialRegistrationPayload("rl-google-token"))
                .with(request -> {
                    request.setRemoteAddr("127.0.0.1");
                    return request;
                });
        mockMvc.perform(socialGoogle1)
                .andExpect(status().isCreated());

        MockHttpServletRequestBuilder socialGoogle2 = post("/registration/social/google")
                .header("Idempotency-Key", "rl-social-google-2")
                .contentType(MediaType.APPLICATION_JSON)
                .content(socialRegistrationPayload("rl-google-token"))
                .with(request -> {
                    request.setRemoteAddr("127.0.0.1");
                    return request;
                });
        mockMvc.perform(socialGoogle2)
                .andExpect(status().isTooManyRequests())
                .andExpect(jsonPath("$.errorCode").value("RATE_LIMITED"));
    }

    @Test
    void loginWithInvalidCredentials_returns401InvalidCredentials() throws Exception {
        createCredential("invalid@example.com", "Pass12345!");

        mockMvc.perform(post(BASE + "/login")
                        .header("Idempotency-Key", "idem-login-invalid")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"email\":\"invalid@example.com\",\"password\":\"WrongPass!\"}"))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.errorCode").value("INVALID_CREDENTIALS"));
    }

    @Test
    void loginIdempotencyConflict_returns409IdempotencyConflict() throws Exception {
        AuthCredential credential = createCredential("idem-conflict@example.com", "Pass12345!");
        String idempotencyKey = "idem-key-conflict";

        mockMvc.perform(post(BASE + "/login")
                        .header("Idempotency-Key", idempotencyKey)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"email\":\"idem-conflict@example.com\",\"password\":\"Pass12345!\"}"))
                .andExpect(status().isOk());

        mockMvc.perform(post(BASE + "/login")
                        .header("Idempotency-Key", idempotencyKey)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"email\":\"idem-conflict@example.com\",\"password\":\"Different!\"}"))
                .andExpect(status().isConflict())
                .andExpect(jsonPath("$.errorCode").value("IDEMPOTENCY_CONFLICT"));
    }

    @Test
    void forgotThenResetPassword_happyPath() throws Exception {
        createCredential("reset@example.com", "OldPass123!");

        mockMvc.perform(post(BASE + "/password/forgot")
                        .header("Idempotency-Key", "idem-password-forgot-1")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"email\":\"reset@example.com\"}"))
                .andExpect(status().isAccepted());

        ArgumentCaptor<String> resetTokenCaptor = ArgumentCaptor.forClass(String.class);
        ArgumentCaptor<RecoveryChannel> channelCaptor = ArgumentCaptor.forClass(RecoveryChannel.class);
        verify(messagingClient, times(1)).sendPasswordReset(anyString(), channelCaptor.capture(), resetTokenCaptor.capture());
        assertThat(channelCaptor.getValue()).isEqualTo(RecoveryChannel.EMAIL);
        String rawToken = resetTokenCaptor.getValue();

        mockMvc.perform(post(BASE + "/password/reset")
                        .header("Idempotency-Key", "idem-password-reset-1")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"token\":\"" + rawToken + "\",\"newPassword\":\"NewPass123!\"}"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.message").value("Password reset successful"));

        mockMvc.perform(post(BASE + "/login")
                        .header("Idempotency-Key", "idem-login-reset")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"email\":\"reset@example.com\",\"password\":\"NewPass123!\"}"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.loginTransactionId").exists());
    }

    @Test
    void passwordForgotIdempotencyConflict_returns409() throws Exception {
        String idempotencyKey = "password-forgot-conflict";

        mockMvc.perform(post(BASE + "/password/forgot")
                        .header("Idempotency-Key", idempotencyKey)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"email\":\"conflict1@example.com\"}"))
                .andExpect(status().isAccepted());

        mockMvc.perform(post(BASE + "/password/forgot")
                        .header("Idempotency-Key", idempotencyKey)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"email\":\"conflict2@example.com\"}"))
                .andExpect(status().isConflict())
                .andExpect(jsonPath("$.errorCode").value("IDEMPOTENCY_CONFLICT"));
    }

    @Test
    void mfaRecoveryStartConfirm_happyPath_setsReEnrollFlag() throws Exception {
        AuthCredential credential = createCredential("mfa@example.com", "Pass12345!");
        createMfa(credential, "JBSWY3DPEHPK3PXP");

        mockMvc.perform(post(MFA_RECOVERY_BASE + "/start")
                        .header("Idempotency-Key", "idem-mfa-recovery-start")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"email\":\"mfa@example.com\",\"channel\":\"EMAIL\"}"))
                .andExpect(status().isAccepted());

        ArgumentCaptor<String> recoveryToken = ArgumentCaptor.forClass(String.class);
        verify(messagingClient, times(1)).sendMfaRecovery(anyString(), any(RecoveryChannel.class), recoveryToken.capture());

        mockMvc.perform(post(MFA_RECOVERY_BASE + "/confirm")
                        .header("Idempotency-Key", "idem-mfa-recovery-confirm")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"token\":\"" + recoveryToken.getValue() + "\"}"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.message").value("MFA recovery confirmed"));

        AuthCredential updated = credentialRepository.findById(credential.getId()).orElseThrow();
        MfaConfig updatedMfa = mfaRepository.findByCredentialId(credential.getId()).orElseThrow();
        assertThat(updated.getStatus()).isEqualTo(UserStatus.PENDING_MFA_ENROLLMENT);
        assertThat(updatedMfa.isEnabled()).isFalse();
        assertThat(updatedMfa.getTotpSecretEncrypted()).isNull();
    }

    @Test
    void mfaRecoveryConfirm_invalidToken_returnsBadRequest() throws Exception {
        mockMvc.perform(post(MFA_RECOVERY_BASE + "/confirm")
                        .header("Idempotency-Key", "idem-mfa-recovery-confirm-invalid")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"token\":\"invalid-token\"}"))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.errorCode").value("TOKEN_INVALID"));
    }

    @Test
    void loginWrongPassword_returns401InvalidCredentials() throws Exception {
        createCredential("badpass@example.com", "Correct123!");

        mockMvc.perform(post(BASE + "/login")
                        .header("Idempotency-Key", "idem-bad-pass")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"email\":\"badpass@example.com\",\"password\":\"wrong\"}"))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.errorCode").value("INVALID_CREDENTIALS"));
    }

    @Test
    void mfaVerifyWrongTotp_returns400TotpInvalid() throws Exception {
        AuthCredential credential = createCredential("totp@example.com", "Pass12345!");
        createMfa(credential, "JBSWY3DPEHPK3PXP");

        MvcResult login = mockMvc.perform(post(BASE + "/login")
                        .header("Idempotency-Key", "idem-login-totp")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"email\":\"totp@example.com\",\"password\":\"Pass12345!\"}"))
                .andExpect(status().isOk())
                .andReturn();

        String tx = json(login).get("loginTransactionId").asText();

        mockMvc.perform(post(BASE + "/mfa/verify")
                        .header("Idempotency-Key", "idem-mfa-wrong")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"loginTransactionId\":\"" + tx + "\",\"totpCode\":\"000000\",\"sessionPolicy\":\"HOURS_24\"}"))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.errorCode").value("TOTP_INVALID"));
    }

    @Test
    void mfaVerifyWithoutConfiguration_returns401MfaRequired() throws Exception {
        createCredential("mfa-missing@example.com", "Pass12345!");

        MvcResult login = mockMvc.perform(post(BASE + "/login")
                        .header("Idempotency-Key", "idem-mfa-required-login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"email\":\"mfa-missing@example.com\",\"password\":\"Pass12345!\"}"))
                .andExpect(status().isOk())
                .andReturn();

        String tx = json(login).get("loginTransactionId").asText();

        mockMvc.perform(post(BASE + "/mfa/verify")
                        .header("Idempotency-Key", "idem-mfa-required-verify")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"loginTransactionId\":\"" + tx + "\",\"totpCode\":\"000000\",\"sessionPolicy\":\"HOURS_24\"}"))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.errorCode").value("MFA_REQUIRED"));
    }

    @Test
    void refreshWithoutCookie_returns401RefreshInvalid() throws Exception {
        mockMvc.perform(post(BASE + "/refresh"))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.errorCode").value("REFRESH_INVALID"));
    }

    @Test
    void refreshWithInvalidCookie_returns401RefreshInvalid() throws Exception {
        mockMvc.perform(post(BASE + "/refresh")
                        .cookie(new Cookie("AUTH_REFRESH", "invalid-token")))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.errorCode").value("REFRESH_INVALID"));
    }

    @Test
    void refreshWithTenantHeaderMismatch_returns403TenantMismatch() throws Exception {
        AuthCredential credential = createCredential("tenant-mismatch@example.com", "Pass12345!");
        createMfa(credential, "JBSWY3DPEHPK3PXP");
        String tenantId = "tenant-alpha";
        String otherTenant = "tenant-beta";

        MvcResult loginResult = mockMvc.perform(post(BASE + "/login")
                        .header("Idempotency-Key", "idem-tenant-1")
                        .header("X-Tenant-Id", tenantId)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"email\":\"tenant-mismatch@example.com\",\"password\":\"Pass12345!\"}"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.loginTransactionId").exists())
                .andReturn();

        String loginTransactionId = json(loginResult).get("loginTransactionId").asText();
        String totp = generateTotpNow("JBSWY3DPEHPK3PXP");

        MvcResult mfaResult = mockMvc.perform(post(BASE + "/mfa/verify")
                        .header("Idempotency-Key", "idem-tenant-2")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"loginTransactionId\":\"" + loginTransactionId + "\",\"totpCode\":\"" + totp + "\",\"sessionPolicy\":\"HOURS_24\"}"))
                .andExpect(status().isOk())
                .andReturn();

        String refreshCookie = extractCookieValue(mfaResult.getResponse().getHeader(HttpHeaders.SET_COOKIE), "AUTH_REFRESH");

        mockMvc.perform(post(BASE + "/refresh")
                        .header("X-Tenant-Id", otherTenant)
                        .cookie(new Cookie("AUTH_REFRESH", refreshCookie)))
                .andExpect(status().isForbidden())
                .andExpect(jsonPath("$.errorCode").value("TENANT_MISMATCH"));
    }

    @Test
    void resetWithExpiredToken_returns410TokenExpired() throws Exception {
        AuthCredential credential = createCredential("expired@example.com", "Pass12345!");
        String raw = "prt_expired_token";

        PasswordResetToken token = new PasswordResetToken();
        token.setCredential(credential);
        token.setTokenHash(sha256(raw));
        token.setCreatedAt(Instant.now().minusSeconds(7200));
        token.setExpiresAt(Instant.now().minusSeconds(60));
        passwordResetTokenRepository.save(token);

        mockMvc.perform(post(BASE + "/password/reset")
                        .header("Idempotency-Key", "idem-password-reset-check")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"token\":\"" + raw + "\",\"newPassword\":\"NewPass123!\"}"))
                .andExpect(status().isGone())
                .andExpect(jsonPath("$.errorCode").value("TOKEN_EXPIRED"));
    }

    @Test
    void resetWithInvalidToken_returns400TokenInvalid() throws Exception {
        mockMvc.perform(post(BASE + "/password/reset")
                        .header("Idempotency-Key", "idem-password-reset-invalid")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"token\":\"prt_invalid\",\"newPassword\":\"NewPass123!\"}"))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.errorCode").value("TOKEN_INVALID"));
    }

    @Test
    void passwordResetIdempotencyConflict_returns409() throws Exception {
        createCredential("conflict-reset@example.com", "OldPass123!");

        mockMvc.perform(post(BASE + "/password/forgot")
                        .header("Idempotency-Key", "password-reset-conflict-forgot")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"email\":\"conflict-reset@example.com\"}"))
                .andExpect(status().isAccepted());

        ArgumentCaptor<String> resetTokenCaptor = ArgumentCaptor.forClass(String.class);
        verify(messagingClient, times(1)).sendPasswordReset(anyString(), any(RecoveryChannel.class), resetTokenCaptor.capture());
        String token = resetTokenCaptor.getValue();

        String idempotencyKey = "password-reset-conflict";
        mockMvc.perform(post(BASE + "/password/reset")
                        .header("Idempotency-Key", idempotencyKey)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"token\":\"" + token + "\",\"newPassword\":\"NewPass123!\"}"))
                .andExpect(status().isOk());

        mockMvc.perform(post(BASE + "/password/reset")
                        .header("Idempotency-Key", idempotencyKey)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"token\":\"" + token + "\",\"newPassword\":\"OtherPass123!\"}"))
                .andExpect(status().isConflict())
                .andExpect(jsonPath("$.errorCode").value("IDEMPOTENCY_CONFLICT"));
    }

    @Test
    void passwordChange_authenticated_success() throws Exception {
        AuthCredential credential = createCredential("change@example.com", "Pass12345!");
        createMfa(credential, "JBSWY3DPEHPK3PXP");

        String remoteA = "127.0.0.10";
        String remoteB = "127.0.0.11";

        MvcResult login = mockMvc.perform(withRemoteAddress(post(BASE + "/login")
                        .header("Idempotency-Key", "idem-login-change")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"email\":\"change@example.com\",\"password\":\"Pass12345!\"}"), remoteA))
                .andExpect(status().isOk())
                .andReturn();

        String loginTransactionId = json(login).get("loginTransactionId").asText();
        String totp = generateTotpNow("JBSWY3DPEHPK3PXP");

        MvcResult mfaResult = mockMvc.perform(withRemoteAddress(post(BASE + "/mfa/verify")
                        .header("Idempotency-Key", "idem-mfa-change")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"loginTransactionId\":\"" + loginTransactionId + "\",\"totpCode\":\"" + totp + "\",\"sessionPolicy\":\"HOURS_24\"}"), remoteA))
                .andExpect(status().isOk())
                .andReturn();

        String accessToken = json(mfaResult).get("accessToken").asText();

        mockMvc.perform(withRemoteAddress(post(BASE + "/password/change")
                        .header(HttpHeaders.AUTHORIZATION, "Bearer " + accessToken)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"currentPassword\":\"Pass12345!\",\"newPassword\":\"Changed123!\"}"), remoteB))
                .andExpect(status().isAccepted())
                .andExpect(jsonPath("$.message").value("Password changed successfully"));

        MvcResult loginAfterChange = mockMvc.perform(withRemoteAddress(post(BASE + "/login")
                        .header("Idempotency-Key", "idem-login-change-recheck")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"email\":\"change@example.com\",\"password\":\"Changed123!\"}"), remoteB))
                .andExpect(status().isOk())
                .andReturn();

        String afterChangeTx = json(loginAfterChange).get("loginTransactionId").asText();
        String newTotp = generateTotpNow("JBSWY3DPEHPK3PXP");

        mockMvc.perform(withRemoteAddress(post(BASE + "/mfa/verify")
                        .header("Idempotency-Key", "idem-mfa-change-recheck")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"loginTransactionId\":\"" + afterChangeTx + "\",\"totpCode\":\"" + newTotp + "\",\"sessionPolicy\":\"HOURS_24\"}"), remoteB))
                .andExpect(status().isOk());
    }

    @Test
    void passwordChange_missingAuthorization_returns401InvalidCredentials() throws Exception {
        mockMvc.perform(post(BASE + "/password/change")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"currentPassword\":\"Pass12345!\",\"newPassword\":\"Changed123!\"}"))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.errorCode").value("INVALID_CREDENTIALS"));
    }

    @Test
    void idempotencyConflictSameKeyDifferentBody_returns409() throws Exception {
        createCredential("idem@example.com", "Pass12345!");

        mockMvc.perform(post(BASE + "/login")
                        .header("Idempotency-Key", "idem-conflict")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"email\":\"idem@example.com\",\"password\":\"Pass12345!\"}"))
                .andExpect(status().isOk());

        mockMvc.perform(post(BASE + "/login")
                        .header("Idempotency-Key", "idem-conflict")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"email\":\"idem@example.com\",\"password\":\"Different123!\"}"))
                .andExpect(status().isConflict())
                .andExpect(jsonPath("$.errorCode").value("IDEMPOTENCY_CONFLICT"));
    }

    @Test
    void internalServiceToken_withValidApiKey_returnsServiceToken() throws Exception {
        long ttl = 180;
        String payload = "{\"serviceName\":\"auth-service\",\"tenantId\":\"tenant-1\",\"aud\":[\"company-service\"],\"scopes\":[\"company:create\"],\"ttlSeconds\":" + ttl + "}";

        MvcResult result = mockMvc.perform(post(INTERNAL_TOKENS_SERVICE)
                        .header("Idempotency-Key", "idem-service-token")
                        .header(INTERNAL_API_KEY_HEADER, INTERNAL_API_KEY_VALUE)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(payload))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.accessToken").exists())
                .andExpect(jsonPath("$.tokenType").value("Bearer"))
                .andExpect(jsonPath("$.expiresIn").value((int) ttl))
                .andReturn();

        SignedJWT jwt = SignedJWT.parse(json(result).get("accessToken").asText());
        JWTClaimsSet claims = jwt.getJWTClaimsSet();
        assertThat(claims.getStringClaim("subject_type")).isEqualTo("SERVICE");
        assertThat(claims.getSubject()).isEqualTo("auth-service");
        assertThat(claims.getStringClaim("tenant_id")).isEqualTo("tenant-1");
        assertThat(claims.getAudience()).contains("company-service");
        assertThat(claims.getStringListClaim("scp")).contains("company:create");
    }

    @Test
    void internalServiceToken_invalidApiKey_returns401() throws Exception {
        String payload = "{\"serviceName\":\"auth-service\",\"tenantId\":\"tenant-1\",\"aud\":[\"company-service\"],\"scopes\":[\"company:create\"],\"ttlSeconds\":120}";

        mockMvc.perform(post(INTERNAL_TOKENS_SERVICE)
                        .header("Idempotency-Key", "idem-service-token-missing-key")
                        .header(INTERNAL_API_KEY_HEADER, "wrong-key")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(payload))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.errorCode").value("INTERNAL_API_KEY_INVALID"));
    }

    @Test
    void internalServiceToken_emptyScopes_returns400() throws Exception {
        String payload = "{\"serviceName\":\"auth-service\",\"tenantId\":\"tenant-1\",\"aud\":[\"company-service\"],\"scopes\":[],\"ttlSeconds\":120}";

        mockMvc.perform(post(INTERNAL_TOKENS_SERVICE)
                        .header("Idempotency-Key", "idem-service-token-scope")
                        .header(INTERNAL_API_KEY_HEADER, INTERNAL_API_KEY_VALUE)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(payload))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.errorCode").value("VALIDATION_ERROR"));
    }

    @Test
    void validationErrorPropagatesCorrelationIdHeaderAndErrorFormat() throws Exception {
        String correlationId = "cid-4f0e890d-3c4b-4f2f-b513-6c1a3d9c1a1f";

        MvcResult result = mockMvc.perform(post(BASE + "/login")
                        .header("Idempotency-Key", "idem-correlation-1")
                        .header(CorrelationIdFilter.HEADER_NAME, correlationId)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"email\":\"user@example.com\"}"))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.errorCode").value("VALIDATION_ERROR"))
                .andReturn();

        JsonNode body = json(result);
        assertThat(body.get("correlationId").asText()).isEqualTo(correlationId);
        String expectedPath = result.getRequest().getRequestURI();
        assertThat(body.get("path").asText()).isEqualTo(expectedPath);
        assertThat(body.get("details").asText()).contains("MethodArgumentNotValidException");
        assertThat(body.get("timestamp").asText()).isNotBlank();
        assertThat(result.getResponse().getHeader(CorrelationIdFilter.HEADER_NAME)).isEqualTo(correlationId);
    }

    @Test
    void validationErrorGeneratesCorrelationIdWhenHeaderMissing() throws Exception {
        MvcResult result = mockMvc.perform(post(BASE + "/login")
                        .header("Idempotency-Key", "idem-correlation-2")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"email\":\"user@example.com\"}"))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.errorCode").value("VALIDATION_ERROR"))
                .andExpect(jsonPath("$.correlationId").exists())
                .andReturn();

        String generatedCorrelationId = result.getResponse().getHeader(CorrelationIdFilter.HEADER_NAME);
        assertThat(generatedCorrelationId).isNotBlank();
        assertThat(json(result).get("correlationId").asText()).isEqualTo(generatedCorrelationId);
    }

    @Test
    void registrationStart_successful_createsPendingContext() throws Exception {
        ArgumentCaptor<String> recipientCaptor = ArgumentCaptor.forClass(String.class);
        ArgumentCaptor<String> registrationIdCaptor = ArgumentCaptor.forClass(String.class);
        ArgumentCaptor<String> tokenCaptor = ArgumentCaptor.forClass(String.class);

        MvcResult result = mockMvc.perform(post("/registration/start")
                        .header("Idempotency-Key", "idem-registration-start")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(registrationPayload("starter@example.com")))
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.registrationId").exists())
                .andExpect(jsonPath("$.status").value("PENDING_EMAIL_VERIFICATION"))
                .andReturn();

        JsonNode body = json(result);
        String registrationId = body.get("registrationId").asText();

        assertThat(registrationProcessRepository.findByRegistrationId(registrationId)).isPresent();
        assertThat(credentialRepository.findByLoginEmail("starter@example.com")).isPresent();

        verify(messagingClient).sendRegistrationVerification(recipientCaptor.capture(), registrationIdCaptor.capture(), tokenCaptor.capture());
        assertThat(recipientCaptor.getValue()).isEqualTo("starter@example.com");
        assertThat(registrationIdCaptor.getValue()).isEqualTo(registrationId);
        assertThat(tokenCaptor.getValue()).startsWith("vt_");
        assertThat(verificationTokenRepository.findAll()).hasSize(1);
    }

    @Test
    void registrationStart_duplicateEmail_returnsConflict() throws Exception {
        createCredential("duplicate@example.com", "Pass12345!");

        mockMvc.perform(post("/registration/start")
                        .header("Idempotency-Key", "idem-registration-duplicate")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(registrationPayload("duplicate@example.com")))
                .andExpect(status().isConflict())
                .andExpect(jsonPath("$.errorCode").value("DUPLICATE_EMAIL"));
    }

    @Test
    void registrationStart_requiresIdempotencyKey() throws Exception {
        mockMvc.perform(post("/registration/start")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(registrationPayload("missing@example.com")))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.errorCode").value("VALIDATION_ERROR"));
    }

    @Test
    void registrationVerify_successful_marksEmailVerified() throws Exception {
        ArgumentCaptor<String> registrationIdCaptor = ArgumentCaptor.forClass(String.class);
        ArgumentCaptor<String> tokenCaptor = ArgumentCaptor.forClass(String.class);

        MvcResult start = mockMvc.perform(post("/registration/start")
                        .header("Idempotency-Key", "idem-registration-verify-start")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(registrationPayload("verify@example.com")))
                .andExpect(status().isCreated())
                .andReturn();

        String registrationId = json(start).get("registrationId").asText();
        verify(messagingClient).sendRegistrationVerification(anyString(), registrationIdCaptor.capture(), tokenCaptor.capture());
        String token = tokenCaptor.getValue();

        mockMvc.perform(post("/registration/verify-email")
                        .header("Idempotency-Key", "idem-registration-verify")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"registrationId\":\"" + registrationId + "\",\"verificationToken\":\"" + token + "\"}"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.status").value("EMAIL_VERIFIED"));

        VerificationToken storedToken = verificationTokenRepository.findAll().get(0);
        assertThat(storedToken.getUsedAt()).isNotNull();
        assertThat(credentialRepository.findByLoginEmail("verify@example.com").get().getStatus()).isEqualTo(UserStatus.ACTIVATION_IN_PROGRESS);
    }

    @Test
    void registrationVerify_invalidToken_returnsBadRequest() throws Exception {
        MvcResult start = mockMvc.perform(post("/registration/start")
                        .header("Idempotency-Key", "idem-registration-invalid-start")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(registrationPayload("invalid@example.com")))
                .andExpect(status().isCreated())
                .andReturn();

        String registrationId = json(start).get("registrationId").asText();

        mockMvc.perform(post("/registration/verify-email")
                        .header("Idempotency-Key", "idem-registration-invalid")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"registrationId\":\"" + registrationId + "\",\"verificationToken\":\"vt_invalid\"}"))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.errorCode").value("TOKEN_INVALID"));
    }

    @Test
    void registrationVerify_expiredToken_returnsUnauthorized() throws Exception {
        ArgumentCaptor<String> tokenCaptor = ArgumentCaptor.forClass(String.class);

        MvcResult start = mockMvc.perform(post("/registration/start")
                        .header("Idempotency-Key", "idem-registration-expired-start")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(registrationPayload("expired@example.com")))
                .andExpect(status().isCreated())
                .andReturn();

        String registrationId = json(start).get("registrationId").asText();
        verify(messagingClient).sendRegistrationVerification(anyString(), anyString(), tokenCaptor.capture());
        String token = tokenCaptor.getValue();

        VerificationToken storedToken = verificationTokenRepository.findAll().get(0);
        storedToken.setExpiresAt(Instant.now().minusSeconds(1));
        verificationTokenRepository.save(storedToken);

        mockMvc.perform(post("/registration/verify-email")
                        .header("Idempotency-Key", "idem-registration-expired")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"registrationId\":\"" + registrationId + "\",\"verificationToken\":\"" + token + "\"}"))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.errorCode").value("TOKEN_EXPIRED"));
    }

    @Test
    void socialRegistrationGoogle_successfulCreatesPendingProcess() throws Exception {
        SocialUserInfo googleUser = new SocialUserInfo("google-sub", "social@example.com");
        when(googleSocialProviderClient.fetchUserInfo("google-token")).thenReturn(googleUser);

        mockMvc.perform(post("/registration/social/google")
                        .header("Idempotency-Key", "social-google-success")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(socialRegistrationPayload("google-token")))
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.registrationId").exists())
                .andExpect(jsonPath("$.status").value("PENDING_EMAIL_VERIFICATION"));

        assertThat(identityRepository.findByProviderAndProviderSubject(Provider.GOOGLE, "google-sub")).isPresent();
        assertThat(credentialRepository.findByLoginEmail("social@example.com")).isPresent();
    }

    @Test
    void socialLoginGoogle_successfulCreatesLoginTransaction() throws Exception {
        SocialUserInfo googleUser = new SocialUserInfo("google-login", "social-login@example.com");
        when(googleSocialProviderClient.fetchUserInfo("google-login-token")).thenReturn(googleUser);

        mockMvc.perform(post("/registration/social/google")
                        .header("Idempotency-Key", "social-google-login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(socialRegistrationPayload("google-login-token")))
                .andExpect(status().isCreated());

        mockMvc.perform(post("/auth/social/google")
                        .header("Idempotency-Key", "social-login-google")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(socialLoginPayload("google-login-token")))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.loginTransactionId").exists());
    }

    @Test
    void passwordForgotUnknownEmail_returnsAcceptedWithoutMessaging() throws Exception {
        mockMvc.perform(post(BASE + "/password/forgot")
                        .header("Idempotency-Key", "password-forgot-unknown")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"email\":\"unknown@example.com\"}"))
                .andExpect(status().isAccepted());

        verify(messagingClient, never()).sendPasswordReset(anyString(), any(RecoveryChannel.class), anyString());
    }

    @Test
    void socialRegistrationGoogle_providerUnavailable_returns503() throws Exception {
        when(googleSocialProviderClient.fetchUserInfo("bad-token"))
                .thenThrow(new AppException(HttpStatus.SERVICE_UNAVAILABLE, ErrorCode.SOCIAL_PROVIDER_UNAVAILABLE, "Google provider unavailable"));

        mockMvc.perform(post("/registration/social/google")
                        .header("Idempotency-Key", "social-google-unavailable")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(socialRegistrationPayload("bad-token")))
                .andExpect(status().isServiceUnavailable())
                .andExpect(jsonPath("$.errorCode").value("SOCIAL_PROVIDER_UNAVAILABLE"));
    }

    @Test
    void socialRegistrationGoogle_identityAlreadyLinked_returnsConflict() throws Exception {
        SocialUserInfo googleUser = new SocialUserInfo("google-dup", "dup@example.com");
        when(googleSocialProviderClient.fetchUserInfo("google-dup-token")).thenReturn(googleUser);

        String remoteFirst = "127.0.0.50";
        String remoteSecond = "127.0.0.51";

        mockMvc.perform(withRemoteAddress(post("/registration/social/google")
                        .header("Idempotency-Key", "social-google-dup-1")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(socialRegistrationPayload("google-dup-token")), remoteFirst))
                .andExpect(status().isCreated());

        mockMvc.perform(withRemoteAddress(post("/registration/social/google")
                        .header("Idempotency-Key", "social-google-dup-2")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(socialRegistrationPayload("google-dup-token")), remoteSecond))
                .andExpect(status().isConflict())
                .andExpect(jsonPath("$.errorCode").value("SOCIAL_IDENTITY_ALREADY_LINKED"));
    }

    @Test
    void socialRegistrationGoogle_emailAlreadyUsed_returnsConflict() throws Exception {
        createCredential("conflict@example.com", "Pass12345!");
        SocialUserInfo googleUser = new SocialUserInfo("google-email", "conflict@example.com");
        when(googleSocialProviderClient.fetchUserInfo("google-email-token")).thenReturn(googleUser);

        mockMvc.perform(post("/registration/social/google")
                        .header("Idempotency-Key", "social-google-email-conflict")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(socialRegistrationPayload("google-email-token")))
                .andExpect(status().isConflict())
                .andExpect(jsonPath("$.errorCode").value("EMAIL_ALREADY_USED_BY_OTHER_PROVIDER"));
    }

    @Test
    void socialRegistrationFacebook_successfulCreatesPendingProcess() throws Exception {
        SocialUserInfo facebookUser = new SocialUserInfo("facebook-sub", "social-fb@example.com");
        when(facebookSocialProviderClient.fetchUserInfo("facebook-token")).thenReturn(facebookUser);

        mockMvc.perform(post("/registration/social/facebook")
                        .header("Idempotency-Key", "social-facebook-success")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(socialRegistrationPayload("facebook-token")))
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.registrationId").exists())
                .andExpect(jsonPath("$.status").value("PENDING_EMAIL_VERIFICATION"));

        assertThat(identityRepository.findByProviderAndProviderSubject(Provider.FACEBOOK, "facebook-sub")).isPresent();
        assertThat(credentialRepository.findByLoginEmail("social-fb@example.com")).isPresent();
    }

    @Test
    void socialRegistrationGoogle_replayReturnsStoredResponse() throws Exception {
        SocialUserInfo googleUser = new SocialUserInfo("google-replay", "replay@example.com");
        when(googleSocialProviderClient.fetchUserInfo("google-replay-token")).thenReturn(googleUser);

        String key = "social-google-replay";

        String remoteFirst = "127.0.0.30";
        String remoteSecond = "127.0.0.31";

        MvcResult first = mockMvc.perform(withRemoteAddress(post("/registration/social/google")
                        .header("Idempotency-Key", key)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(socialRegistrationPayload("google-replay-token")), remoteFirst))
                .andExpect(status().isCreated())
                .andReturn();

        String firstId = json(first).get("registrationId").asText();

        MvcResult second = mockMvc.perform(withRemoteAddress(post("/registration/social/google")
                        .header("Idempotency-Key", key)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(socialRegistrationPayload("google-replay-token")), remoteSecond))
                .andExpect(status().isCreated())
                .andReturn();

        String secondId = json(second).get("registrationId").asText();
        assertThat(secondId).isEqualTo(firstId);
        assertThat(idempotencyRepository.findByIdempotencyKey(key)).isPresent();
    }

    @Test
    void socialRegistrationGoogle_idempotencyConflictDifferentPayload() throws Exception {
        SocialUserInfo googleUser = new SocialUserInfo("google-conflict", "conflict@example.com");
        when(googleSocialProviderClient.fetchUserInfo("google-conflict-token")).thenReturn(googleUser);

        String key = "social-google-different";

        String remoteFirst = "127.0.0.40";
        String remoteSecond = "127.0.0.41";

        mockMvc.perform(withRemoteAddress(post("/registration/social/google")
                        .header("Idempotency-Key", key)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(socialRegistrationPayload("google-conflict-token")), remoteFirst))
                .andExpect(status().isCreated());

        mockMvc.perform(withRemoteAddress(post("/registration/social/google")
                        .header("Idempotency-Key", key)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(socialRegistrationPayload("google-conflict-token-alt")), remoteSecond))
                .andExpect(status().isConflict())
                .andExpect(jsonPath("$.errorCode").value("IDEMPOTENCY_CONFLICT"));
    }

    @Test
    void socialRegistrationGoogle_missingIdempotencyKey_returnsBadRequest() throws Exception {
        mockMvc.perform(post("/registration/social/google")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(socialRegistrationPayload("google-missing-key")))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.errorCode").value("VALIDATION_ERROR"));
    }

    @Test
    void registrationStartLogsStructuredFields() throws Exception {
        Logger registrationLogger = (Logger) LoggerFactory.getLogger(RegistrationController.class);
        ListAppender<ILoggingEvent> appender = new ListAppender<>();
        appender.start();
        registrationLogger.addAppender(appender);
        try {
            mockMvc.perform(post("/registration/start")
                            .header("Idempotency-Key", "log-struct-1")
                            .contentType(MediaType.APPLICATION_JSON)
                            .content(registrationPayload("log-structured@example.com")))
                    .andExpect(status().isCreated());
        } finally {
            registrationLogger.detachAppender(appender);
        }

        assertThat(appender.list)
                .anyMatch(event -> event.getFormattedMessage().contains("eventName=registration.start")
                        && event.getFormattedMessage().contains("targetService=auth-service")
                        && event.getFormattedMessage().contains("outcome=SUCCESS"));
    }

    @Test
    void supportDiagnosisReturnsMetricsForTenant() throws Exception {
        mockMvc.perform(post("/registration/start")
                        .header("Idempotency-Key", "support-start-data")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(registrationPayload("support-diagnosis@example.com")))
                .andExpect(status().isCreated());

        mockMvc.perform(get("/support/diagnosis")
                        .header("X-Support-User-Id", "support-user")
                        .header("X-Support-Role", "SUPPORT_AGENT")
                        .header("X-Support-Purpose", "Check tenant health")
                        .param("tenantId", "tenant-1"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.resolvedTenantId").value("tenant-1"))
                .andExpect(jsonPath("$.supportUserId").value("support-user"))
                .andExpect(jsonPath("$.details.pendingRegistrations").value(1));
    }

    @Test
    void supportDiagnosisWithoutCredentialsIsRejected() throws Exception {
        mockMvc.perform(get("/support/diagnosis")
                        .header("X-Support-Purpose", "Check tenant health")
                        .param("tenantId", "tenant-1"))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.errorCode").value("ACCESS_DENIED"));
    }

    @Test
    void supportDiagnosisWithoutTenantContextIsRejected() throws Exception {
        mockMvc.perform(get("/support/diagnosis")
                        .header("X-Support-User-Id", "support-user")
                        .header("X-Support-Role", "SUPPORT_AGENT")
                        .header("X-Support-Purpose", "Diagnose"))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.errorCode").value("VALIDATION_ERROR"));
    }

    @Test
    void loginStructuredLogIncludesMetadata() throws Exception {
        authLogAppender.list.clear();
        createCredential("logentry@example.com", "P@ssw0rd!");

        mockMvc.perform(post(BASE + "/login")
                        .header("Idempotency-Key", "log-structured-key")
                        .header("X-Tenant-Id", "tenant-structured")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"email\":\"logentry@example.com\",\"password\":\"P@ssw0rd!\"}"))
                .andExpect(status().isOk());

        assertThat(authLogAppender.list).anyMatch(event -> {
            String message = event.getFormattedMessage();
            return message.contains("eventName=auth.login.password")
                    && message.contains("outcome=SUCCESS")
                    && message.contains("idempotencyKey=log-structured-key")
                    && message.contains("correlationId=");
        });
    }

    @Test
    void loginFailureLogsFailureOutcome() throws Exception {
        authLogAppender.list.clear();
        createCredential("fail@example.com", "P@ssw0rd!");

        mockMvc.perform(post(BASE + "/login")
                        .header("Idempotency-Key", "log-structured-fail")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"email\":\"fail@example.com\",\"password\":\"WrongPass123!\"}"))
                .andExpect(status().isUnauthorized());

        assertThat(authLogAppender.list)
                .anyMatch(event -> event.getFormattedMessage().contains("eventName=auth.login.password")
                        && event.getFormattedMessage().contains("outcome=FAILURE")
                        && event.getFormattedMessage().contains("errorCode=INVALID_CREDENTIALS"));
    }

    private ResultActions loginRequest(String tenantId, String idempotencyKey, String email, String password) throws Exception {
        MockHttpServletRequestBuilder builder = post(BASE + "/login")
                .header("Idempotency-Key", idempotencyKey)
                .header("X-Tenant-Id", tenantId)
                .contentType(MediaType.APPLICATION_JSON)
                .content("{\"email\":\"" + email + "\",\"password\":\"" + password + "\"}")
                .with(request -> {
                    request.setRemoteAddr("127.0.0.1");
                    return request;
                });
        return mockMvc.perform(builder);
    }

    private MockHttpServletRequestBuilder withRemoteAddress(MockHttpServletRequestBuilder builder, String remoteAddr) {
        return builder.with(request -> {
            request.setRemoteAddr(remoteAddr);
            return request;
        });
    }

    private AuthCredential createCredential(String email, String password) {
        AuthCredential credential = new AuthCredential();
        credential.setUserId(UUID.randomUUID().toString());
        credential.setLoginEmail(email);
        credential.setPasswordHash(ENCODER.encode(password));
        credential.setStatus(UserStatus.ACTIVE);
        credential.setEmailVerified(true);
        credential.setFailedAttempts(0);
        credential.setCreatedAt(Instant.now());
        credential.setModifiedAt(Instant.now());
        return credentialRepository.save(credential);
    }

    private void createMfa(AuthCredential credential, String secretBase32) {
        MfaConfig mfa = new MfaConfig();
        mfa.setCredential(credential);
        mfa.setEnabled(true);
        mfa.setTotpSecretEncrypted(secretBase32);
        mfa.setSecondFactorType("TOTP");
        mfa.setEmailChannelEnabled(true);
        mfa.setSmsChannelEnabled(true);
        mfa.setCreatedAt(Instant.now());
        mfa.setUpdatedAt(Instant.now());
        mfaRepository.save(mfa);
    }

    private JsonNode json(MvcResult result) throws Exception {
        return objectMapper.readTree(result.getResponse().getContentAsString());
    }

    private String extractCookieValue(String setCookieHeader, String cookieName) {
        assertThat(setCookieHeader).isNotBlank();
        String prefix = cookieName + "=";
        int start = setCookieHeader.indexOf(prefix);
        assertThat(start).isGreaterThanOrEqualTo(0);
        int valueStart = start + prefix.length();
        int end = setCookieHeader.indexOf(';', valueStart);
        if (end < 0) {
            end = setCookieHeader.length();
        }
        return setCookieHeader.substring(valueStart, end);
    }

    private String generateTotpNow(String secretBase32) {
        byte[] key = decodeBase32(secretBase32);
        long step = Instant.now().getEpochSecond() / 30;
        return generateTotp(key, step, 6);
    }

    private String generateTotp(byte[] key, long counter, int digits) {
        try {
            byte[] data = ByteBuffer.allocate(8).putLong(counter).array();
            Mac mac = Mac.getInstance("HmacSHA1");
            mac.init(new SecretKeySpec(key, "HmacSHA1"));
            byte[] hash = mac.doFinal(data);
            int offset = hash[hash.length - 1] & 0x0F;
            int binary = ((hash[offset] & 0x7F) << 24)
                    | ((hash[offset + 1] & 0xFF) << 16)
                    | ((hash[offset + 2] & 0xFF) << 8)
                    | (hash[offset + 3] & 0xFF);
            int otp = binary % (int) Math.pow(10, digits);
            return String.format("%0" + digits + "d", otp);
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    private byte[] decodeBase32(String value) {
        String alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
        int buffer = 0;
        int bitsLeft = 0;
        java.util.ArrayList<Byte> out = new java.util.ArrayList<>();
        for (char c : value.replace(" ", "").replace("=", "").toUpperCase().toCharArray()) {
            int val = alphabet.indexOf(c);
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

    private void configureAuthLogging() {
        Logger authLogger = (Logger) LoggerFactory.getLogger(AuthController.class);
        if (authLogAppender != null) {
            authLogger.detachAppender(authLogAppender);
        }
        authLogAppender = new ListAppender<>();
        authLogAppender.start();
        authLogger.addAppender(authLogAppender);
    }

    private String sha256(String input) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hashed = digest.digest(input.getBytes(StandardCharsets.UTF_8));
            StringBuilder sb = new StringBuilder();
            for (byte b : hashed) {
                sb.append(String.format("%02x", b));
            }
            return sb.toString();
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    private String registrationPayload(String email) {
        return """
                {
                  "tenantId": "tenant-1",
                  "userEmail": "%s",
                  "userPassword": "Pass12345!",
                  "companyPayload": {"companyName": "Acme GmbH"},
                  "locationPayload": {"city": "Berlin"},
                  "userPayload": {"firstName": "Max", "lastName": "Mustermann"}
                }
                """.formatted(email).trim();
    }

    private String socialRegistrationPayload(String token) {
        return """
                {
                  "tenantId": "tenant-social",
                  "companyPayload": {"companyName": "Social Co"},
                  "locationPayload": {"city": "Hamburg"},
                  "userPayload": {"firstName": "Social", "lastName": "User"},
                  "socialToken": "%s"
                }
                """.formatted(token);
    }

    private String socialLoginPayload(String token) {
        return "{\"socialToken\":\"" + token + "\"}";
    }

    @Test
    void registrationMfaEnroll_successful_preparesTotpData() throws Exception {
        RegistrationSetup setup = startRegistrationAndCaptureToken("mfa-enroll@example.com", "idem-mfa-enroll-success-start");
        verifyRegistrationEmail(setup.registrationId(), setup.verificationToken(), "idem-mfa-enroll-success-verify");

        MvcResult enroll = mockMvc.perform(post("/registration/mfa/totp/enroll")
                        .header("Idempotency-Key", "idem-mfa-enroll-success")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"registrationId\":\"" + setup.registrationId() + "\"}"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.secret").isString())
                .andExpect(jsonPath("$.otpauthUri").isString())
                .andExpect(jsonPath("$.status").value("MFA_ENROLLMENT_PREPARED"))
                .andReturn();

        String secret = json(enroll).get("secret").asText();
        AuthCredential credential = credentialRepository.findByLoginEmail("mfa-enroll@example.com").orElseThrow();
        MfaConfig config = mfaRepository.findByCredentialId(credential.getId()).orElseThrow();

        assertThat(config.isEnabled()).isFalse();
        assertThat(config.getTotpSecretEncrypted()).isEqualTo(secret);
        assertThat(config.getSecondFactorType()).isEqualTo("TOTP");
        assertThat(credential.getStatus()).isEqualTo(UserStatus.ACTIVATION_IN_PROGRESS);
    }

    @Test
    void registrationMfaEnroll_requiresEmailVerified() throws Exception {
        RegistrationSetup setup = startRegistrationAndCaptureToken("mfa-unverified@example.com", "idem-mfa-enroll-unverified-start");

        mockMvc.perform(post("/registration/mfa/totp/enroll")
                        .header("Idempotency-Key", "idem-mfa-enroll-unverified")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"registrationId\":\"" + setup.registrationId() + "\"}"))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.errorCode").value("EMAIL_NOT_VERIFIED"));
    }

    @Test
    void registrationMfaConfirm_successful_activatesAfterTotp() throws Exception {
        RegistrationSetup setup = startRegistrationAndCaptureToken("mfa-confirm@example.com", "idem-mfa-confirm-start");
        verifyRegistrationEmail(setup.registrationId(), setup.verificationToken(), "idem-mfa-confirm-verify");

        String secret = json(mockMvc.perform(post("/registration/mfa/totp/enroll")
                                .header("Idempotency-Key", "idem-mfa-confirm-enroll")
                                .contentType(MediaType.APPLICATION_JSON)
                                .content("{\"registrationId\":\"" + setup.registrationId() + "\"}"))
                        .andExpect(status().isOk()).andReturn())
                .get("secret").asText();
        String totp = generateTotpNow(secret);

        mockMvc.perform(post("/registration/mfa/totp/confirm")
                        .header("Idempotency-Key", "idem-mfa-confirm")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"registrationId\":\"" + setup.registrationId() + "\",\"totpCode\":\"" + totp + "\"}"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.status").value("ACTIVE"));

        AuthCredential credential = credentialRepository.findByLoginEmail("mfa-confirm@example.com").orElseThrow();
        assertThat(credential.getStatus()).isEqualTo(UserStatus.ACTIVE);
        MfaConfig config = mfaRepository.findByCredentialId(credential.getId()).orElseThrow();
        assertThat(config.isEnabled()).isTrue();
        assertThat(config.getEnrolledAt()).isNotNull();

        RegistrationProcess process = registrationProcessRepository.findByRegistrationId(setup.registrationId()).orElseThrow();
        assertThat(process.getStatus()).isEqualTo("ACTIVE");
    }

    @Test
    void registrationMfaConfirm_invalidTotp_returnsBadRequest() throws Exception {
        RegistrationSetup setup = startRegistrationAndCaptureToken("mfa-confirm-invalid@example.com", "idem-mfa-confirm-invalid-start");
        verifyRegistrationEmail(setup.registrationId(), setup.verificationToken(), "idem-mfa-confirm-invalid-verify");

        String secret = json(mockMvc.perform(post("/registration/mfa/totp/enroll")
                                .header("Idempotency-Key", "idem-mfa-confirm-invalid-enroll")
                                .contentType(MediaType.APPLICATION_JSON)
                                .content("{\"registrationId\":\"" + setup.registrationId() + "\"}"))
                        .andExpect(status().isOk()).andReturn())
                .get("secret").asText();

        mockMvc.perform(post("/registration/mfa/totp/confirm")
                        .header("Idempotency-Key", "idem-mfa-confirm-invalid")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"registrationId\":\"" + setup.registrationId() + "\",\"totpCode\":\"000000\"}"))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.errorCode").value("TOTP_INVALID"));

        AuthCredential credential = credentialRepository.findByLoginEmail("mfa-confirm-invalid@example.com").orElseThrow();
        assertThat(credential.getStatus()).isEqualTo(UserStatus.ACTIVATION_IN_PROGRESS);
        MfaConfig config = mfaRepository.findByCredentialId(credential.getId()).orElseThrow();
        assertThat(config.isEnabled()).isFalse();
    }

    private RegistrationSetup startRegistrationAndCaptureToken(String email, String idempotencyKey) throws Exception {
        ArgumentCaptor<String> registrationIdCaptor = ArgumentCaptor.forClass(String.class);
        ArgumentCaptor<String> tokenCaptor = ArgumentCaptor.forClass(String.class);

        MvcResult start = mockMvc.perform(post("/registration/start")
                        .header("Idempotency-Key", idempotencyKey)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(registrationPayload(email)))
                .andExpect(status().isCreated())
                .andReturn();

        String registrationId = json(start).get("registrationId").asText();
        verify(messagingClient).sendRegistrationVerification(anyString(), registrationIdCaptor.capture(), tokenCaptor.capture());
        assertThat(registrationIdCaptor.getValue()).isEqualTo(registrationId);
        return new RegistrationSetup(registrationId, tokenCaptor.getValue());
    }

    private void verifyRegistrationEmail(String registrationId, String token, String idempotencyKey) throws Exception {
        mockMvc.perform(post("/registration/verify-email")
                        .header("Idempotency-Key", idempotencyKey)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"registrationId\":\"" + registrationId + "\",\"verificationToken\":\"" + token + "\"}"))
                .andExpect(status().isOk());
    }

    private static record RegistrationSetup(String registrationId, String verificationToken) {
    }

    @Test
    void registrationActivation_success_callsDownstreamClients() throws Exception {
        RegistrationSetup setup = startRegistrationAndCaptureToken("mfa-activation@example.com", "idem-mfa-activation-start");
        verifyRegistrationEmail(setup.registrationId(), setup.verificationToken(), "idem-mfa-activation-verify");

        String secret = json(mockMvc.perform(post("/registration/mfa/totp/enroll")
                                .header("Idempotency-Key", "idem-mfa-activation-enroll")
                                .contentType(MediaType.APPLICATION_JSON)
                                .content("{\"registrationId\":\"" + setup.registrationId() + "\"}"))
                        .andExpect(status().isOk()).andReturn())
                .get("secret").asText();
        String totp = generateTotpNow(secret);

        mockMvc.perform(post("/registration/mfa/totp/confirm")
                        .header("Idempotency-Key", "idem-mfa-activation-confirm")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"registrationId\":\"" + setup.registrationId() + "\",\"totpCode\":\"" + totp + "\"}"))
                .andExpect(status().isOk());

        verify(userServiceClient).activate(any());
        verify(companyServiceClient).activate(any());
        verify(iamServiceClient).assignTenantAdmin(any());
    }

    @Test
    void registrationActivation_userServiceDown_returns503() throws Exception {
        doThrow(new AppException(HttpStatus.SERVICE_UNAVAILABLE, ErrorCode.DOWNSTREAM_USER_UNAVAILABLE, "user service unavailable"))
                .when(userServiceClient).activate(any());

        RegistrationSetup setup = startRegistrationAndCaptureToken("mfa-activation-user-down@example.com", "idem-mfa-activation-user-start");
        verifyRegistrationEmail(setup.registrationId(), setup.verificationToken(), "idem-mfa-activation-user-verify");

        String secret = json(mockMvc.perform(post("/registration/mfa/totp/enroll")
                                .header("Idempotency-Key", "idem-mfa-activation-user-enroll")
                                .contentType(MediaType.APPLICATION_JSON)
                                .content("{\"registrationId\":\"" + setup.registrationId() + "\"}"))
                        .andExpect(status().isOk()).andReturn())
                .get("secret").asText();
        String totp = generateTotpNow(secret);

        mockMvc.perform(post("/registration/mfa/totp/confirm")
                        .header("Idempotency-Key", "idem-mfa-activation-user-confirm")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"registrationId\":\"" + setup.registrationId() + "\",\"totpCode\":\"" + totp + "\"}"))
                .andExpect(status().isServiceUnavailable())
                .andExpect(jsonPath("$.errorCode").value("DOWNSTREAM_USER_UNAVAILABLE"));

        verify(companyServiceClient, never()).activate(any());
        verify(iamServiceClient, never()).assignTenantAdmin(any());
    }

    @Test
    void registrationActivation_companyServiceDown_returns503() throws Exception {
        doThrow(new AppException(HttpStatus.SERVICE_UNAVAILABLE, ErrorCode.DOWNSTREAM_COMPANY_UNAVAILABLE, "company service unavailable"))
                .when(companyServiceClient).activate(any());

        RegistrationSetup setup = startRegistrationAndCaptureToken("mfa-activation-company-down@example.com", "idem-mfa-activation-company-start");
        verifyRegistrationEmail(setup.registrationId(), setup.verificationToken(), "idem-mfa-activation-company-verify");

        String secret = json(mockMvc.perform(post("/registration/mfa/totp/enroll")
                                .header("Idempotency-Key", "idem-mfa-activation-company-enroll")
                                .contentType(MediaType.APPLICATION_JSON)
                                .content("{\"registrationId\":\"" + setup.registrationId() + "\"}"))
                        .andExpect(status().isOk()).andReturn())
                .get("secret").asText();
        String totp = generateTotpNow(secret);

        mockMvc.perform(post("/registration/mfa/totp/confirm")
                        .header("Idempotency-Key", "idem-mfa-activation-company-confirm")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"registrationId\":\"" + setup.registrationId() + "\",\"totpCode\":\"" + totp + "\"}"))
                .andExpect(status().isServiceUnavailable())
                .andExpect(jsonPath("$.errorCode").value("DOWNSTREAM_COMPANY_UNAVAILABLE"));

        verify(iamServiceClient, never()).assignTenantAdmin(any());
    }

    @Test
    void registrationActivation_iamServiceDown_returns503() throws Exception {
        doThrow(new AppException(HttpStatus.SERVICE_UNAVAILABLE, ErrorCode.DOWNSTREAM_IAM_UNAVAILABLE, "iam service unavailable"))
                .when(iamServiceClient).assignTenantAdmin(any());

        RegistrationSetup setup = startRegistrationAndCaptureToken("mfa-activation-iam-down@example.com", "idem-mfa-activation-iam-start");
        verifyRegistrationEmail(setup.registrationId(), setup.verificationToken(), "idem-mfa-activation-iam-verify");

        String secret = json(mockMvc.perform(post("/registration/mfa/totp/enroll")
                                .header("Idempotency-Key", "idem-mfa-activation-iam-enroll")
                                .contentType(MediaType.APPLICATION_JSON)
                                .content("{\"registrationId\":\"" + setup.registrationId() + "\"}"))
                        .andExpect(status().isOk()).andReturn())
                .get("secret").asText();
        String totp = generateTotpNow(secret);

        mockMvc.perform(post("/registration/mfa/totp/confirm")
                        .header("Idempotency-Key", "idem-mfa-activation-iam-confirm")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"registrationId\":\"" + setup.registrationId() + "\",\"totpCode\":\"" + totp + "\"}"))
                .andExpect(status().isServiceUnavailable())
                .andExpect(jsonPath("$.errorCode").value("DOWNSTREAM_IAM_UNAVAILABLE"));
    }
}




