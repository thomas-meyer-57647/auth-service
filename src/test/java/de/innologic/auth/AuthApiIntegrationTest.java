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
import de.innologic.auth.messaging.MessagingClient;
import de.innologic.auth.outbound.CompanyServiceClient;
import de.innologic.auth.outbound.IamServiceClient;
import de.innologic.auth.outbound.UserServiceClient;
import de.innologic.auth.security.jwt.JwtTokenService;
import de.innologic.auth.web.error.AppException;
import de.innologic.auth.web.error.ErrorCode;
import de.innologic.auth.web.filter.CorrelationIdFilter;
import jakarta.servlet.http.Cookie;
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

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.Instant;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
@AutoConfigureMockMvc(addFilters = false)
@ActiveProfiles("test")
class AuthApiIntegrationTest {

    private static final String BASE = "/auth";
    private static final BCryptPasswordEncoder ENCODER = new BCryptPasswordEncoder();
    private static final String INTERNAL_API_KEY_HEADER = "X-Internal-Api-Key";
    private static final String INTERNAL_API_KEY_VALUE = "internal-test-key";

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private ObjectMapper objectMapper;

    @Autowired
    private JwtTokenService jwtTokenService;

    @Autowired
    private CredentialRepository credentialRepository;

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

    @MockitoBean
    private MessagingClient messagingClient;

    @MockBean
    private UserServiceClient userServiceClient;

    @MockBean
    private CompanyServiceClient companyServiceClient;

    @MockBean
    private IamServiceClient iamServiceClient;

    @BeforeEach
    void clean() {
        verificationTokenRepository.deleteAll();
        registrationProcessRepository.deleteAll();
        sessionRepository.deleteAll();
        mfaRecoveryTokenRepository.deleteAll();
        passwordResetTokenRepository.deleteAll();
        mfaRepository.deleteAll();
        idempotencyRepository.deleteAll();
        credentialRepository.deleteAll();
    }

    @Test
    void loginMfaRefreshLogout_happyPath() throws Exception {
        AuthCredential credential = createCredential("user@example.com", "P@ssw0rd!");
        createMfa(credential, "JBSWY3DPEHPK3PXP");

        MvcResult loginResult = mockMvc.perform(post(BASE + "/login")
                        .header("Idempotency-Key", "idem-login-1")
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
        assertThat(accessClaims.getStringClaim("tenant_id")).isNotBlank();
        assertThat(accessClaims.getAudience()).contains("auth-api");
        assertThat(accessClaims.getIssuer()).isNotBlank();
        assertThat(accessClaims.getSubject()).isNotBlank();
        assertThat(accessClaims.getJWTID()).isNotBlank();
        assertThat(accessClaims.getIssueTime()).isNotNull();
        assertThat(accessClaims.getExpirationTime()).isNotNull();

        String refreshCookie = extractCookieValue(mfaResult.getResponse().getHeader(HttpHeaders.SET_COOKIE), "AUTH_REFRESH");
        assertThat(refreshCookie).isNotBlank();

        MvcResult refreshResult = mockMvc.perform(post(BASE + "/refresh")
                        .cookie(new Cookie("AUTH_REFRESH", refreshCookie)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.accessToken").exists())
                .andReturn();

        String rotatedRefresh = extractCookieValue(refreshResult.getResponse().getHeader(HttpHeaders.SET_COOKIE), "AUTH_REFRESH");
        assertThat(rotatedRefresh).isNotBlank();
        assertThat(rotatedRefresh).isNotEqualTo(refreshCookie);

        mockMvc.perform(post(BASE + "/logout")
                        .cookie(new Cookie("AUTH_REFRESH", rotatedRefresh)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.message").value("Logged out"));

        assertThat(sessionRepository.findAll()).allMatch(s -> s.getRevokedAt() != null);
    }

    @Test
    void forgotThenResetPassword_happyPath() throws Exception {
        createCredential("reset@example.com", "OldPass123!");

        mockMvc.perform(post(BASE + "/password/forgot")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"email\":\"reset@example.com\"}"))
                .andExpect(status().isAccepted());

        ArgumentCaptor<String> resetTokenCaptor = ArgumentCaptor.forClass(String.class);
        verify(messagingClient, times(1)).sendPasswordReset(anyString(), resetTokenCaptor.capture());
        String rawToken = resetTokenCaptor.getValue();

        mockMvc.perform(post(BASE + "/password/reset")
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
    void mfaRecoveryStartConfirm_happyPath_setsReEnrollFlag() throws Exception {
        AuthCredential credential = createCredential("mfa@example.com", "Pass12345!");
        createMfa(credential, "JBSWY3DPEHPK3PXP");

        mockMvc.perform(post(BASE + "/mfa/recovery/start")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"email\":\"mfa@example.com\",\"channel\":\"EMAIL\"}"))
                .andExpect(status().isAccepted());

        ArgumentCaptor<String> recoveryToken = ArgumentCaptor.forClass(String.class);
        verify(messagingClient, times(1)).sendMfaRecovery(anyString(), any(RecoveryChannel.class), recoveryToken.capture());

        mockMvc.perform(post(BASE + "/mfa/recovery/confirm")
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
    void refreshWithoutCookie_returns401RefreshInvalid() throws Exception {
        mockMvc.perform(post(BASE + "/refresh"))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.errorCode").value("REFRESH_INVALID"));
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
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"token\":\"" + raw + "\",\"newPassword\":\"NewPass123!\"}"))
                .andExpect(status().isGone())
                .andExpect(jsonPath("$.errorCode").value("TOKEN_EXPIRED"));
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
        long ttl = jwtTokenService.getServiceTokenTtlSeconds();
        String payload = "{\"serviceName\":\"auth-service\",\"tenantId\":\"tenant-1\",\"aud\":[\"company-service\"],\"scopes\":[\"company:create\"]}";

        MvcResult result = mockMvc.perform(post(BASE + "/internal/service-token")
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
    void internalServiceToken_missingApiKey_returns401() throws Exception {
        String payload = "{\"serviceName\":\"auth-service\",\"tenantId\":\"tenant-1\",\"aud\":[\"company-service\"],\"scopes\":[\"company:create\"]}";

        mockMvc.perform(post(BASE + "/internal/service-token")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(payload))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.errorCode").value("INTERNAL_API_KEY_INVALID"));
    }

    @Test
    void internalServiceToken_emptyScopes_returns400() throws Exception {
        String payload = "{\"serviceName\":\"auth-service\",\"tenantId\":\"tenant-1\",\"aud\":[\"company-service\"],\"scopes\":[]}";

        mockMvc.perform(post(BASE + "/internal/service-token")
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

    private AuthCredential createCredential(String email, String password) {
        AuthCredential credential = new AuthCredential();
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
