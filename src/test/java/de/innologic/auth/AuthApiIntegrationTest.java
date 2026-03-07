package de.innologic.auth;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import de.innologic.auth.domain.entity.Credential;
import de.innologic.auth.security.jwt.JwtTokenService;
import de.innologic.auth.domain.entity.Mfa;
import de.innologic.auth.domain.entity.PasswordResetToken;
import de.innologic.auth.domain.enums.RecoveryChannel;
import de.innologic.auth.domain.enums.UserStatus;
import de.innologic.auth.domain.repository.CredentialRepository;
import de.innologic.auth.domain.repository.IdempotencyRepository;
import de.innologic.auth.domain.repository.MfaRecoveryTokenRepository;
import de.innologic.auth.domain.repository.MfaRepository;
import de.innologic.auth.domain.repository.PasswordResetTokenRepository;
import de.innologic.auth.domain.repository.SessionRepository;
import de.innologic.auth.messaging.MessagingClient;
import de.innologic.auth.web.filter.CorrelationIdFilter;
import jakarta.servlet.http.Cookie;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
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
    private MfaRepository mfaRepository;

    @Autowired
    private SessionRepository sessionRepository;

    @Autowired
    private IdempotencyRepository idempotencyRepository;

    @Autowired
    private PasswordResetTokenRepository passwordResetTokenRepository;

    @Autowired
    private MfaRecoveryTokenRepository mfaRecoveryTokenRepository;

    @MockitoBean
    private MessagingClient messagingClient;

    @BeforeEach
    void clean() {
        sessionRepository.deleteAll();
        mfaRecoveryTokenRepository.deleteAll();
        passwordResetTokenRepository.deleteAll();
        mfaRepository.deleteAll();
        idempotencyRepository.deleteAll();
        credentialRepository.deleteAll();
    }

    @Test
    void loginMfaRefreshLogout_happyPath() throws Exception {
        Credential credential = createCredential("user@example.com", "P@ssw0rd!");
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
        Credential credential = createCredential("mfa@example.com", "Pass12345!");
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

        Credential updated = credentialRepository.findById(credential.getId()).orElseThrow();
        Mfa updatedMfa = mfaRepository.findByCredentialId(credential.getId()).orElseThrow();
        assertThat(updated.getUserStatus()).isEqualTo(UserStatus.PENDING_MFA_ENROLLMENT);
        assertThat(updatedMfa.isEnabled()).isFalse();
        assertThat(updatedMfa.getSecretEncrypted()).isNull();
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
        Credential credential = createCredential("totp@example.com", "Pass12345!");
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
        Credential credential = createCredential("expired@example.com", "Pass12345!");
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

    private Credential createCredential(String email, String password) {
        Credential credential = new Credential();
        credential.setEmail(email);
        credential.setPasswordHash(ENCODER.encode(password));
        credential.setUserStatus(UserStatus.ACTIVE);
        credential.setEmailVerified(true);
        credential.setFailedLoginAttempts(0);
        credential.setCreatedAt(Instant.now());
        credential.setUpdatedAt(Instant.now());
        return credentialRepository.save(credential);
    }

    private void createMfa(Credential credential, String secretBase32) {
        Mfa mfa = new Mfa();
        mfa.setCredential(credential);
        mfa.setEnabled(true);
        mfa.setSecretEncrypted(secretBase32);
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
}
