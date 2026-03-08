package de.innologic.auth;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import de.innologic.auth.domain.repository.CredentialRepository;
import de.innologic.auth.domain.repository.IdempotencyRepository;
import de.innologic.auth.domain.repository.MfaConfigRepository;
import de.innologic.auth.domain.repository.PasswordResetTokenRepository;
import de.innologic.auth.domain.repository.RegistrationProcessRepository;
import de.innologic.auth.domain.repository.VerificationTokenRepository;
import de.innologic.auth.messaging.MessagingClient;
import de.innologic.auth.outbound.CompanyServiceClient;
import de.innologic.auth.outbound.IamServiceClient;
import de.innologic.auth.outbound.UserServiceClient;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.verify;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest(properties = "AUTH_MFA_ENABLED=false")
@AutoConfigureMockMvc(addFilters = false)
@ActiveProfiles("test")
class AuthApiMfaDisabledIntegrationTest {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private ObjectMapper objectMapper;

    @Autowired
    private CredentialRepository credentialRepository;

    @Autowired
    private IdempotencyRepository idempotencyRepository;

    @Autowired
    private MfaConfigRepository mfaRepository;

    @Autowired
    private PasswordResetTokenRepository passwordResetTokenRepository;

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
        passwordResetTokenRepository.deleteAll();
        mfaRepository.deleteAll();
        idempotencyRepository.deleteAll();
        credentialRepository.deleteAll();
    }

    @Test
    void registrationMfaEnroll_whenMfaDisabled_returnsMfaNotEnrolled() throws Exception {
        ArgumentCaptor<String> registrationIdCaptor = ArgumentCaptor.forClass(String.class);
        ArgumentCaptor<String> tokenCaptor = ArgumentCaptor.forClass(String.class);

        MvcResult start = mockMvc.perform(post("/registration/start")
                        .header("Idempotency-Key", "idem-mfa-disabled-start")
                        .contentType("application/json")
                        .content(registrationPayload("mfa-disabled@example.com")))
                .andExpect(status().isCreated())
                .andReturn();

        String registrationId = json(start).get("registrationId").asText();
        verify(messagingClient).sendRegistrationVerification(anyString(), registrationIdCaptor.capture(), tokenCaptor.capture());
        assertThat(registrationIdCaptor.getValue()).isEqualTo(registrationId);

        mockMvc.perform(post("/registration/verify-email")
                        .header("Idempotency-Key", "idem-mfa-disabled-verify")
                        .contentType("application/json")
                        .content("{\"registrationId\":\"" + registrationId + "\",\"verificationToken\":\"" + tokenCaptor.getValue() + "\"}"))
                .andExpect(status().isOk());

        mockMvc.perform(post("/registration/mfa/totp/enroll")
                        .header("Idempotency-Key", "idem-mfa-disabled")
                        .contentType("application/json")
                        .content("{\"registrationId\":\"" + registrationId + "\"}"))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.errorCode").value("MFA_NOT_ENROLLED"));
    }

    private JsonNode json(MvcResult result) throws Exception {
        return objectMapper.readTree(result.getResponse().getContentAsString());
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
}
