package de.innologic.auth.outbound;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import de.innologic.auth.domain.entity.AuthCredential;
import de.innologic.auth.domain.entity.RegistrationProcess;
import de.innologic.auth.outbound.dto.CompanyActivationRequest;
import de.innologic.auth.outbound.dto.IamTenantAdminRequest;
import de.innologic.auth.outbound.dto.UserActivationRequest;
import de.innologic.auth.web.error.AppException;
import de.innologic.auth.web.error.ErrorCode;
import de.innologic.auth.web.filter.CorrelationIdFilter;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.slf4j.MDC;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;

import java.util.List;

@Component
public class ActivationOrchestrator {

    private static final Logger log = LoggerFactory.getLogger(ActivationOrchestrator.class);

    private final UserServiceClient userServiceClient;
    private final CompanyServiceClient companyServiceClient;
    private final IamServiceClient iamServiceClient;
    private final ObjectMapper objectMapper;

    public ActivationOrchestrator(UserServiceClient userServiceClient,
                                  CompanyServiceClient companyServiceClient,
                                  IamServiceClient iamServiceClient,
                                  ObjectMapper objectMapper) {
        this.userServiceClient = userServiceClient;
        this.companyServiceClient = companyServiceClient;
        this.iamServiceClient = iamServiceClient;
        this.objectMapper = objectMapper;
    }

    public void activate(RegistrationProcess process, AuthCredential credential) {
        log.info("Starting activation orchestrator for registrationId={} correlationId={}", process.getRegistrationId(), correlationId());
        JsonNode companyPayload = parsePayload(process.getCompanyPayload());
        JsonNode locationPayload = parsePayload(process.getLocationPayload());
        JsonNode userPayload = parsePayload(process.getUserPayload());

        UserActivationRequest userRequest = buildUserRequest(credential, userPayload, companyPayload);
        userServiceClient.activate(userRequest);

        CompanyActivationRequest companyRequest = buildCompanyRequest(companyPayload, locationPayload);
        companyServiceClient.activate(companyRequest);

        IamTenantAdminRequest iamRequest = buildIamRequest(process.getTenantId(), credential);
        iamServiceClient.assignTenantAdmin(iamRequest);
        log.info("Activation orchestrator succeeded for registrationId={} correlationId={}", process.getRegistrationId(), correlationId());
    }

    private UserActivationRequest buildUserRequest(AuthCredential credential, JsonNode userPayload, JsonNode companyPayload) {
        String firstName = textValue(userPayload, "firstName");
        String lastName = textValue(userPayload, "lastName");
        String displayName = textValue(userPayload, "displayName");
        if (!StringUtils.hasText(displayName)) {
            displayName = String.join(" ", StringUtils.hasText(firstName) ? firstName : "", StringUtils.hasText(lastName) ? lastName : "").trim();
            if (!StringUtils.hasText(displayName)) {
                displayName = credential.getLoginEmail();
            }
        }
        return new UserActivationRequest(
                credential.getUserId(),
                credential.getLoginEmail(),
                textValue(companyPayload, "companyId"),
                firstName,
                lastName,
                displayName,
                "ACTIVE"
        );
    }

    private CompanyActivationRequest buildCompanyRequest(JsonNode companyPayload, JsonNode locationPayload) {
        return new CompanyActivationRequest(
                textValue(companyPayload, "companyId"),
                textValue(companyPayload, "companyName"),
                "ACTIVE",
                textValue(locationPayload, "timezone"),
                textValue(locationPayload, "countryCode"),
                textValue(locationPayload, "regionCode"),
                textValue(locationPayload, "locationId"),
                textValue(locationPayload, "headquarterLocationId")
        );
    }

    private IamTenantAdminRequest buildIamRequest(String tenantId, AuthCredential credential) {
        return new IamTenantAdminRequest(
                tenantId,
                credential.getUserId(),
                "USER",
                List.of("TENANT_ADMIN"),
                Boolean.TRUE
        );
    }

    private JsonNode parsePayload(String payload) {
        if (!StringUtils.hasText(payload)) {
            return null;
        }
        try {
            return objectMapper.readTree(payload);
        } catch (JsonProcessingException e) {
            throw new AppException(HttpStatus.INTERNAL_SERVER_ERROR, ErrorCode.INTERNAL_ERROR, "Unable to parse registration payload");
        }
    }

    private String textValue(JsonNode node, String field) {
        if (node == null || !node.has(field)) {
            return null;
        }
        String value = node.get(field).asText(null);
        return StringUtils.hasText(value) ? value : null;
    }

    private String correlationId() {
        String correlationId = MDC.get(CorrelationIdFilter.MDC_KEY);
        return correlationId == null ? "n/a" : correlationId;
    }
}

