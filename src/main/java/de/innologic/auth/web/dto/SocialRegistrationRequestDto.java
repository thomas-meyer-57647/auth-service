package de.innologic.auth.web.dto;

import com.fasterxml.jackson.databind.JsonNode;
import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;

@Schema(name = "SocialRegistrationRequest", description = "Payload used to start a social registration journey.")
public class SocialRegistrationRequestDto {

    @Schema(description = "Tenant id for the company that is being onboarded.", example = "tenant-42", requiredMode = Schema.RequiredMode.REQUIRED)
    @NotBlank
    private String tenantId;

    @Schema(description = "Company payload that the user wants to create. Stored for downstream services.", requiredMode = Schema.RequiredMode.REQUIRED, type = "object", example = "{\"companyName\":\"Acme GmbH\"}")
    @NotNull
    private JsonNode companyPayload;

    @Schema(description = "Primary location payload that the tenant owns.", requiredMode = Schema.RequiredMode.REQUIRED, type = "object", example = "{\"city\":\"Berlin\"}")
    @NotNull
    private JsonNode locationPayload;

    @Schema(description = "Additional user payload that should travel through the registration process.", requiredMode = Schema.RequiredMode.NOT_REQUIRED, type = "object", example = "{\"firstName\":\"Max\",\"lastName\":\"Mustermann\"}")
    private JsonNode userPayload;

    @Schema(description = "Social provider token (ID token / access token) that proves the user identity.", example = "ya29.a0AfH6SMCk...", requiredMode = Schema.RequiredMode.REQUIRED)
    @NotBlank
    private String socialToken;

    public String getTenantId() {
        return tenantId;
    }

    public void setTenantId(String tenantId) {
        this.tenantId = tenantId;
    }

    public JsonNode getCompanyPayload() {
        return companyPayload;
    }

    public void setCompanyPayload(JsonNode companyPayload) {
        this.companyPayload = companyPayload;
    }

    public JsonNode getLocationPayload() {
        return locationPayload;
    }

    public void setLocationPayload(JsonNode locationPayload) {
        this.locationPayload = locationPayload;
    }

    public JsonNode getUserPayload() {
        return userPayload;
    }

    public void setUserPayload(JsonNode userPayload) {
        this.userPayload = userPayload;
    }

    public String getSocialToken() {
        return socialToken;
    }

    public void setSocialToken(String socialToken) {
        this.socialToken = socialToken;
    }
}
