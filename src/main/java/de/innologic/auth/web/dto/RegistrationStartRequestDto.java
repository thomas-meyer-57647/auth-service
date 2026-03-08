package de.innologic.auth.web.dto;

import com.fasterxml.jackson.databind.JsonNode;
import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Size;

@Schema(name = "RegistrationStartRequest", description = "Payload for starting a registration journey.")
public class RegistrationStartRequestDto {

    @Schema(description = "Tenant id for the company that is being onboarded.", example = "tenant-42", requiredMode = Schema.RequiredMode.REQUIRED)
    @NotBlank
    private String tenantId;

    @Schema(description = "Primary e-mail address that will be used for login.", example = "admin@example.com", requiredMode = Schema.RequiredMode.REQUIRED)
    @NotBlank
    @Email
    @Size(max = 255)
    private String userEmail;

    @Schema(description = "Initial password for the user. Must follow the platform password policy.", example = "Str0ngP@ss!", requiredMode = Schema.RequiredMode.REQUIRED)
    @NotBlank
    @Size(min = 8, max = 255)
    private String userPassword;

    @Schema(description = "Company payload that the user wants to create. Stored for downstream services.", requiredMode = Schema.RequiredMode.REQUIRED, type = "object", example = "{\"companyName\":\"Acme GmbH\"}")
    @NotNull
    private JsonNode companyPayload;

    @Schema(description = "Primary location payload that the tenant owns.", requiredMode = Schema.RequiredMode.REQUIRED, type = "object", example = "{\"city\":\"Berlin\"}")
    @NotNull
    private JsonNode locationPayload;

    @Schema(description = "Additional user payload that should travel through the registration process.", requiredMode = Schema.RequiredMode.NOT_REQUIRED, type = "object", example = "{\"firstName\":\"Max\",\"lastName\":\"Mustermann\"}")
    private JsonNode userPayload;

    public String getTenantId() {
        return tenantId;
    }

    public void setTenantId(String tenantId) {
        this.tenantId = tenantId;
    }

    public String getUserEmail() {
        return userEmail;
    }

    public void setUserEmail(String userEmail) {
        this.userEmail = userEmail;
    }

    public String getUserPassword() {
        return userPassword;
    }

    public void setUserPassword(String userPassword) {
        this.userPassword = userPassword;
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
}
