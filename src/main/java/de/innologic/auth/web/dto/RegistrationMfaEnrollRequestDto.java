package de.innologic.auth.web.dto;

import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.validation.constraints.NotBlank;

@Schema(name = "RegistrationMfaEnrollRequest", description = "Request to start TOTP enrollment for a pending registration.")
public class RegistrationMfaEnrollRequestDto {

    @Schema(description = "Registration identifier with verified e-mail.", example = "reg_97f9d2c9-d5b6-4c3d-b4e9-33b6796d04f2", requiredMode = Schema.RequiredMode.REQUIRED)
    @NotBlank
    private String registrationId;

    public String getRegistrationId() {
        return registrationId;
    }

    public void setRegistrationId(String registrationId) {
        this.registrationId = registrationId;
    }
}
