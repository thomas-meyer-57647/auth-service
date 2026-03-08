package de.innologic.auth.web.dto;

import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

@Schema(name = "RegistrationVerifyRequest", description = "Payload sent to verify the e-mail belonging to a registration.")
public class RegistrationVerifyRequestDto {

    @Schema(description = "Registration identifier that must match the pending process.", example = "reg_97f9d2c9-d5b6-4c3d-b4e9-33b6796d04f2", requiredMode = Schema.RequiredMode.REQUIRED)
    @NotBlank
    private String registrationId;

    @Schema(description = "Verification token that was sent to the user via e-mail.", example = "vt_4d7b292f2a3c44ae8d3bd9e9d8b0f8dc", requiredMode = Schema.RequiredMode.REQUIRED)
    @NotBlank
    @Size(max = 255)
    private String verificationToken;

    public String getRegistrationId() {
        return registrationId;
    }

    public void setRegistrationId(String registrationId) {
        this.registrationId = registrationId;
    }

    public String getVerificationToken() {
        return verificationToken;
    }

    public void setVerificationToken(String verificationToken) {
        this.verificationToken = verificationToken;
    }
}
